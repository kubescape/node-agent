// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

// Package runtime is the native owner of the enforce_network gadget. The
// binding controller comes from the common enforcement package; this package
// adds the network policy maps and the operator registration.
package runtime

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	netpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/policy"
)

const (
	operatorName = "enforce-network"
	annotation   = "annotations.enforce-network"
	configKey    = "enforce-network/config"
	bindingsKey  = "enforce-network/bindings"
)

type ContainerIdentity = enforcement.ContainerIdentity

// Hooks lists the int LSM hooks of the gadget with their argument count
// (without `ret`). Each program reads the previous verdict, `ret`, right after
// them, so the counts must match the running kernel.
var Hooks = map[string]int{"socket_connect": 3, "socket_sendmsg": 3}

// checkKernel refuses a kernel whose hook signatures differ from Hooks
// (replaced in tests).
var checkKernel = func() error {
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return fmt.Errorf("kernel BTF: %w", err)
	}
	return enforcement.CheckLSMHookArgs(kernel, Hooks)
}

// Config holds the compiled rules and the initial container selection.
type Config struct {
	Policy          netpolicy.Compiled
	InitialBindings []enforcement.Binding
}

func WithConfig(config Config) gadgetcontext.Option {
	p := &config.Policy
	p.Slots = append([]netpolicy.SlotValue(nil), p.Slots...)
	p.Prefixes = append([]netpolicy.PrefixEntry(nil), p.Prefixes...)
	p.Lists = append([]netpolicy.RuleList(nil), p.Lists...)
	config.InitialBindings = append([]enforcement.Binding(nil), config.InitialBindings...)
	return func(gc *gadgetcontext.GadgetContext) { gc.SetVar(configKey, config) }
}

// GetBindings returns the controller of a running instance.
func GetBindings(gc operators.GadgetContext) (*enforcement.Bindings, error) {
	value, _ := gc.GetVar(bindingsKey)
	b, ok := value.(*instance)
	if !ok {
		return nil, fmt.Errorf("network binding controller is unavailable")
	}
	return b.Bindings, nil
}

// GetPublisher returns the function that publishes a one-slot compiled policy
// into a slot of a running instance.
func GetPublisher(gc operators.GadgetContext) (func(slot uint32, p netpolicy.Compiled) error, error) {
	value, _ := gc.GetVar(bindingsKey)
	b, ok := value.(*instance)
	if !ok {
		return nil, fmt.Errorf("network binding controller is unavailable")
	}
	return b.Publish, nil
}

func validateConfig(config Config) error {
	p := config.Policy
	if p.Generation == 0 || len(p.Slots) > netpolicy.KernelMaxSlots ||
		len(p.Prefixes) > netpolicy.KernelMaxPrefixes || len(p.Lists) > netpolicy.KernelMaxLists {
		return fmt.Errorf("invalid compiled network policy")
	}
	for i, s := range p.Slots {
		if s.Generation != p.Generation {
			return fmt.Errorf("slot %d carries another generation", i)
		}
	}
	for _, e := range p.Prefixes {
		if int(e.Key.Slot) >= len(p.Slots) || int(e.List) >= len(p.Lists) || e.Key.PrefixLen < 32 || e.Key.PrefixLen > 32+128 {
			return fmt.Errorf("invalid prefix entry for slot %d", e.Key.Slot)
		}
	}
	for i, l := range p.Lists {
		if l.Len > netpolicy.KernelListLen {
			return fmt.Errorf("rule list %d is too long", i)
		}
	}
	return nil
}

// checkMap compares a map with its declaration in network_policy.h. Every
// policy map is read-only for the program.
func checkMap(m enforcement.Map, name string, typ ebpf.MapType, key, value, max uint32) error {
	if m == nil || m.Type() != typ || m.KeySize() != key || m.ValueSize() != value || m.MaxEntries() != max || m.Flags()&unix.BPF_F_RDONLY_PROG == 0 {
		return fmt.Errorf("invalid immutable network policy map layout: %s", name)
	}
	return nil
}

// slotPolicy is what one slot publishes: its header, its prefixes (List
// indexes lists) and the rule lists they use.
type slotPolicy struct {
	header   netpolicy.SlotValue
	prefixes []netpolicy.PrefixEntry
	lists    []netpolicy.RuleList
}

// splitSlots splits a compiled policy per slot. The compiler shares a rule
// list between slots; each slot gets its own copy, so a publication never
// depends on another one.
func splitSlots(p netpolicy.Compiled) []slotPolicy {
	out := make([]slotPolicy, len(p.Slots))
	local := make([]map[uint32]uint32, len(p.Slots))
	for i, s := range p.Slots {
		out[i].header = s
		local[i] = map[uint32]uint32{}
	}
	for _, e := range p.Prefixes {
		sp, ids := &out[e.Key.Slot], local[e.Key.Slot]
		id, ok := ids[e.List]
		if !ok {
			id = uint32(len(sp.lists))
			ids[e.List] = id
			sp.lists = append(sp.lists, p.Lists[e.List])
		}
		e.List = id
		sp.prefixes = append(sp.prefixes, e)
	}
	return out
}

// listPool allocates rule list indexes of net_rules to the storage buffers.
type listPool struct {
	mu   sync.Mutex
	free []uint32
	used map[uint32][]uint32 // storage -> its list indexes
}

func newListPool() *listPool {
	p := &listPool{used: map[uint32][]uint32{}}
	for i := netpolicy.KernelMapLists - 1; i >= 0; i-- {
		p.free = append(p.free, uint32(i))
	}
	return p
}

func (p *listPool) take(storage uint32, n int) ([]uint32, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.used[storage]; ok {
		return nil, fmt.Errorf("storage %d already holds rule lists", storage)
	}
	if n > len(p.free) {
		return nil, fmt.Errorf("%d rule lists needed, %d free", n, len(p.free))
	}
	ids := append([]uint32(nil), p.free[len(p.free)-n:]...)
	p.free = p.free[:len(p.free)-n]
	p.used[storage] = ids
	return ids, nil
}

func (p *listPool) release(storage uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.free = append(p.free, p.used[storage]...)
	delete(p.used, storage)
}

// publication writes one slot at a storage index: rule lists, prefixes, and
// the slot header last (the slot is judged only once its header exists).
func (i *instance) publication(slot uint32, sp slotPolicy) enforcement.Publication {
	return enforcement.Publication{Slot: slot, Generation: sp.header.Generation, Strict: sp.header.Mode == netpolicy.KernelModeEnforce,
		Write: func(maps map[string]enforcement.Map, storage uint32) error {
			slots, prefixes, lists := maps["net_slots"], maps["net_prefix"], maps["net_rules"]
			if err := errors.Join(checkMap(slots, "net_slots", ebpf.Array, 4, netpolicy.KernelSlotSize, netpolicy.KernelStorage),
				checkMap(prefixes, "net_prefix", ebpf.LPMTrie, netpolicy.KernelPrefixKeySize, 4, netpolicy.KernelMapPrefixes),
				checkMap(lists, "net_rules", ebpf.Array, 4, netpolicy.KernelListSize, netpolicy.KernelMapLists)); err != nil {
				return err
			}
			ids, err := i.lists.take(storage, len(sp.lists))
			if err != nil {
				return err
			}
			for k, l := range sp.lists {
				if err := lists.Put(ids[k], l); err != nil {
					return fmt.Errorf("writing rule list: %w", err)
				}
			}
			for _, e := range sp.prefixes {
				key := e.Key
				key.Slot = storage
				if err := prefixes.Put(key, ids[e.List]); err != nil {
					return fmt.Errorf("writing prefix: %w", err)
				}
			}
			if err := slots.Put(storage, sp.header); err != nil {
				return fmt.Errorf("writing slot header: %w", err)
			}
			return nil
		},
		Delete: func(maps map[string]enforcement.Map, storage uint32) error {
			errs := []error{maps["net_slots"].Put(storage, netpolicy.SlotValue{})}
			for _, e := range sp.prefixes {
				key := e.Key
				key.Slot = storage
				if err := maps["net_prefix"].Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					errs = append(errs, err)
				}
			}
			if err := errors.Join(errs...); err != nil {
				return err // the lists stay allocated until a delete succeeds
			}
			i.lists.release(storage)
			return nil
		}}
}

// StrictSlots returns the class of each slot: a slot is Strict when its mode
// is enforce (an enforce rule or default, see netpolicy).
func StrictSlots(p netpolicy.Compiled) func(uint32) bool {
	return func(slot uint32) bool {
		return int(slot) < len(p.Slots) && p.Slots[slot].Mode == netpolicy.KernelModeEnforce
	}
}

// instance is the binding controller of a running gadget instance, with the
// rule list pool its publications share.
type instance struct {
	*enforcement.Bindings
	lists *listPool
}

// Publish publishes slot 0 of a compiled policy (one combination) into slot.
func (i *instance) Publish(slot uint32, p netpolicy.Compiled) error {
	if len(p.Slots) != 1 {
		return fmt.Errorf("a publication holds one slot, not %d", len(p.Slots))
	}
	return i.Bindings.Publish(i.publication(slot, splitSlots(p)[0]))
}

type operator struct{}

func New() operators.DataOperator            { return &operator{} }
func init()                                  { operators.RegisterDataOperator(New()) }
func (*operator) Name() string               { return operatorName }
func (*operator) Priority() int              { return 1 }
func (*operator) Init(*params.Params) error  { return nil }
func (*operator) GlobalParams() api.Params   { return nil }
func (*operator) InstanceParams() api.Params { return nil }

func (*operator) InstantiateDataOperator(gc operators.GadgetContext, _ api.ParamValues) (operators.DataOperatorInstance, error) {
	value, _ := gc.GetVar("config")
	metadata, ok := value.(*viper.Viper)
	if !ok || !metadata.GetBool(annotation) {
		return nil, nil
	}
	value, _ = gc.GetVar(configKey)
	config, supplied := value.(Config)
	if !supplied {
		return nil, fmt.Errorf("enforce_network requires native policy configuration; use runtime.WithConfig")
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	// Before the programs are loaded: a wrong argument count would make the
	// program read an argument as the previous verdict.
	if err := checkKernel(); err != nil {
		return nil, fmt.Errorf("enforce_network: %w", err)
	}
	i := &instance{lists: newListPool()}
	var initial []enforcement.Publication
	for slot, sp := range splitSlots(config.Policy) {
		initial = append(initial, i.publication(uint32(slot), sp))
	}
	b, err := enforcement.New(enforcement.Config{
		Name:                operatorName,
		Generation:          config.Policy.Generation,
		Slots:               netpolicy.KernelMaxSlots,
		InitialBindings:     config.InitialBindings,
		PublishMaps:         []string{"net_slots", "net_prefix", "net_rules"},
		InitialPublications: initial,
		FaultMap:            "net_faults",
		StrictSlot:          StrictSlots(config.Policy),
		SubtreeLevels:       enforcement.SubtreeLevels,
	})
	if err != nil {
		return nil, err
	}
	i.Bindings = b
	gc.SetVar(bindingsKey, i)
	return i, nil
}
