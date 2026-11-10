// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

// Package runtime is the native owner of the enforce_network gadget. The
// binding controller comes from the common enforcement package; this package
// adds the network policy maps and the operator registration.
package runtime

import (
	"fmt"

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

// writeSlots writes the slot headers, the map the binding controller freezes.
func writeSlots(slots []netpolicy.SlotValue) func(enforcement.Map) error {
	return func(m enforcement.Map) error {
		if err := checkMap(m, "net_slots", ebpf.Array, 4, netpolicy.KernelSlotSize, netpolicy.KernelMaxSlots); err != nil {
			return err
		}
		for i, s := range slots {
			if err := m.Put(uint32(i), s); err != nil {
				return fmt.Errorf("writing slot %d: %w", i, err)
			}
		}
		return nil
	}
}

// writeRules writes and freezes the prefix trie and the rule lists.
func writeRules(prefixes, lists enforcement.Map, p netpolicy.Compiled) error {
	if err := checkMap(prefixes, "net_prefix", ebpf.LPMTrie, netpolicy.KernelPrefixKeySize, 4, netpolicy.KernelMaxPrefixes); err != nil {
		return err
	}
	if err := checkMap(lists, "net_rules", ebpf.Array, 4, netpolicy.KernelListSize, netpolicy.KernelMaxLists); err != nil {
		return err
	}
	for i, l := range p.Lists {
		if err := lists.Put(uint32(i), l); err != nil {
			return fmt.Errorf("writing rule list %d: %w", i, err)
		}
	}
	for _, e := range p.Prefixes {
		if err := prefixes.Put(e.Key, e.List); err != nil {
			return fmt.Errorf("writing prefix: %w", err)
		}
	}
	if err := lists.Freeze(); err != nil {
		return fmt.Errorf("freezing rule lists: %w", err)
	}
	if err := prefixes.Freeze(); err != nil {
		return fmt.Errorf("freezing prefixes: %w", err)
	}
	return nil
}

// StrictSlots returns the class of each slot: a slot is Strict when its mode
// is enforce (an enforce rule or default, see netpolicy).
func StrictSlots(p netpolicy.Compiled) func(uint32) bool {
	return func(slot uint32) bool {
		return int(slot) < len(p.Slots) && p.Slots[slot].Mode == netpolicy.KernelModeEnforce
	}
}

// instance writes the rule maps, then starts the binding controller, which
// writes and freezes the slot headers before any binding.
type instance struct {
	*enforcement.Bindings
	policy netpolicy.Compiled
}

func (i *instance) Start(gc operators.GadgetContext) error {
	get := func(name string) enforcement.Map {
		value, _ := gc.GetVar(operators.MapPrefix + name)
		if m, ok := value.(*ebpf.Map); ok && m != nil {
			return m
		}
		return nil
	}
	if err := writeRules(get("net_prefix"), get("net_rules"), i.policy); err != nil {
		return err
	}
	return i.Bindings.Start(gc)
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
	b, err := enforcement.New(enforcement.Config{
		Name:            operatorName,
		Generation:      config.Policy.Generation,
		Slots:           uint32(len(config.Policy.Slots)),
		InitialBindings: config.InitialBindings,
		PolicyMap:       "net_slots",
		WritePolicy:     writeSlots(config.Policy.Slots),
		FaultMap:        "net_faults",
		StrictSlot:      StrictSlots(config.Policy),
		SubtreeLevels:   enforcement.SubtreeLevels,
	})
	if err != nil {
		return nil, err
	}
	i := &instance{Bindings: b, policy: config.Policy}
	gc.SetVar(bindingsKey, i)
	return i, nil
}
