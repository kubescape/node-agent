// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

// Package runtime is the native owner of the enforce_privilege gadget. The
// binding controller comes from the common enforcement package; this package
// adds the privilege policy map and the operator registration.
package runtime

import (
	"errors"
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
	privpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/policy"
)

const (
	// MapPrefix is SANDBOX_SECTION of ../privilege_policy.h: the prefix of
	// the section's pinned maps.
	mapPrefix    = "sbx_priv_"
	policyMap    = "policy"
	operatorName = "enforce-privilege"
	annotation   = "annotations.enforce-privilege"
	configKey    = "enforce-privilege/config"
	bindingsKey  = "enforce-privilege/bindings"
)

type ContainerIdentity = enforcement.ContainerIdentity

// Hooks lists the int LSM hooks of ../program.bpf.c with the argument counts
// (without `ret`) their program handles. Each program reads the previous
// verdict, `ret`, right after the arguments. bpf and perf_event_open changed in
// Linux 6.15 and handle both signatures (checked for 6.1 to 6.18).
var Hooks = map[string][]int{
	"userns_create": {1}, "task_alloc": {2}, "capable": {4}, "capset": {5},
	"task_fix_setuid": {3}, "task_fix_setgid": {3}, "sb_mount": {5}, "sb_kern_mount": {1},
	"sb_umount": {2}, "move_mount": {2}, "sb_pivotroot": {2}, "path_chroot": {1},
	"inode_init_security_anon": {3}, "ptrace_access_check": {2}, "ptrace_traceme": {1},
	"kernel_read_file": {3}, "kernel_load_data": {2}, "kernel_module_request": {1},
	"bpf": {3, 4}, "perf_event_open": {2, 1}, "key_alloc": {3}, "key_permission": {3}, "inode_mknod": {4},
}

// checkKernel refuses a kernel whose hook signatures differ from Hooks
// (replaced in tests).
var checkKernel = func() error {
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return fmt.Errorf("kernel BTF: %w", err)
	}
	// A hook with an unknown signature cannot be skipped before load, and its
	// program would read a wrong argument: refuse the kernel and name the hooks.
	return enforcement.JoinHookMismatches(enforcement.LSMHookArgMismatches(kernel, Hooks))
}

// Config holds the compiled rules and the initial container selection.
type Config struct {
	Policy          privpolicy.Compiled
	InitialBindings []enforcement.Binding
}

func WithConfig(config Config) gadgetcontext.Option {
	config.Policy.Entries = append([]privpolicy.KernelEntry(nil), config.Policy.Entries...)
	config.InitialBindings = append([]enforcement.Binding(nil), config.InitialBindings...)
	return func(gc *gadgetcontext.GadgetContext) { gc.SetVar(configKey, config) }
}

// GetBindings returns the controller of a running instance.
func GetBindings(gc operators.GadgetContext) (*enforcement.Bindings, error) {
	value, _ := gc.GetVar(bindingsKey)
	b, ok := value.(*enforcement.Bindings)
	if !ok {
		return nil, fmt.Errorf("privilege binding controller is unavailable")
	}
	return b, nil
}

func validateConfig(config Config) error {
	p := config.Policy
	if p.Generation == 0 || p.Slots > privpolicy.KernelMaxSlots || len(p.Entries) > privpolicy.KernelMaxEntries {
		return fmt.Errorf("invalid compiled privilege policy")
	}
	metas := map[uint32]bool{}
	for _, e := range p.Entries {
		if e.Key.Slot >= p.Slots {
			return fmt.Errorf("policy entry for slot %d out of range", e.Key.Slot)
		}
		if e.Key.Kind == privpolicy.KindMeta {
			if e.Value.Generation != p.Generation {
				return fmt.Errorf("slot %d carries another generation", e.Key.Slot)
			}
			if metas[e.Key.Slot] {
				return fmt.Errorf("slot %d has two generation entries", e.Key.Slot)
			}
			metas[e.Key.Slot] = true
		}
	}
	if uint32(len(metas)) != p.Slots {
		return fmt.Errorf("every slot needs one generation entry")
	}
	return nil
}

// checkPolicyMap checks the map layout against privilege_policy.h.
func checkPolicyMap(m enforcement.Map) error {
	if m == nil || m.Type() != ebpf.Hash || m.KeySize() != privpolicy.KernelKeySize || m.ValueSize() != privpolicy.KernelValueSize || m.MaxEntries() != privpolicy.KernelMapEntries || m.Flags()&unix.BPF_F_RDONLY_PROG == 0 {
		return fmt.Errorf("invalid immutable privilege policy map layout")
	}
	return nil
}

// Publications splits a compiled policy into one publication per slot. Each
// writes its entries keyed by the storage index, the META entry last (the
// slot is judged only once its header exists), and deletes exactly those.
func Publications(p privpolicy.Compiled) []enforcement.Publication {
	strict := StrictSlots(p)
	perSlot := make([][]privpolicy.KernelEntry, p.Slots)
	for _, e := range p.Entries {
		if e.Key.Kind == privpolicy.KindMeta {
			continue
		}
		perSlot[e.Key.Slot] = append(perSlot[e.Key.Slot], e)
	}
	for _, e := range p.Entries {
		if e.Key.Kind == privpolicy.KindMeta {
			perSlot[e.Key.Slot] = append(perSlot[e.Key.Slot], e)
		}
	}
	out := make([]enforcement.Publication, 0, p.Slots)
	for slot := range perSlot {
		entries := perSlot[slot]
		out = append(out, enforcement.Publication{Slot: uint32(slot), Generation: p.Generation, Strict: strict(uint32(slot)),
			Write: func(maps map[string]enforcement.Map, storage uint32) error {
				m := maps[policyMap]
				if err := checkPolicyMap(m); err != nil {
					return err
				}
				for _, e := range entries {
					key := e.Key
					key.Slot = storage
					if err := m.Put(key, e.Value); err != nil {
						return fmt.Errorf("writing policy: %w", err)
					}
				}
				return nil
			},
			Delete: func(maps map[string]enforcement.Map, storage uint32) error {
				var errs []error
				for _, e := range entries {
					key := e.Key
					key.Slot = storage
					if err := maps[policyMap].Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
						errs = append(errs, err)
					}
				}
				return errors.Join(errs...)
			}})
	}
	return out
}

// purge deletes every policy entry of one storage buffer: a buffer an
// adopted state left, whose compiled entries this instance does not know.
func purge(maps map[string]enforcement.Map, storage uint32) error {
	m, ok := maps[policyMap].(*ebpf.Map)
	if !ok {
		return fmt.Errorf("privilege policy map cannot be listed")
	}
	var (
		key   privpolicy.KernelKey
		value privpolicy.KernelValue
		keys  []privpolicy.KernelKey
	)
	it := m.Iterate()
	for it.Next(&key, &value) {
		if key.Slot == storage {
			keys = append(keys, key)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("listing privilege policy: %w", err)
	}
	var errs []error
	for _, k := range keys {
		if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// classOf reads the class of the publication at a storage index from its
// META entry: Strict when it enforces.
func classOf(maps map[string]enforcement.Map, storage uint32) (bool, error) {
	m, ok := maps[policyMap].(interface {
		Lookup(key, valueOut interface{}) error
	})
	if !ok {
		return false, fmt.Errorf("privilege policy map cannot be read")
	}
	var meta privpolicy.KernelValue
	if err := m.Lookup(privpolicy.KernelKey{Slot: storage, Kind: privpolicy.KindMeta}, &meta); err != nil {
		return false, fmt.Errorf("reading the META entry of storage %d: %w", storage, err)
	}
	return meta.Mode == privpolicy.KernelModeEnforce, nil
}

// StrictSlots returns the class of each slot: a slot enforces when its META
// entry has the enforce mode (see ../privilege_policy.h).
func StrictSlots(p privpolicy.Compiled) func(uint32) bool {
	strict := map[uint32]bool{}
	for _, e := range p.Entries {
		if e.Key.Kind == privpolicy.KindMeta && e.Value.Mode == privpolicy.KernelModeEnforce {
			strict[e.Key.Slot] = true
		}
	}
	return func(slot uint32) bool { return strict[slot] }
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
		return nil, fmt.Errorf("enforce_privilege requires native policy configuration; use runtime.WithConfig")
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	// Before the programs are loaded: a wrong argument count would make them
	// read an argument as the previous verdict.
	if err := checkKernel(); err != nil {
		return nil, fmt.Errorf("enforce_privilege: %w", err)
	}
	b, err := enforcement.New(enforcement.Config{
		Name:                operatorName,
		Generation:          config.Policy.Generation,
		Slots:               privpolicy.KernelMaxSlots,
		InitialBindings:     config.InitialBindings,
		MapPrefix:           mapPrefix,
		PublishMaps:         []string{policyMap},
		Purge:               purge,
		ClassOf:             classOf,
		InitialPublications: Publications(config.Policy),
		ArmMap:              "armed_tasks",
		FaultMap:            "arming_faults",
		WitnessMap:          "arming_witness",
		StrictSlot:          StrictSlots(config.Policy),
		SubtreeLevels:       enforcement.SubtreeLevels,
	})
	if err != nil {
		return nil, err
	}
	gc.SetVar(bindingsKey, b)
	return b, nil
}
