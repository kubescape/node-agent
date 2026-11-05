// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

// Package runtime is the native owner of the enforce_privilege gadget. The
// binding controller comes from the common enforcement package; this package
// adds the privilege policy map and the operator registration.
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
	privpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/policy"
)

const (
	operatorName = "enforce-privilege"
	annotation   = "annotations.enforce-privilege"
	configKey    = "enforce-privilege/config"
	bindingsKey  = "enforce-privilege/bindings"
)

type ContainerIdentity = enforcement.ContainerIdentity

// Hooks lists the int LSM hooks of ../program.bpf.c with their argument count
// (without `ret`). Each program reads the previous verdict, `ret`, right after
// them, so the counts must match the running kernel.
var Hooks = map[string]int{
	"userns_create": 1, "task_alloc": 2, "capable": 4, "capset": 5,
	"task_fix_setuid": 3, "task_fix_setgid": 3, "sb_mount": 5, "sb_kern_mount": 1,
	"sb_umount": 2, "move_mount": 2, "sb_pivotroot": 2, "path_chroot": 1,
	"inode_init_security_anon": 3, "ptrace_access_check": 2, "ptrace_traceme": 1,
	"kernel_read_file": 3, "kernel_load_data": 2, "kernel_module_request": 1,
	"bpf": 3, "perf_event_open": 2, "key_alloc": 3, "key_permission": 3, "inode_mknod": 4,
}

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

// writePolicy checks the map layout against privilege_policy.h and writes the
// compiled entries.
func writePolicy(entries []privpolicy.KernelEntry) func(enforcement.Map) error {
	return func(m enforcement.Map) error {
		if m == nil || m.Type() != ebpf.Hash || m.KeySize() != privpolicy.KernelKeySize || m.ValueSize() != privpolicy.KernelValueSize || m.MaxEntries() != privpolicy.KernelMaxEntries || m.Flags()&unix.BPF_F_RDONLY_PROG == 0 {
			return fmt.Errorf("invalid immutable privilege policy map layout")
		}
		for _, e := range entries {
			if err := m.Put(e.Key, e.Value); err != nil {
				return fmt.Errorf("writing policy: %w", err)
			}
		}
		return nil
	}
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
		Name:            operatorName,
		Generation:      config.Policy.Generation,
		Slots:           config.Policy.Slots,
		InitialBindings: config.InitialBindings,
		PolicyMap:       "policy",
		WritePolicy:     writePolicy(config.Policy.Entries),
		ArmMap:          "armed_tasks",
		FaultMap:        "arming_faults",
	})
	if err != nil {
		return nil, err
	}
	gc.SetVar(bindingsKey, b)
	return b, nil
}
