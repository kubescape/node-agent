// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

// Package runtime is the native owner of the enforce_file gadget. The binding
// controller comes from the common enforcement package; this package adds the
// file policy maps and the operator registration.
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
	filepolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/policy"
)

const (
	operatorName = "enforce-file"
	annotation   = "annotations.enforce-file"
	configKey    = "enforce-file/config"
	bindingsKey  = "enforce-file/bindings"
)

type ContainerIdentity = enforcement.ContainerIdentity

// Hooks lists the int LSM hooks with their argument count (without `ret`).
// Each program reads the previous verdict, `ret`, right after them, so the
// counts must match the running kernel.
var Hooks = map[string]int{
	"file_open": 1, "path_truncate": 1, "path_chmod": 2, "path_chown": 3,
	"inode_setxattr": 6, "inode_set_acl": 4, "path_mknod": 4, "path_mkdir": 3,
	"path_symlink": 3, "path_unlink": 2, "path_rmdir": 2, "path_link": 3,
	"path_rename": 5, "task_alloc": 2,
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
	Policy          filepolicy.Compiled
	InitialBindings []enforcement.Binding
}

func WithConfig(config Config) gadgetcontext.Option {
	p := &config.Policy
	p.Slots = append([]filepolicy.SlotValue(nil), p.Slots...)
	p.Literals = append([]filepolicy.LiteralEntry(nil), p.Literals...)
	config.InitialBindings = append([]enforcement.Binding(nil), config.InitialBindings...)
	return func(gc *gadgetcontext.GadgetContext) { gc.SetVar(configKey, config) }
}

// GetBindings returns the controller of a running instance.
func GetBindings(gc operators.GadgetContext) (*enforcement.Bindings, error) {
	value, _ := gc.GetVar(bindingsKey)
	b, ok := value.(*instance)
	if !ok {
		return nil, fmt.Errorf("file binding controller is unavailable")
	}
	return b.Bindings, nil
}

func validateConfig(config Config) error {
	p := config.Policy
	if p.Generation == 0 || len(p.Slots) == 0 || len(p.Slots) > filepolicy.KernelMaxSlots ||
		len(p.Literals) > filepolicy.KernelMaxLiterals {
		return fmt.Errorf("invalid compiled file policy")
	}
	for i, s := range p.Slots {
		if s.Generation != p.Generation {
			return fmt.Errorf("slot %d carries another generation", i)
		}
		if s.NRules > filepolicy.KernelMaxRules || s.NGlobs > filepolicy.KernelMaxGlobs {
			return fmt.Errorf("slot %d has too many rules or globs", i)
		}
		for _, r := range s.Rules[:s.NRules] {
			if int(r.RuleID) >= len(p.RuleNames) || int(r.OriginID) >= len(p.Origins) {
				return fmt.Errorf("slot %d refers to an unknown rule or origin", i)
			}
		}
	}
	for _, l := range p.Literals {
		if int(l.Key.Slot) >= len(p.Slots) {
			return fmt.Errorf("literal entry for slot %d out of range", l.Key.Slot)
		}
	}
	return nil
}

// checkMap compares a map with its declaration in file_policy.h. Every
// policy map is read-only for the program.
func checkMap(m enforcement.Map, name string, typ ebpf.MapType, key, value, max uint32) error {
	if m == nil || m.Type() != typ || m.KeySize() != key || m.ValueSize() != value || m.MaxEntries() != max || m.Flags()&unix.BPF_F_RDONLY_PROG == 0 {
		return fmt.Errorf("invalid immutable file policy map layout: %s", name)
	}
	return nil
}

// writeSlots writes the slot headers, the map the binding controller freezes.
// fromImage sets filepolicy.SlotFromImage (see FromImageUnavailable); the
// compiler never sets it.
func writeSlots(slots []filepolicy.SlotValue, fromImage bool) func(enforcement.Map) error {
	return func(m enforcement.Map) error {
		if err := checkMap(m, "file_slots", ebpf.Array, 4, filepolicy.KernelSlotSize, filepolicy.KernelMaxSlots); err != nil {
			return err
		}
		for i := range slots {
			slot := slots[i]
			slot.Flags &^= filepolicy.SlotFromImage
			if fromImage {
				slot.Flags |= filepolicy.SlotFromImage
			}
			if err := m.Put(uint32(i), &slot); err != nil {
				return fmt.Errorf("writing slot %d: %w", i, err)
			}
		}
		return nil
	}
}

// writeLiterals writes and freezes the literal component table.
func writeLiterals(m enforcement.Map, p filepolicy.Compiled) error {
	if err := checkMap(m, "file_literals", ebpf.Hash, filepolicy.KernelLiteralKeySize, filepolicy.KernelLiteralValueSize, filepolicy.KernelMaxLiterals); err != nil {
		return err
	}
	for _, l := range p.Literals {
		if err := m.Put(l.Key, l.Bits); err != nil {
			return fmt.Errorf("writing literal: %w", err)
		}
	}
	if err := m.Freeze(); err != nil {
		return fmt.Errorf("freezing literals: %w", err)
	}
	return nil
}

// instance writes the literal table, then starts the binding controller,
// which writes and freezes the slots before any binding.
type instance struct {
	*enforcement.Bindings
	policy filepolicy.Compiled
}

func (i *instance) Start(gc operators.GadgetContext) error {
	value, _ := gc.GetVar(operators.MapPrefix + "file_literals")
	var literals enforcement.Map
	if m, ok := value.(*ebpf.Map); ok && m != nil {
		literals = m
	}
	if err := writeLiterals(literals, i.policy); err != nil {
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
		return nil, fmt.Errorf("enforce_file requires native policy configuration; use runtime.WithConfig")
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	// Before the programs are loaded: a wrong argument count would make a
	// program read an argument as the previous verdict.
	if err := checkKernel(); err != nil {
		return nil, fmt.Errorf("enforce_file: %w", err)
	}
	b, err := enforcement.New(enforcement.Config{
		Name:            operatorName,
		Generation:      config.Policy.Generation,
		Slots:           uint32(len(config.Policy.Slots)),
		InitialBindings: config.InitialBindings,
		PolicyMap:       "file_slots",
		WritePolicy:     writeSlots(config.Policy.Slots, FromImageUnavailable() == ""),
		ArmMap:          "armed_tasks",
		FaultMap:        "arming_faults",
	})
	if err != nil {
		return nil, err
	}
	i := &instance{Bindings: b, policy: config.Policy}
	gc.SetVar(bindingsKey, i)
	return i, nil
}
