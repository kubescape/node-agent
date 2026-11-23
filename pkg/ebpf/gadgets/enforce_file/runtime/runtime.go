// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

// Package runtime is the native owner of the enforce_file gadget. The binding
// controller comes from the common enforcement package; this package adds the
// file policy maps and the operator registration.
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
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/rootbarrier"
	filepolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/policy"
)

const (
	// MapPrefix is SANDBOX_SECTION of ../program.bpf.c: the prefix of the
	// section's pinned maps.
	MapPrefix    = "sbx1_file_"
	operatorName = "enforce-file"
	annotation   = "annotations.enforce-file"
	configKey    = "enforce-file/config"
	bindingsKey  = "enforce-file/bindings"
	barrierKey   = "enforce-file/barrier"
)

type ContainerIdentity = enforcement.ContainerIdentity

// Hooks lists the int LSM hooks with their argument count (without `ret`).
// Each program reads the previous verdict, `ret`, right after them, so the
// counts must match the running kernel.
var Hooks = map[string]int{
	"file_open": 1, "path_truncate": 1, "path_chmod": 2, "path_chown": 3,
	"inode_setxattr": 6, "inode_removexattr": 3, "inode_set_acl": 4, "inode_remove_acl": 3,
	"inode_setattr": 3, "path_mknod": 4, "path_mkdir": 3,
	"path_symlink": 3, "path_unlink": 2, "path_rmdir": 2, "path_link": 3,
	"path_rename": 5, "task_alloc": 2, "bprm_check_security": 1,
	"cred_prepare": 3, "cred_alloc_blank": 2, "uring_override_creds": 1,
}

// Programs maps each LSM program of the gadget to its hook: the programs of
// ../program.bpf.c and the root barrier's (BarrierHooks; ig_file_alloc
// carries the barrier's task_alloc body). They are the expected live links
// (enforcement.CheckAttached) and the hook an attach error names
// (enforcement.AsAttachCapacity).
var Programs = map[string]string{
	"ig_file_open":             "file_open",
	"ig_file_truncate":         "path_truncate",
	"ig_file_chmod":            "path_chmod",
	"ig_file_chown":            "path_chown",
	"ig_file_setxattr":         "inode_setxattr",
	"ig_file_set_acl":          "inode_set_acl",
	"ig_file_removexattr":      "inode_removexattr",
	"ig_file_remove_acl":       "inode_remove_acl",
	"ig_file_setattr":          "inode_setattr",
	"ig_file_mknod":            "path_mknod",
	"ig_file_mkdir":            "path_mkdir",
	"ig_file_symlink":          "path_symlink",
	"ig_file_unlink":           "path_unlink",
	"ig_file_rmdir":            "path_rmdir",
	"ig_file_link":             "path_link",
	"ig_file_rename":           "path_rename",
	"ig_file_exec_check":       "bprm_check_security",
	"ig_file_exec":             "bprm_committed_creds",
	"ig_file_alloc":            "task_alloc",
	"ig_file_cred_prepare":     "cred_prepare",
	"ig_file_cred_alloc_blank": "cred_alloc_blank",
	"ig_file_uring_creds":      "uring_override_creds",
	"ig_file_cred_free":        "cred_free",
	"rb_chroot":                "path_chroot",
	"rb_pivotroot":             "sb_pivotroot",
	"rb_userns":                "userns_create",
	"rb_capable":               "capable",
	"rb_sb_mount":              "sb_mount",
	"rb_move_mount":            "move_mount",
	"rb_sb_umount":             "sb_umount",
}

// checkKernel refuses a kernel whose hook signatures differ from Hooks
// (replaced in tests).
var checkKernel = func() error {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return fmt.Errorf("kernel release: %w", err)
	}
	if err := checkRelease(unix.ByteSliceToString(u.Release[:])); err != nil {
		return err
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return fmt.Errorf("kernel BTF: %w", err)
	}
	return enforcement.CheckLSMHookArgs(kernel, allHooks())
}

// checkRelease refuses a kernel older than 6.12, the supported floor. Before
// 6.11 the BPF LSM default of inode_setxattr makes the kernel skip its
// CAP_SYS_ADMIN check of security.* attributes (see the README), and 6.12 is
// the oldest kernel the gadget is tested on.
func checkRelease(release string) error {
	var major, minor int
	if _, err := fmt.Sscanf(release, "%d.%d", &major, &minor); err != nil {
		return fmt.Errorf("kernel release %q: %w", release, err)
	}
	if major < 6 || (major == 6 && minor < 12) {
		return fmt.Errorf("kernel %s is older than 6.12, the supported floor", release)
	}
	return nil
}

// allHooks adds the root barrier's hooks to Hooks: each barrier program also
// reads `ret` after the hook's arguments, and returns it for every task, so a
// wrong count must refuse the load before the programs attach.
func allHooks() map[string]int {
	hooks := make(map[string]int, len(Hooks)+len(rootbarrier.Hooks))
	for name, args := range Hooks {
		hooks[name] = args
	}
	for _, h := range rootbarrier.Hooks {
		hooks[h.LSM] = h.Args
	}
	return hooks
}

// Config holds the compiled rules and the initial container selection.
type Config struct {
	Policy          filepolicy.Compiled
	InitialBindings []enforcement.Binding
	// FaultInjection admits the test-only switches (arming-fail-fork-marks,
	// arming-fail-exec-marks, cred-record-fail, cred-forget-fail). Only
	// kernel tests set it; otherwise an instance with one set is refused.
	FaultInjection bool
	// CredQuota is the entries of the credential record one binding may
	// hold (../../common/creds.h); 0 keeps CRED_QUOTA_DEFAULT (32768).
	CredQuota uint32
	// CredPressure is the record's fill from which a binding may hold only
	// its share, and CredSize the size the share is computed from (tests
	// only, which cannot fill the real record); 0 keeps the defaults
	// (CRED_PRESSURE_DEFAULT, 75%; CRED_RECORD_MAX).
	CredPressure, CredSize uint32
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
	if p.Generation == 0 || len(p.Slots) > filepolicy.KernelMaxSlots ||
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
// slotValue is the header of a slot as written: the from-image flag follows
// the node, not the compiler.
func slotValue(slot filepolicy.SlotValue, fromImage bool) filepolicy.SlotValue {
	slot.Flags &^= filepolicy.SlotFromImage
	if fromImage {
		slot.Flags |= filepolicy.SlotFromImage
	}
	return slot
}

// publication writes slot `slot` of p at a storage index: its literals keyed
// by the storage index, then the slot header last (the slot is judged only
// once its header exists).
func publication(p filepolicy.Compiled, from, slot uint32, fromImage bool) enforcement.Publication {
	header := slotValue(p.Slots[from], fromImage)
	var literals []filepolicy.LiteralEntry
	for _, l := range p.Literals {
		if l.Key.Slot == from {
			literals = append(literals, l)
		}
	}
	return enforcement.Publication{Slot: slot, Generation: header.Generation, Strict: header.Mode == filepolicy.KernelModeEnforce,
		Write: func(maps map[string]enforcement.Map, storage uint32) error {
			slots, lits := maps["file_slots"], maps["file_literals"]
			if err := errors.Join(checkMap(slots, "file_slots", ebpf.Array, 4, filepolicy.KernelSlotSize, filepolicy.KernelStorage),
				checkMap(lits, "file_literals", ebpf.Hash, filepolicy.KernelLiteralKeySize, filepolicy.KernelLiteralValueSize, filepolicy.KernelMapLiterals)); err != nil {
				return err
			}
			for _, l := range literals {
				key := l.Key
				key.Slot = storage
				if err := lits.Put(key, l.Bits); err != nil {
					return fmt.Errorf("writing literal: %w", err)
				}
			}
			if err := slots.Put(storage, &header); err != nil {
				return fmt.Errorf("writing slot header: %w", err)
			}
			return nil
		},
		Delete: func(maps map[string]enforcement.Map, storage uint32) error {
			errs := []error{maps["file_slots"].Put(storage, &filepolicy.SlotValue{})}
			for _, l := range literals {
				key := l.Key
				key.Slot = storage
				if err := maps["file_literals"].Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					errs = append(errs, err)
				}
			}
			return errors.Join(errs...)
		}}
}

// purge deletes every entry of one storage buffer (its literals and its
// header): a buffer an adopted state left.
func purge(maps map[string]enforcement.Map, storage uint32) error {
	m, ok := maps["file_literals"].(*ebpf.Map)
	if !ok {
		return fmt.Errorf("file literal map cannot be listed")
	}
	var (
		key  filepolicy.LiteralKey
		bits filepolicy.Bits
		keys []filepolicy.LiteralKey
	)
	it := m.Iterate()
	for it.Next(&key, &bits) {
		if key.Slot == storage {
			keys = append(keys, key)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("listing file literals: %w", err)
	}
	errs := []error{maps["file_slots"].Put(storage, &filepolicy.SlotValue{})}
	for _, k := range keys {
		if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// occupied scans the file maps once for the storage buffers that hold
// entries: a header or literals.
func occupied(maps map[string]enforcement.Map) (map[uint32]bool, error) {
	slots, ok := maps["file_slots"].(*ebpf.Map)
	if !ok {
		return nil, fmt.Errorf("file slot map cannot be listed")
	}
	literals, ok := maps["file_literals"].(*ebpf.Map)
	if !ok {
		return nil, fmt.Errorf("file literal map cannot be listed")
	}
	out := map[uint32]bool{}
	var (
		storage uint32
		header  filepolicy.SlotValue
	)
	it := slots.Iterate()
	for it.Next(&storage, &header) {
		if header.Generation != 0 {
			out[storage] = true
		}
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("listing file slots: %w", err)
	}
	var (
		key  filepolicy.LiteralKey
		bits filepolicy.Bits
	)
	lit := literals.Iterate()
	for lit.Next(&key, &bits) {
		out[key.Slot] = true
	}
	if err := lit.Err(); err != nil {
		return nil, fmt.Errorf("listing file literals: %w", err)
	}
	return out, nil
}

// classOf reads the class of the publication at a storage index from its
// header: Strict when it enforces.
func classOf(maps map[string]enforcement.Map, storage uint32) (bool, error) {
	m, ok := maps["file_slots"].(interface {
		Lookup(key, valueOut interface{}) error
	})
	if !ok {
		return false, fmt.Errorf("file slot map cannot be read")
	}
	var header filepolicy.SlotValue
	if err := m.Lookup(storage, &header); err != nil {
		return false, fmt.Errorf("reading the header of storage %d: %w", storage, err)
	}
	return header.Mode == filepolicy.KernelModeEnforce, nil
}

// Publish publishes slot 0 of a compiled policy (one combination) into slot
// of a running instance.
func (i *instance) Publish(slot uint32, p filepolicy.Compiled) error {
	if len(p.Slots) != 1 {
		return fmt.Errorf("a publication holds one slot, not %d", len(p.Slots))
	}
	return i.Bindings.Publish(publication(p, 0, slot, FromImageUnavailable() == ""))
}

// GetPublisher returns the function that publishes a one-slot compiled policy
// into a slot of a running instance.
func GetPublisher(gc operators.GadgetContext) (func(slot uint32, p filepolicy.Compiled) error, error) {
	value, _ := gc.GetVar(bindingsKey)
	i, ok := value.(*instance)
	if !ok {
		return nil, fmt.Errorf("file binding controller is unavailable")
	}
	return i.Publish, nil
}

// Enforcing reports whether a slot can enforce. The root barrier covers the
// tasks of such a slot (see "Root barrier" in ../program.bpf.c).
func Enforcing(p filepolicy.Compiled, slot uint32) bool {
	return int(slot) < len(p.Slots) && p.Slots[slot].Mode == filepolicy.KernelModeEnforce
}

// Barrier is the root barrier attestation of one instance.
type Barrier struct {
	mu       sync.Mutex
	attested bool
	err      error
	// faults is the barrier's predicate fault map (root_barrier_faults).
	faults *ebpf.Map
}

// Faults returns the barrier's predicate faults since the instance started
// (Strict faults denied, Audit faults allowed): witness counters for the
// owner's fail rate. An unreadable map is an error, never zero.
func (b *Barrier) Faults() (map[rootbarrier.Fault]uint64, error) {
	b.mu.Lock()
	faults := b.faults
	b.mu.Unlock()
	if faults == nil {
		return nil, fmt.Errorf("root barrier fault map is unavailable")
	}
	return rootbarrier.Faults(faults)
}

// Err returns why the barrier does not protect the tasks of an enforcing
// slot: not attested yet, or the attestation failed. A binding to an
// enforcing slot depends on it; an audit-only binding never does.
func (b *Barrier) Err() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.attested {
		return fmt.Errorf("root barrier is not attested yet")
	}
	return b.err
}

func (b *Barrier) set(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.attested, b.err = true, err
}

// GetBarrier returns the root barrier attestation of a running instance.
func GetBarrier(gc operators.GadgetContext) (*Barrier, error) {
	value, _ := gc.GetVar(barrierKey)
	b, ok := value.(*Barrier)
	if !ok {
		return nil, fmt.Errorf("file root barrier is unavailable")
	}
	return b, nil
}

// BarrierHooks are the barrier hooks this gadget attests (the kernel keeps 15
// characters of a program name, so names stay that short): ig_file_alloc
// carries the barrier's task_alloc body (ROOT_BARRIER_NO_TASK_ALLOC_PROGRAM
// in ../program.bpf.c).
var BarrierHooks = rootbarrier.WithProgram(rootbarrier.Hooks, "task_alloc", "ig_file_alloc")

// verifyBarrier attests the root barrier (replaced in tests).
var verifyBarrier = rootbarrier.Verify

// instance writes the literal table, then starts the binding controller,
// which writes and freezes the slots before any binding.
type instance struct {
	*enforcement.Bindings
	policy  filepolicy.Compiled
	initial []enforcement.Binding
	barrier *Barrier
}

// Ready attests the root barrier, then completes the binding controller. A
// failed attestation refuses activation when an initial binding is on an
// enforcing slot. Otherwise the instance starts, and Barrier.Err reports the
// failure: the owner then refuses bindings to enforcing slots.
func (i *instance) Ready(gc operators.GadgetContext) error {
	var value any
	if gc != nil {
		value, _ = gc.GetVar(operators.MapPrefix + rootbarrier.FaultsMap)
	}
	if value != nil {
		if m, ok := value.(*ebpf.Map); ok {
			i.barrier.mu.Lock()
			i.barrier.faults = m
			i.barrier.mu.Unlock()
		}
	}
	err := verifyBarrier(gc, BarrierHooks)
	if err != nil {
		err = fmt.Errorf("root barrier: %w", err)
		for _, b := range i.initial {
			if Enforcing(i.policy, b.Slot) {
				return err
			}
		}
	}
	i.barrier.set(err)
	return i.Bindings.Ready(gc)
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
	// The test switches are 0 at load unless the Go config admits fault
	// injection (the gadget parameters cannot).
	if !config.FaultInjection {
		if err := enforcement.ForceTestSwitchesOff(gc, nil); err != nil {
			return nil, err
		}
	}
	creds, err := enforcement.CredConstants(config.CredQuota, config.CredPressure, config.CredSize)
	if err != nil {
		return nil, err
	}
	if err := enforcement.SetNativeConstants(gc, creds); err != nil {
		return nil, err
	}
	var initial []enforcement.Publication
	for slot := range config.Policy.Slots {
		initial = append(initial, publication(config.Policy, uint32(slot), uint32(slot), FromImageUnavailable() == ""))
	}
	b, err := enforcement.New(enforcement.Config{
		Name:                operatorName,
		Generation:          config.Policy.Generation,
		Slots:               filepolicy.KernelMaxSlots,
		InitialBindings:     config.InitialBindings,
		MapPrefix:           MapPrefix,
		PublishMaps:         []string{"file_slots", "file_literals"},
		Purge:               purge,
		ClassOf:             classOf,
		Occupied:            occupied,
		InitialPublications: initial,
		ArmMap:              "armed_tasks",
		FaultMap:            "arming_faults",
		WitnessMap:          "arming_witness",
		AttemptsMap:         "arming_attempts",
		UnevaluatedMap:      "arming_unevaluated",
		StrictSlot:          func(slot uint32) bool { return Enforcing(config.Policy, slot) },
		SubtreeLevels:       enforcement.SubtreeLevels,
		// The file section has no test switches of its own (no
		// TestSwitches): the arming and credential switches of
		// enforcement.TestSwitches are always checked.
		FaultInjection: config.FaultInjection,
		Programs:       Programs,
		CredWalk:       "ig_file_cred_walk",
		CredFree:       "ig_file_cred_free",
	})
	if err != nil {
		return nil, err
	}
	i := &instance{Bindings: b, policy: config.Policy, initial: config.InitialBindings, barrier: &Barrier{}}
	gc.SetVar(bindingsKey, i)
	gc.SetVar(barrierKey, i.barrier)
	return i, nil
}
