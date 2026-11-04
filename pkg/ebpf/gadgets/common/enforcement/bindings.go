// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

// Package enforcement holds the native owner pieces shared by the enforcement
// gadgets. Bindings is the container binding controller of one node-wide gadget
// instance, after the enforce_exec simple engine in the Inspektor Gadget fork:
// the section's policy is written and frozen before any binding, container
// membership changes live, and a policy content change starts a replacement
// instance. It uses the enforce_exec identity type and `bindings` key and value
// size; the value holds the container's policy slot.
package enforcement

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/cilium/ebpf"

	execpolicy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
	execruntime "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// MaxBindings matches BINDINGS_MAX in ../bindings.h.
const MaxBindings = 1024

// ContainerIdentity is the enforce_exec identity, so one owner binds every gadget.
type ContainerIdentity = execruntime.ContainerIdentity

// Binding places one container in one policy slot.
type Binding struct {
	Container ContainerIdentity
	Slot      uint32
}

// bindingValue matches struct binding_value in ../bindings.h.
type bindingValue struct {
	Slot     uint32
	Reserved uint32
}

// Map is the part of *ebpf.Map the controller uses.
type Map interface {
	Put(key, value interface{}) error
	Delete(key interface{}) error
	Type() ebpf.MapType
	KeySize() uint32
	ValueSize() uint32
	MaxEntries() uint32
	Flags() uint32
	Freeze() error
}

// Config describes one gadget instance.
type Config struct {
	// Name of the native operator instance.
	Name string
	// Generation identifies the policy of this instance (nonzero).
	Generation      uint64
	InitialBindings []Binding
	// Slots is the number of policy slots in the policy map.
	Slots uint32
	// PolicyMap is the name of the section's policy map.
	PolicyMap string
	// WritePolicy checks the policy map layout and writes the entries. The
	// controller freezes the map afterwards, before any binding.
	WritePolicy func(Map) error
	// ArmMap names the arming task-storage map. When set, binding a container
	// also arms the tasks already running in it (see ../arming.h).
	ArmMap string
	// FaultMap names the per-slot tracking fault array (arming_faults in
	// ../arming.h). When set, SlotFaults reads it.
	FaultMap string
}

// FaultMap is the part of *ebpf.Map that SlotFaults reads.
type FaultMap interface {
	Lookup(key, valueOut interface{}) error
	Type() ebpf.MapType
	KeySize() uint32
	ValueSize() uint32
	MaxEntries() uint32
}

type Status struct {
	Revision uint64
	Bound    int
	Ready    bool
	// Error is a startup or stop error: the instance does not protect.
	Error error
	// LastError is the result of the last live Bind or Unbind. It concerns
	// that call only and does not affect Ready.
	LastError error
}

// Bindings serializes all writes. Map handles are borrowed from the eBPF operator.
type Bindings struct {
	mu              sync.Mutex
	config          Config
	desired         map[execpolicy.Container]Binding
	active          map[uint64]Binding
	members, armed  Map
	faults          FaultMap
	ready, stopped  bool
	startupComplete bool
	startupError    error
	lastError       error
	// armExisting is replaced in tests.
	armExisting func(Map, string) error
}

func New(config Config) (*Bindings, error) {
	if config.Name == "" || config.Generation == 0 || config.PolicyMap == "" || config.WritePolicy == nil {
		return nil, fmt.Errorf("enforcement controller requires a name, a generation and a policy writer")
	}
	if len(config.InitialBindings) > MaxBindings {
		return nil, fmt.Errorf("too many initial bindings")
	}
	b := &Bindings{config: config, desired: map[execpolicy.Container]Binding{}, active: map[uint64]Binding{}, armExisting: ArmExisting}
	for _, c := range config.InitialBindings {
		if err := b.validate(c); err != nil {
			return nil, err
		}
		if _, exists := b.desired[selector(c.Container)]; exists {
			return nil, fmt.Errorf("duplicate initial container identity")
		}
		b.desired[selector(c.Container)] = c
	}
	return b, nil
}

func (b *Bindings) Name() string { return b.config.Name }

func (b *Bindings) Status() Status {
	b.mu.Lock()
	defer b.mu.Unlock()
	return Status{Revision: b.config.Generation, Bound: len(b.active), Ready: b.ready && b.startupComplete && !b.stopped, Error: b.startupError, LastError: b.lastError}
}

// Bind synchronously places one exact container in a slot. Binding a bound
// container to another slot moves it in one map write.
func (b *Bindings) Bind(c Binding) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.ready || b.stopped {
		return b.recordError(fmt.Errorf("binding controller is not running"))
	}
	return b.recordError(b.bind(c))
}

// Unbind ignores stale removal notifications, which cannot remove a newer identity.
func (b *Bindings) Unbind(c ContainerIdentity) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.ready || b.stopped {
		return b.recordError(fmt.Errorf("binding controller is not running"))
	}
	return b.recordError(b.unbind(c))
}

// Ready is the final startup boundary.
func (b *Bindings) Ready(operators.GadgetContext) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.ready || b.stopped {
		return fmt.Errorf("binding controller is not running")
	}
	if b.startupError != nil {
		return b.startupError
	}
	b.startupComplete = true
	return nil
}

// recordError is called with mu held. Startup errors stay sticky.
func (b *Bindings) recordError(err error) error {
	b.lastError = err
	if err != nil && !b.startupComplete && b.startupError == nil {
		b.startupError = err
	}
	return err
}

func selector(c ContainerIdentity) execpolicy.Container {
	return execpolicy.Container{Runtime: c.Runtime, ID: c.ID}
}

func (b *Bindings) validate(c Binding) error {
	if c.Slot >= b.config.Slots {
		return fmt.Errorf("policy slot %d out of range", c.Slot)
	}
	return validate(c.Container)
}

func validate(c ContainerIdentity) error {
	if strings.TrimSpace(c.Runtime) == "" || strings.TrimSpace(c.ID) == "" || c.CgroupID == 0 || c.CgroupPath == "/" || !strings.HasPrefix(c.CgroupPath, "/") {
		return fmt.Errorf("binding requires runtime, full container ID and non-root cgroup v2 identity")
	}
	return nil
}

func (b *Bindings) bind(c Binding) error {
	if err := b.validate(c); err != nil {
		return err
	}
	id := c.Container
	previous, bound := b.active[id.CgroupID]
	if bound && previous.Container != id {
		return fmt.Errorf("cgroup identity conflicts with active binding")
	}
	if bound && previous.Slot == c.Slot {
		return nil
	}
	if !bound {
		for _, other := range b.active {
			if selector(other.Container) == selector(id) {
				return fmt.Errorf("container identity already bound to a different cgroup")
			}
		}
		if len(b.active) >= MaxBindings {
			return fmt.Errorf("container binding capacity exceeded")
		}
	}
	if err := b.members.Put(id.CgroupID, bindingValue{Slot: c.Slot}); err != nil {
		return fmt.Errorf("writing container binding: %w", err)
	}
	// A slot move arms again too: a task that the old slot left unarmed (an
	// audit slot allows a fork whose child mark failed) must not escape the
	// new slot.
	if b.armed != nil {
		if err := b.armExisting(b.armed, id.CgroupPath); err != nil {
			if bound && !errors.Is(err, ErrContainerGone) {
				// Undo the move, so a retry moves and arms again.
				if perr := b.members.Put(id.CgroupID, bindingValue{Slot: previous.Slot}); perr != nil {
					b.active[id.CgroupID] = c
					return errors.Join(err, perr)
				}
				return err
			}
			// A container that is gone needs no protection; a startup
			// replay skips it (see start).
			if derr := b.members.Delete(id.CgroupID); derr != nil {
				// The kernel entry stays: keep it tracked so Unbind can
				// remove it later.
				b.active[id.CgroupID] = c
				return errors.Join(err, derr)
			}
			delete(b.active, id.CgroupID)
			return err
		}
	}
	b.active[id.CgroupID] = c
	return nil
}

func (b *Bindings) unbind(c ContainerIdentity) error {
	if b.desired[selector(c)].Container == c {
		delete(b.desired, selector(c))
	}
	if previous, ok := b.active[c.CgroupID]; !ok || previous.Container != c {
		return nil
	}
	if err := b.members.Delete(c.CgroupID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("removing container binding: %w", err)
	}
	delete(b.active, c.CgroupID)
	return nil
}

func (b *Bindings) Start(gc operators.GadgetContext) error {
	getMap := func(name string) (*ebpf.Map, error) {
		value, _ := gc.GetVar(operators.MapPrefix + name)
		m, ok := value.(*ebpf.Map)
		if !ok || m == nil {
			return nil, fmt.Errorf("missing BPF map %s", name)
		}
		return m, nil
	}
	policy, err := getMap(b.config.PolicyMap)
	if err != nil {
		return err
	}
	members, err := getMap("bindings")
	if err != nil {
		return err
	}
	var faults FaultMap
	if b.config.FaultMap != "" {
		if faults, err = getMap(b.config.FaultMap); err != nil {
			return err
		}
		if faults.Type() != ebpf.Array || faults.KeySize() != 4 || faults.ValueSize() != 8 || faults.MaxEntries() < b.config.Slots {
			return fmt.Errorf("invalid fault map layout")
		}
	}
	var armed Map
	if b.config.ArmMap != "" {
		if armed, err = getMap(b.config.ArmMap); err != nil {
			return err
		}
		if armed.Type() != ebpf.TaskStorage {
			return fmt.Errorf("invalid arming map layout")
		}
	}
	return b.start(policy, members, armed, faults)
}

// SlotFaults returns the tracking faults counted for a slot since the instance
// started (see ../arming.h). A nonzero count means a task of an enforcing slot
// may be outside the rules, or was refused a fork.
func (b *Bindings) SlotFaults(slot uint32) (uint64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.faults == nil {
		return 0, fmt.Errorf("no fault map configured")
	}
	var count uint64
	if err := b.faults.Lookup(slot, &count); err != nil {
		return 0, fmt.Errorf("reading tracking faults: %w", err)
	}
	return count, nil
}

// start writes and freezes the policy before any binding is written.
func (b *Bindings) start(policy, members, armed Map, faults FaultMap) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped {
		return fmt.Errorf("binding controller already stopped")
	}
	if b.ready {
		return fmt.Errorf("binding controller already started")
	}
	if members == nil || members.Type() != ebpf.Hash || members.KeySize() != 8 || members.ValueSize() != 8 || members.MaxEntries() != MaxBindings {
		return fmt.Errorf("invalid binding map layout")
	}
	if err := b.config.WritePolicy(policy); err != nil {
		return err
	}
	if err := policy.Freeze(); err != nil {
		return fmt.Errorf("freezing policy: %w", err)
	}
	b.members, b.armed, b.faults = members, armed, faults
	for _, c := range b.desired {
		if err := b.bind(c); err != nil && !errors.Is(err, ErrContainerGone) {
			return b.recordError(err)
		}
	}
	b.desired = nil
	b.ready = true
	return nil
}

func (b *Bindings) Stop(operators.GadgetContext) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stopped = true
	b.ready = false
	return nil
}

func (b *Bindings) Close(gc operators.GadgetContext) error { return b.Stop(gc) }
