// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

// Package enforcement holds the native owner pieces shared by the enforcement
// gadgets. Bindings is the container binding controller of one node-wide gadget
// instance, after the enforce_exec simple engine in the Inspektor Gadget fork.
// Container membership changes live. The section's policy is either written
// and frozen before any binding (Config.WritePolicy), or, in a long-lived
// instance, published per slot in place (Publish, see slots.go and
// ../slots.h). It uses the enforce_exec identity type and key and value size
// in `sandbox_bindings`; the value holds the container's policy slot.
package enforcement

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"

	execpolicy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
	execruntime "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// MaxBindings matches BINDINGS_MAX in ../bindings.h.
const MaxBindings = 1024

// BindingsMap is the binding map of ../bindings.h, after Config.MapPrefix.
const BindingsMap = "bindings"

// ContainerIdentity is the enforce_exec identity, so one owner binds every gadget.
type ContainerIdentity = execruntime.ContainerIdentity

// Binding places one container in one policy slot.
type Binding struct {
	Container ContainerIdentity
	Slot      uint32
	// SkipArming binds without arming the tasks already in the cgroup. Use it
	// for a parent cgroup bound before its containers start: a container
	// runtime helper can be there between its namespace setup and its exec,
	// and must not be judged. Tasks are still armed at their own exec.
	SkipArming bool
	// Subtree also covers the descendant cgroups. Scope is exact by default;
	// set it only for a parent cgroup bound before its containers start, and
	// report it in status.
	Subtree bool
	// RuntimeHelpers admits the runtime helper exemption of ../arming.h for
	// the tasks this binding covers (OCI hooks that runc init forks before the
	// workload starts). Set it only with Subtree on such a parent cgroup.
	RuntimeHelpers bool
}

// Flags of struct sandbox_binding in ../bindings.h.
const (
	bindingSubtree        uint32 = 1 << 0
	bindingStrict         uint32 = 1 << 1
	bindingRuntimeHelpers uint32 = 1 << 2
)

// SubtreeLevels is Config.SubtreeLevels for a gadget built with
// BINDINGS_CGROUP_DEPTH 32: a Subtree binding up to cgroup level 31.
const SubtreeLevels = 31

// bindingValue matches struct sandbox_binding in ../bindings.h.
type bindingValue struct {
	Slot  uint32
	Flags uint32
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
	// controller freezes the map afterwards, before any binding. Leave it
	// nil for a long-lived instance whose slots are published (Publish).
	WritePolicy func(Map) error
	// PublishMaps names the maps a publication writes (the section's policy
	// maps). With WritePolicy nil, Publish passes them to Publication.Write.
	PublishMaps []string
	// Quarantine is how long a replaced or freed buffer stays before it is
	// deleted (default DefaultQuarantine).
	Quarantine time.Duration
	// InitialPublications are published at start, before InitialBindings.
	InitialPublications []Publication
	// MapPrefix is the section's prefix of its pinned maps (SANDBOX_SECTION
	// in ../pin.h). The binding, slot state, publish, arm, fault and witness
	// map names are given without it.
	MapPrefix string
	// Purge deletes every entry of one storage buffer and ClassOf reads the
	// class of the publication there, without the compiled policy: the
	// controller adopts the pinned state a previous instance left (see
	// adopt in slots.go). Required with PublishMaps.
	Purge   func(maps map[string]Map, storage uint32) error
	ClassOf func(maps map[string]Map, storage uint32) (strict bool, err error)
	// ArmMap names the arming task-storage map. When set, binding a container
	// also arms the tasks already running in it (see ../arming.h).
	ArmMap string
	// FaultMap names the per-slot fault array (arming_faults in
	// ../arming.h). When set, SlotFaults reads it.
	FaultMap string
	// WitnessMap names the node-wide witness array (arming_witness in
	// ../arming.h). When set, ArmingWitness reads it.
	WitnessMap string
	// StrictSlot reports whether a slot enforces. The class goes into each
	// binding (BINDING_STRICT), so the program fails closed for a Strict
	// binding even when the slot's policy is missing. Required with FaultMap.
	StrictSlot func(slot uint32) bool
	// SubtreeLevels is the deepest cgroup level of a Subtree binding that the
	// program sees from its descendants: BINDINGS_CGROUP_DEPTH - 1 of the
	// gadget. 0 refuses Subtree bindings.
	//
	// Levels are counted in the owner's cgroup namespace. The kernel counts
	// from the host root, so an owner in a nested cgroup namespace must not
	// bind a subtree near this limit.
	SubtreeLevels int
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
	mu      sync.Mutex
	config  Config
	desired map[execpolicy.Container]Binding
	active  map[uint64]Binding
	// unarmed marks bound cgroups whose running tasks the last bind did
	// not arm, so a retry with the same slot arms them.
	unarmed         map[uint64]bool
	members, armed  Map
	faults, witness FaultMap
	counters        FaultMap // the verdict counters array, nil when unavailable
	ready, stopped  bool
	startupComplete bool
	startupError    error
	lastError       error
	// armExisting is replaced in tests.
	armExisting func(Map, string) error
	// Long-lived instance (WritePolicy nil): see slots.go.
	slotState Map
	publish   map[string]Map
	slots     map[uint32]*slotRecord
	retiring  []retirement
	now       func() time.Time
	// nodeFaultBase: node faults before the last HealNode.
	nodeFaultBase uint64
	// classRetry: slots whose Strict-to-Audit binding rewrite failed after
	// the flip (retried by collect).
	classRetry map[uint32]bool
	// adopted: kernel bindings of the pinned state that no Bind took over
	// yet (see adopt and DropAdopted). listBindings reads them.
	adopted      map[uint64]bindingValue
	listBindings func(Map) (map[uint64]bindingValue, error)
}

func New(config Config) (*Bindings, error) {
	if config.Name == "" || config.Generation == 0 {
		return nil, fmt.Errorf("enforcement controller requires a name and a generation")
	}
	if (config.WritePolicy == nil) == (len(config.PublishMaps) == 0) || (config.WritePolicy != nil && config.PolicyMap == "") {
		return nil, fmt.Errorf("enforcement controller requires a policy writer or the maps to publish")
	}
	if config.WritePolicy == nil && (config.Purge == nil || config.ClassOf == nil) {
		return nil, fmt.Errorf("a long-lived instance needs Purge and ClassOf to adopt pinned state")
	}
	if config.WritePolicy == nil && config.Slots > MaxSlots {
		return nil, fmt.Errorf("%d slots exceed %d", config.Slots, MaxSlots)
	}
	if config.Quarantine == 0 {
		config.Quarantine = DefaultQuarantine
	}
	if len(config.InitialBindings) > MaxBindings {
		return nil, fmt.Errorf("too many initial bindings")
	}
	if config.FaultMap != "" && config.StrictSlot == nil {
		// Without the class a Strict binding would allow on a missing slot.
		return nil, fmt.Errorf("enforcement controller with a fault map requires the slot class")
	}
	b := &Bindings{config: config, desired: map[execpolicy.Container]Binding{}, active: map[uint64]Binding{}, unarmed: map[uint64]bool{}, armExisting: ArmExisting,
		slots: map[uint32]*slotRecord{}, now: time.Now, classRetry: map[uint32]bool{}, adopted: map[uint64]bindingValue{}, listBindings: listPinnedBindings}
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
	if c.RuntimeHelpers && !c.Subtree {
		return fmt.Errorf("the runtime helper exemption needs a subtree binding")
	}
	if c.Subtree && cgroupLevel(c.Container.CgroupPath) > b.config.SubtreeLevels {
		// The program would not see the binding from its descendants.
		return fmt.Errorf("subtree binding deeper than cgroup level %d", b.config.SubtreeLevels)
	}
	if b.config.SubtreeLevels > 0 && b.strict(c.Slot) &&
		cgroupLevel(c.Container.CgroupPath) > b.config.SubtreeLevels {
		// A task that moves into a child cgroup would not be seen as
		// outside the Strict binding's scope, so it would not be judged.
		return fmt.Errorf("Strict binding deeper than cgroup level %d", b.config.SubtreeLevels)
	}
	return validate(c.Container)
}

// cgroupLevel is the cgroup v2 level of a path ("/a/b" is 2).
func cgroupLevel(path string) int {
	return strings.Count(strings.Trim(path, "/"), "/") + 1
}

// value is the kernel binding value of c.
func (b *Bindings) value(c Binding) bindingValue {
	v := bindingValue{Slot: c.Slot}
	if c.Subtree {
		v.Flags |= bindingSubtree
	}
	if b.strict(c.Slot) {
		v.Flags |= bindingStrict
	}
	if c.RuntimeHelpers {
		v.Flags |= bindingRuntimeHelpers
	}
	return v
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
	if b.slotState != nil {
		if r := b.slots[c.Slot]; r == nil || !r.published {
			// The class is unknown and the program would see a slot
			// with no policy.
			return fmt.Errorf("policy slot %d is not published", c.Slot)
		}
	}
	id := c.Container
	previous, bound := b.active[id.CgroupID]
	if bound && previous.Container != id {
		return fmt.Errorf("cgroup identity conflicts with active binding")
	}
	if bound && b.value(previous) == b.value(c) && !b.unarmed[id.CgroupID] {
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
	if err := b.members.Put(id.CgroupID, b.value(c)); err != nil {
		return fmt.Errorf("writing container binding: %w", err)
	}
	delete(b.adopted, id.CgroupID) // this run owns the entry now
	// A slot move arms again too: a task that the old slot left unarmed (an
	// audit slot allows a fork whose child mark failed) must not escape the
	// new slot. A SkipArming binding never arms.
	if b.armed != nil && !c.SkipArming {
		if err := b.armExisting(b.armed, id.CgroupPath); err != nil {
			if bound && !errors.Is(err, ErrContainerGone) {
				// Undo the move, so a retry moves and arms again.
				if perr := b.members.Put(id.CgroupID, b.value(previous)); perr != nil {
					b.active[id.CgroupID] = c
					b.unarmed[id.CgroupID] = true
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
				b.unarmed[id.CgroupID] = true
				return errors.Join(err, derr)
			}
			delete(b.active, id.CgroupID)
			delete(b.unarmed, id.CgroupID)
			return err
		}
	}
	delete(b.unarmed, id.CgroupID)
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
	delete(b.unarmed, c.CgroupID)
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
	// The section's pinned maps carry its prefix (../pin.h).
	getPinned := func(name string) (*ebpf.Map, error) { return getMap(b.config.MapPrefix + name) }
	var policy Map
	if b.config.WritePolicy != nil {
		p, err := getMap(b.config.PolicyMap)
		if err != nil {
			return err
		}
		policy = p
	} else {
		state, err := getPinned(SlotStateMap)
		if err != nil {
			return err
		}
		publish := map[string]Map{}
		for _, name := range b.config.PublishMaps {
			if publish[name], err = getPinned(name); err != nil {
				return err
			}
		}
		if err := b.setPublishMaps(state, publish); err != nil {
			return err
		}
	}
	members, err := getPinned(BindingsMap)
	if err != nil {
		return err
	}
	var faults FaultMap
	if b.config.FaultMap != "" {
		if faults, err = getPinned(b.config.FaultMap); err != nil {
			return err
		}
		if faults.Type() != ebpf.Array || faults.KeySize() != 4 || faults.ValueSize() != 8 || faults.MaxEntries() < b.config.Slots {
			return fmt.Errorf("invalid fault map layout")
		}
	}
	var witness FaultMap
	if b.config.WitnessMap != "" {
		if witness, err = getPinned(b.config.WitnessMap); err != nil {
			return err
		}
		if witness.Type() != ebpf.Array || witness.KeySize() != 4 || witness.ValueSize() != 8 || witness.MaxEntries() != armingWitnessCount {
			return fmt.Errorf("invalid witness map layout")
		}
	}
	var armed Map
	if b.config.ArmMap != "" {
		if armed, err = getPinned(b.config.ArmMap); err != nil {
			return err
		}
		if armed.Type() != ebpf.TaskStorage {
			return fmt.Errorf("invalid arming map layout")
		}
	}
	if err := b.start(policy, members, armed, faults, witness); err != nil {
		return err
	}
	// Telemetry only: a missing or unexpected counters map never fails the
	// instance. VerdictCounters then reports it unavailable.
	if counters, err := getMap("counters"); err == nil && counters.Type() == ebpf.PerCPUArray && counters.KeySize() == 4 && counters.ValueSize() == 8 && counters.MaxEntries() >= verdictCounterCount {
		b.mu.Lock()
		b.counters = counters
		b.mu.Unlock()
	}
	return nil
}

// verdictCounterCount is VERDICT_COUNT_MAX in ../verdict.h.
const verdictCounterCount = 6

// VerdictCounters are the counters of ../verdict.h, summed over all CPUs,
// since the instance started.
type VerdictCounters struct {
	Denied    uint64 // deny decisions, audit and enforce
	Submitted uint64 // verdict events written to the ring buffer
	// Dropped: the ring buffer was full. RateLimited: the per-CPU report
	// limit skipped the event. Both are denies with no event.
	Dropped       uint64
	Allowed       uint64
	SectionErrors uint64
	RateLimited   uint64
}

// VerdictCounters reads the gadget's verdict counters.
func (b *Bindings) VerdictCounters() (VerdictCounters, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.counters == nil {
		return VerdictCounters{}, fmt.Errorf("verdict counters unavailable")
	}
	var totals [verdictCounterCount]uint64
	for i := range totals {
		var perCPU []uint64
		if err := b.counters.Lookup(uint32(i), &perCPU); err != nil {
			return VerdictCounters{}, fmt.Errorf("reading verdict counter %d: %w", i, err)
		}
		for _, v := range perCPU {
			totals[i] += v
		}
	}
	return VerdictCounters{Denied: totals[0], Submitted: totals[1], Dropped: totals[2], Allowed: totals[3], SectionErrors: totals[4], RateLimited: totals[5]}, nil
}

// armingWitnessCount is ARMING_WITNESS_MAX in ../arming.h.
const armingWitnessCount = 2

// ArmingWitness holds the node-wide witness counters of ../arming.h since the
// instance started.
type ArmingWitness struct {
	// NodeFaults: a child mark failed outside a Strict binding, for a child
	// that may start in any cgroup. A nonzero count is a fault of every
	// Strict binding.
	NodeFaults uint64
	// ExemptExecs: execs that the runtime helper exemption left unarmed.
	ExemptExecs uint64
}

// ArmingWitness reads the witness counters.
func (b *Bindings) ArmingWitness() (ArmingWitness, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.witness == nil {
		return ArmingWitness{}, fmt.Errorf("no witness map configured")
	}
	var w [armingWitnessCount]uint64
	for i := range w {
		if err := b.witness.Lookup(uint32(i), &w[i]); err != nil {
			return ArmingWitness{}, fmt.Errorf("reading witness counter %d: %w", i, err)
		}
	}
	nodeFaults := w[0]
	if nodeFaults >= b.nodeFaultBase {
		nodeFaults -= b.nodeFaultBase
	}
	return ArmingWitness{NodeFaults: nodeFaults, ExemptExecs: w[1]}, nil
}

// SlotFaults returns the faults counted for a slot since the instance started
// (see ../arming.h), or, for a published slot, since its first publish or its
// last Heal. A nonzero count means a task of a Strict binding may be outside
// the rules, was refused a fork, or met a slot with no policy.
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
	if r := b.slots[slot]; r != nil && r.published && count >= r.faultBase {
		count -= r.faultBase
	}
	return count, nil
}

// start writes and freezes the policy before any binding is written.
func (b *Bindings) start(policy, members, armed Map, faults, witness FaultMap) error {
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
	if b.config.WritePolicy != nil {
		if err := b.config.WritePolicy(policy); err != nil {
			return err
		}
		if err := policy.Freeze(); err != nil {
			return fmt.Errorf("freezing policy: %w", err)
		}
	}
	b.members, b.armed, b.faults, b.witness = members, armed, faults, witness
	if len(b.config.InitialPublications) > 0 && b.slotState == nil {
		return b.recordError(fmt.Errorf("initial publications need the slot state map"))
	}
	if b.slotState != nil {
		// The state is pinned: start from what the kernel holds.
		if err := b.adopt(); err != nil {
			return b.recordError(err)
		}
	}
	for _, p := range b.config.InitialPublications {
		if err := b.publishSlot(p); err != nil {
			return b.recordError(err)
		}
	}
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
