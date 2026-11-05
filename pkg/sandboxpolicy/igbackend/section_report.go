package igbackend

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// SectionReporter receives the verdicts of the privilege, network and file
// gadgets. It runs on the gadget's event path: it must not block.
type SectionReporter func(sandboxpolicy.SectionEvent)

// verdictFields reads the fields that every section verdict has
// (common/verdict.h and the event header of each gadget).
type verdictFields struct {
	generation, cgroup, mode, pid, ruleID, originID, isDefault, slot, comm, hook datasource.FieldAccessor
}

func newVerdictFields(ds datasource.DataSource) (verdictFields, error) {
	get := func(name string) (datasource.FieldAccessor, error) {
		if f := ds.GetField(name); f != nil {
			return f, nil
		}
		return nil, fmt.Errorf("missing verdict field %q", name)
	}
	var f verdictFields
	var err error
	for _, p := range []struct {
		out  *datasource.FieldAccessor
		name string
	}{{&f.generation, "generation"}, {&f.cgroup, "cgroup"}, {&f.mode, "mode"}, {&f.pid, "host_pid"}, {&f.ruleID, "rule_id"},
		{&f.originID, "origin_id"}, {&f.isDefault, "is_default"}, {&f.slot, "slot"}, {&f.comm, "comm"}, {&f.hook, "hook"}} {
		if *p.out, err = get(p.name); err != nil {
			return f, err
		}
	}
	return f, nil
}

// read decodes the common fields. names and origins are the id tables of the
// instance's compiled policy. It also returns the hook name.
func (f verdictFields) read(data datasource.Data, section string, names, origins []string) (sandboxpolicy.SectionVerdict, string) {
	lookup := func(list []string, id uint32) string {
		if int(id) < len(list) {
			return list[id]
		}
		return ""
	}
	ruleID, _ := f.ruleID.Uint32(data)
	originID, _ := f.originID.Uint32(data)
	mode, _ := f.mode.Uint32(data)
	isDefault, _ := f.isDefault.Uint32(data)
	slot, _ := f.slot.Uint32(data)
	pid, _ := f.pid.Uint32(data)
	cgroup, _ := f.cgroup.Uint64(data)
	generation, _ := f.generation.Uint64(data)
	comm, _ := f.comm.String(data)
	hook, _ := f.hook.String(data)
	return sandboxpolicy.NewSectionVerdict(section, generation, cgroup, mode, pid, slot, isDefault != 0,
		lookup(names, ruleID), lookup(origins, originID), comm), hook
}

// maxSlotTables is how many instance generations keep their slot policies.
// The current instance and the ones still stopping are the recent ones; an
// event of an older instance gets no policy (absent, not guessed).
const maxSlotTables = 4

// remember keeps the slot policies of the instance with this generation.
func (b *nodeOwner[C]) remember(generation uint64, slots [][]sandboxpolicy.CompiledPolicy) {
	b.tablesMu.Lock()
	defer b.tablesMu.Unlock()
	if b.tables == nil {
		b.tables = map[uint64][][]sandboxpolicy.CompiledPolicy{}
	}
	b.tables[generation] = slots
	for g := range b.tables {
		if g+maxSlotTables <= generation {
			delete(b.tables, g)
		}
	}
}

// SlotPolicies returns the policies of one slot of the instance with this
// generation: the event's generation and slot fields. It does not take the
// owner lock, so a reporter can call it while a replacement runs.
func (b *nodeOwner[C]) SlotPolicies(generation uint64, slot uint32) ([]sandboxpolicy.CompiledPolicy, bool) {
	b.tablesMu.Lock()
	defer b.tablesMu.Unlock()
	slots, ok := b.tables[generation]
	if !ok || int(slot) >= len(slots) {
		return nil, false
	}
	return append([]sandboxpolicy.CompiledPolicy(nil), slots[slot]...), true
}

// verdictCounterSource is a NodeInstance that reads its gadget's counters.
type verdictCounterSource interface {
	VerdictCounters() (enforcement.VerdictCounters, error)
}

// VerdictStats are the kernel verdict counters of a section, over the owner's
// lifetime. Retired holds the last reading of each stopped instance, so it is
// a lower bound. Unavailable counts instances whose counters could not be
// read: check it before reading zero drops as no drops.
type VerdictStats struct {
	Live, Retired enforcement.VerdictCounters
	Unavailable   uint64
}

func addCounters(a *enforcement.VerdictCounters, b enforcement.VerdictCounters) {
	a.Denied += b.Denied
	a.Submitted += b.Submitted
	a.Dropped += b.Dropped
	a.Allowed += b.Allowed
	a.SectionErrors += b.SectionErrors
	a.RateLimited += b.RateLimited
}

// VerdictStats reads the counters of the running instances.
func (b *nodeOwner[C]) VerdictStats() VerdictStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	stats := VerdictStats{Retired: b.retired, Unavailable: b.retiredUnavailable}
	instances := append([]NodeInstance(nil), b.retiring...)
	if b.instance != nil {
		instances = append(instances, b.instance)
	}
	for _, i := range instances {
		c, err := counters(i)
		if err != nil {
			stats.Unavailable++
			continue
		}
		addCounters(&stats.Live, c)
	}
	return stats
}

func counters(i NodeInstance) (enforcement.VerdictCounters, error) {
	source, ok := i.(verdictCounterSource)
	if !ok {
		return enforcement.VerdictCounters{}, fmt.Errorf("instance has no verdict counters")
	}
	return source.VerdictCounters()
}
