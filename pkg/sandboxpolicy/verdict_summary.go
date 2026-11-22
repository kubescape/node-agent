package sandboxpolicy

import (
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/utils"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// VerdictSummary is the summary record of the deny verdicts that a section
// gadget's kernel could not report (its per-CPU report limit, or a full ring
// buffer) for one key: generation, slot, rule, hook, mode and cgroup. One
// real attempt of another rule hidden in a flood of cheap denied actions
// still leaves this record: the rule it hit, the first and last task, how
// many times, and when. It has no path, destination or target: the kernel
// keeps no per-deny detail. Counts are approximate.
type VerdictSummary struct {
	Section             string
	Generation          uint64
	Slot                uint32
	CgroupID            uint64
	FirstPID, LastPID   uint32
	FirstComm, LastComm string
	Rule                string
	IsDefault           bool
	Mode                api.RuleMode
	Hook                string
	// Reason is "rate_limited" or "dropped" (ring buffer full).
	Reason      string
	Count       uint64
	First, Last time.Time
	// Binding is the cgroup's binding when the exporter resolves it.
	Binding Binding
}

// VerdictSummaryReceiver is a section verdict receiver that also takes
// summary records. Receivers without it get none (the export schema for
// summaries is a follow-up).
type VerdictSummaryReceiver interface {
	ReportVerdictSummary(VerdictSummary)
}

// sectionEventTypes maps a section to the event type its receivers are
// registered under.
var sectionEventTypes = map[string]utils.EventType{
	SectionPrivilege: utils.PrivilegeAuthorizationEventType,
	SectionNetwork:   utils.NetworkAuthorizationEventType,
	SectionFile:      utils.FileAuthorizationEventType,
}

// ReportVerdictSummary resolves the summary's binding and delivers it, in
// the caller's goroutine, to the section's receivers that take summaries.
// It returns how many took it. It never changes enforcement.
func (e *SectionExporter) ReportVerdictSummary(s VerdictSummary) int {
	if e.options.ResolveCgroup != nil {
		if resolved, ok := e.options.ResolveCgroup(s.CgroupID); ok && resolved.CgroupID == s.CgroupID {
			s.Binding = resolved
		}
	}
	var receivers mapset.Set[containerwatcher.GenericEventReceiver]
	if e.options.Receivers != nil {
		receivers, _ = e.options.Receivers.Load(sectionEventTypes[s.Section])
	}
	if receivers == nil {
		return 0
	}
	n := 0
	for _, receiver := range receivers.ToSlice() {
		r, ok := receiver.(VerdictSummaryReceiver)
		if !ok {
			continue
		}
		if err := guardReceiver(func() error { r.ReportVerdictSummary(s); return nil }); err != nil {
			e.receiverErrors.Add(1)
			continue
		}
		n++
	}
	return n
}
