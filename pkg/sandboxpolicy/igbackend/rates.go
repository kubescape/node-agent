package igbackend

import (
	"errors"
	"fmt"
	"time"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
)

// rateReader is a NodeInstance that reads the reporting counters (see
// enforcement.Counters).
type rateReader interface {
	Counters(slot uint32) (enforcement.SlotCounters, error)
	NodeCounters() (enforcement.NodeCounters, error)
}

// extraNotices is a NodeInstance with node-wide failure counters of its own
// that no slot can claim (for example the root barrier's predicate faults in
// a gadget that includes it): they are notices of every slot, Degraded for
// 60 s, never a rate (they have no attempts of their own).
type extraNotices interface {
	ExtraNotices() (uint64, error)
}

// slotRate is the fail-rate window of one slot. It belongs to the owner, not
// to an instance, so it keeps its samples across heals, reloads and new
// instances (the counters are pinned). A slot reused for another combination
// starts a new window.
type slotRate struct {
	combination string
	window      enforcement.RateWindow
	// exempt counts the node's exempted execs since the slot first had a
	// helper-flagged pod binding: base is the node count then, and
	// exempt the notices so far (they never decrease).
	exemptSeen bool
	exemptBase uint64
	exempt     uint64
}

// SampleRates reads the reporting counters of every slot in use into its
// window. Call it periodically (the service refresh, every few seconds): a
// window with no recent sample is unknown.
func (b *nodeOwner[C]) SampleRates(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.rates == nil {
		b.rates = map[uint32]*slotRate{}
	}
	reader, ok := b.instance.(rateReader)
	var node enforcement.NodeCounters
	var nodeErr error
	switch {
	case b.instance == nil || !ok:
		nodeErr = fmt.Errorf("no running %s instance reads its counters", b.section.name)
	case b.section.arming:
		node, nodeErr = reader.NodeCounters()
	}
	var extra uint64
	if x, ok := b.instance.(extraNotices); ok && nodeErr == nil {
		extra, nodeErr = x.ExtraNotices()
	}
	helperSlots := map[string]bool{}
	for _, p := range b.pods {
		helperSlots[p.combination] = true
	}
	used := map[uint32]bool{}
	for combination, slot := range b.slots {
		used[slot] = true
		r := b.rates[slot]
		if r == nil || r.combination != combination {
			r = &slotRate{combination: combination}
			b.rates[slot] = r
		}
		if nodeErr != nil {
			r.window.Add(enforcement.RateSample{At: now}, nodeErr)
			continue
		}
		c, err := reader.Counters(slot)
		if err != nil {
			r.window.Add(enforcement.RateSample{At: now}, err)
			continue
		}
		// Failures: Strict refusals and faults and Audit judgements lost;
		// for a Strict slot also node faults (a lost child mark can start in
		// a Strict cgroup). Each also counts as an attempt. The instance's
		// own node-wide classes are notices. For an Audit slot a node fault
		// is a notice too:
		// the lost child can start in its cgroup unjudged, but which cgroup
		// it lands in is not known, so it degrades for 60 s and is never a
		// rate. Execs that the runtime helper exemption left unjudged (the
		// operator agreed to it) are notices of the slots with helper-flagged
		// pod bindings too.
		s := enforcement.RateSample{At: now, Failures: []uint64{c.Faults, c.Unevaluated}, Attempts: c.Attempts}
		s.Notices = extra
		if b.section.arming {
			strict := strictPolicies(b.combinations[combination])
			if strict {
				s.Failures = append(s.Failures, node.NodeFaults)
				s.Attempts += node.NodeFaults
			}
			if b.helpers && helperSlots[combination] {
				switch {
				case !r.exemptSeen:
					// The slot's first helper-flagged pod binding: the
					// exemptions before it are not this slot's.
					r.exemptSeen, r.exemptBase = true, node.ExemptExecs
				case node.ExemptExecs >= r.exemptBase:
					r.exempt = max(r.exempt, node.ExemptExecs-r.exemptBase)
				default:
					// The counter was created again: count from it.
					r.exemptBase = node.ExemptExecs
				}
			}
			s.Notices += r.exempt
			if !strict {
				s.Notices += node.NodeFaults
			}
		}
		r.window.Add(s, nil)
	}
	for slot := range b.rates {
		if !used[slot] {
			delete(b.rates, slot)
		}
	}
	b.sampleLoss(now)
}

// sampleLoss adds the section's lost-verdict total (kernel dropped and rate
// limited, running and retired instances) to its window. A running instance
// whose counters cannot be read makes the loss unknown (never zero): the
// window starts a new history, so the count does not come back later as a
// false loss.
func (b *nodeOwner[C]) sampleLoss(now time.Time) {
	stats := b.verdictStatsLocked()
	if stats.Unavailable > b.retiredUnavailable {
		b.loss.markUnknown()
		return
	}
	old, readable := b.oldSetLost()
	if !readable {
		b.loss.markUnknown()
		return
	}
	b.loss.add(now, stats.Live.Dropped+stats.Live.RateLimited+stats.Retired.Dropped+stats.Retired.RateLimited+old)
}

// lossWindow keeps a section's lost-verdict total over DegradedWindow: denies
// that the kernel counted but could not report (per-CPU report limit, full
// ring buffer). The counters are per section for the whole node. After an
// unreadable counter or a lower total (counters created again) the loss is
// unknown until a full DegradedWindow of readable samples follows.
type lossWindow struct {
	samples []lossSample
	unknown bool
}

type lossSample struct {
	at    time.Time
	total uint64
}

// add records a total.
func (w *lossWindow) add(at time.Time, total uint64) {
	if n := len(w.samples); n > 0 && total < w.samples[n-1].total {
		w.markUnknown()
	}
	w.samples = append(w.samples, lossSample{at: at, total: total})
	// Keep one sample at or before the window's start.
	cut := 0
	for i := range w.samples {
		if at.Sub(w.samples[i].at) >= enforcement.DegradedWindow {
			cut = i
		}
	}
	w.samples = w.samples[cut:]
}

// markUnknown starts a new history whose loss is unknown until it holds a
// full DegradedWindow.
func (w *lossWindow) markUnknown() {
	w.samples, w.unknown = nil, true
}

// recent is the growth over the last DegradedWindow (over the history there
// is, when it is shorter), or unknown. 0 without a sample in the window: the
// fail-rate window already reports a missing sample as unknown.
func (w *lossWindow) recent(now time.Time) (lost uint64, unknown bool) {
	n := len(w.samples)
	if w.unknown && n > 0 && w.samples[n-1].at.Sub(w.samples[0].at) >= enforcement.DegradedWindow {
		w.unknown = false
	}
	if w.unknown {
		return 0, true
	}
	if n == 0 || now.Sub(w.samples[n-1].at) > enforcement.DegradedWindow {
		return 0, false
	}
	newest, base := w.samples[n-1], w.samples[0]
	for _, s := range w.samples {
		if newest.at.Sub(s.at) >= enforcement.DegradedWindow {
			base = s
		}
	}
	return newest.total - base.total, false
}

// PolicyRates applies the reporting rule to the slots whose combination
// includes the policy: Degraded or NotReady when any is, unknown when any is
// (never zero). ok is false when no slot of this section has the policy.
func (b *nodeOwner[C]) PolicyRates(uid types.UID, now time.Time) (report sandboxpolicy.RateReport, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var unknown []error
	var last, failed, attempts uint64
	for combination, slot := range b.slots {
		if !combinationHas(b.combinations[combination], uid) {
			continue
		}
		ok = true
		r := b.rates[slot]
		if r == nil || r.combination != combination {
			unknown = append(unknown, fmt.Errorf("%s slot %d: no counter sample", b.section.name, slot))
			continue
		}
		rep := r.window.Report(now)
		if rep.Unknown != nil {
			unknown = append(unknown, fmt.Errorf("%s slot %d: %w", b.section.name, slot, rep.Unknown))
			continue
		}
		report.Degraded = report.Degraded || rep.Degraded
		report.NotReady = report.NotReady || rep.NotReady
		last, failed, attempts = last+rep.Last.Failures, failed+rep.Long.Failures, attempts+rep.Long.Attempts
	}
	report.Unknown = errors.Join(unknown...)
	if n, unknown := b.loss.recent(now); ok && unknown {
		report.SuppressedUnknown = b.section.name
	} else if ok && n > 0 {
		report.Suppressed, report.SuppressedNote = n, fmt.Sprintf("%s %d", b.section.name, n)
	}
	report.Message = fmt.Sprintf("%s: %d fail-closed or unevaluated in the last %s; %d of %d over %s (NotReady above %.1f%%)",
		b.section.name, last, enforcement.DegradedWindow, failed, attempts, enforcement.NotReadyWindow, enforcement.NotReadyThreshold*100)
	return report, ok
}

func combinationHas(policies []sandboxpolicy.CompiledPolicy, uid types.UID) bool {
	for _, p := range policies {
		if p.Identity.UID == uid {
			return true
		}
	}
	return false
}

// strictPolicies reports whether a combination enforces: any of its policies
// is in enforce mode (its slot's class).
func strictPolicies(policies []sandboxpolicy.CompiledPolicy) bool {
	for _, p := range policies {
		if p.Mode == api.ModeEnforce {
			return true
		}
	}
	return false
}
