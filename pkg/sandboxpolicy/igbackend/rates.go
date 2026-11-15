package igbackend

import (
	"errors"
	"fmt"
	"time"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"k8s.io/apimachinery/pkg/types"
)

// rateReader is a NodeInstance that reads the reporting counters (see
// enforcement.Counters).
type rateReader interface {
	Counters(slot uint32) (enforcement.SlotCounters, error)
	NodeCounters() (enforcement.NodeCounters, error)
}

// extraFailures is a NodeInstance with node-wide failure counters of its own
// (for example the root barrier's predicate faults in a gadget that includes
// it): each class counts as a failure, and as an attempt, of every slot.
type extraFailures interface {
	ExtraFailures() ([]uint64, error)
}

// slotRate is the fail-rate window of one slot. It belongs to the owner, not
// to an instance, so it keeps its samples across heals, reloads and new
// instances (the counters are pinned). A slot reused for another combination
// starts a new window.
type slotRate struct {
	combination string
	window      enforcement.RateWindow
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
	var extra []uint64
	if x, ok := b.instance.(extraFailures); ok && nodeErr == nil {
		extra, nodeErr = x.ExtraFailures()
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
		// Failures: Strict refusals and faults, Audit judgements lost, node
		// faults (a lost child mark that can start in any cgroup) and, with
		// the operator's consent, execs the runtime helper exemption left
		// unjudged. Each also counts as an attempt.
		s := enforcement.RateSample{At: now, Failures: []uint64{c.Faults, c.Unevaluated}, Attempts: c.Attempts}
		for _, n := range extra {
			s.Failures = append(s.Failures, n)
			s.Attempts += n
		}
		if b.section.arming {
			s.Failures = append(s.Failures, node.NodeFaults)
			s.Attempts += node.NodeFaults
			if b.helpers {
				s.Failures = append(s.Failures, node.ExemptExecs)
				s.Attempts += node.ExemptExecs
			}
		}
		r.window.Add(s, nil)
	}
	for slot := range b.rates {
		if !used[slot] {
			delete(b.rates, slot)
		}
	}
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
