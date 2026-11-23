package integration

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kubescape/node-agent/pkg/metricsmanager"
)

const (
	// telemetryInterval is how often the verdict telemetry counters are
	// exported.
	telemetryInterval = 15 * time.Second
	// telemetryReadTimeout bounds the backend record lock wait of one
	// kernel counter read (best effort: a shared-node Health read and a
	// per-instance counter read are not interrupted). A read cut short
	// exports no kernel totals for that tick and marks them incomplete.
	telemetryReadTimeout = time.Second
	// lossReportInterval is the minimum time between two loss reports.
	lossReportInterval = time.Minute
)

// verdictTelemetry turns the service's lifetime verdict counters into metric
// deltas and rate-limited loss reports. Observability only: enforcement and
// readiness never read it. Used by the service loop goroutine only.
type verdictTelemetry struct {
	// last is the high-water mark of each counter: a total that drops (an
	// unreadable instance, a restarted shared node) is never reported as
	// negative, and its regrowth is reported only above the mark.
	last map[string]uint64
	// lost is the loss growth since the last report.
	lost     map[string]uint64
	reported time.Time
}

// advance records value as key's current total and returns its growth.
func (t *verdictTelemetry) advance(key string, value uint64, loss bool) uint64 {
	if t.last == nil {
		t.last, t.lost = map[string]uint64{}, map[string]uint64{}
	}
	if value <= t.last[key] {
		return 0
	}
	delta := value - t.last[key]
	t.last[key] = value
	if loss {
		t.lost[key] += delta
	}
	return delta
}

// exportTelemetry exports the exporter, decode and kernel verdict counters
// and reports loss growth through OnError at most once per
// lossReportInterval, carrying the growth since the last report.
func (s *Service) exportTelemetry(ctx context.Context, now time.Time) {
	m := s.options.Metrics
	if m == nil {
		m = metricsmanager.NewMetricsNoop()
	}
	t := &s.telemetry
	exporter := s.exporter.Stats()
	for _, c := range []struct {
		result string
		value  uint64
		loss   bool
	}{
		{"enqueued", exporter.Enqueued, false},
		{"delivered", exporter.Delivered, false},
		{"dropped", exporter.Dropped, true},
		{"receiver_error", exporter.ReceiverErrors, true},
		{"enrichment_error", exporter.EnrichmentErrors, true},
	} {
		if delta := t.advance("exporter/"+c.result, c.value, c.loss); delta != 0 {
			m.ReportSandboxPolicyExporterEvents(c.result, delta)
		}
	}
	// The section gadgets (privilege, network, file): their own queue, and
	// the kernel counters of each running gadget. A deny the kernel could
	// not report (ring buffer full, rate limited) is a loss.
	section := s.SectionExporterStats()
	for _, c := range []struct {
		result string
		value  uint64
		loss   bool
	}{
		{"enqueued", section.Enqueued, false},
		{"delivered", section.Delivered, false},
		{"dropped", section.Dropped, true},
		{"receiver_error", section.ReceiverErrors, true},
		{"enrichment_error", section.EnrichmentErrors, true},
	} {
		if delta := t.advance("section_exporter/"+c.result, c.value, c.loss); delta != 0 {
			m.ReportSandboxPolicySectionExporterEvents(c.result, delta)
		}
	}
	for name, v := range s.SectionVerdictStats() {
		live, retired := v.Live, v.Retired
		for _, c := range []struct {
			result string
			value  uint64
			loss   bool
		}{
			{"denied", live.Denied + retired.Denied, false},
			{"submitted", live.Submitted + retired.Submitted, false},
			{"dropped", live.Dropped + retired.Dropped, true},
			{"rate_limited", live.RateLimited + retired.RateLimited, true},
			{"section_error", live.SectionErrors + retired.SectionErrors, false},
		} {
			key := "section_kernel/" + name + "/" + c.result
			delta := t.advance(key, c.value, false)
			if delta == 0 {
				continue
			}
			if c.loss {
				t.lost["section_kernel/"+c.result] += delta
			}
			m.ReportSandboxPolicySectionKernelEvents(name, c.result, delta)
		}
	}
	if delta := t.advance("decode_error", s.decodeErrors.Load(), true); delta != 0 {
		m.ReportSandboxPolicyDecodeErrors(delta)
	}
	readCtx, cancel := context.WithTimeout(ctx, telemetryReadTimeout)
	submitted, lost, observationErrors, complete, err := s.kernelTotals(readCtx)
	cancel()
	if err != nil {
		// Totals unknown for this tick.
		m.SetSandboxPolicyKernelStatsComplete(false)
	} else {
		m.SetSandboxPolicyKernelStatsComplete(complete)
		for _, c := range []struct {
			result string
			value  uint64
			loss   bool
		}{
			{"submitted", submitted, false},
			{"lost", lost, true},
			{"observation_error", observationErrors, true},
		} {
			if delta := t.advance("kernel/"+c.result, c.value, c.loss); delta != 0 {
				m.ReportSandboxPolicyKernelEvents(c.result, delta)
			}
		}
	}
	if len(t.lost) == 0 || !t.reported.IsZero() && now.Sub(t.reported) < lossReportInterval {
		return
	}
	s.report(fmt.Errorf("sandbox verdict telemetry loss (enforcement unchanged): exporter dropped=%d receiverErrors=%d enrichmentErrors=%d, decodeErrors=%d, kernel lost=%d observationErrors=%d, section exporter dropped=%d receiverErrors=%d enrichmentErrors=%d, section kernel dropped=%d rateLimited=%d since the last report",
		t.lost["exporter/dropped"], t.lost["exporter/receiver_error"], t.lost["exporter/enrichment_error"], t.lost["decode_error"], t.lost["kernel/lost"], t.lost["kernel/observation_error"],
		t.lost["section_exporter/dropped"], t.lost["section_exporter/receiver_error"], t.lost["section_exporter/enrichment_error"], t.lost["section_kernel/dropped"], t.lost["section_kernel/rate_limited"]))
	clear(t.lost)
	t.reported = now
}

// kernelTotals reads the kernel verdict counters: the shared node's when the
// shared engine runs, else the backend's per-instance owned and retired
// totals. complete is false when some counters were unreadable (the totals
// are then a lower bound). err is set only when the read was cut short and
// the totals are unknown for this tick.
func (s *Service) kernelTotals(ctx context.Context) (submitted, lost, observationErrors uint64, complete bool, err error) {
	if s.health != nil {
		h := s.health.Health()
		if !h.Started {
			// No node runs, so no kernel event exists to count.
			return 0, 0, 0, true, nil
		}
		if h.CountersErr != nil {
			return 0, 0, 0, false, nil
		}
		return h.Counters.Submitted, h.Counters.Lost, h.Counters.ObservationErrors, true, nil
	}
	stats, err := s.KernelEventStats(ctx)
	if err != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return 0, 0, 0, false, err
	}
	total := stats.Owned
	total.Submitted += stats.Retired.Submitted
	total.Lost += stats.Retired.Lost
	total.ObservationErrors += stats.Retired.ObservationErrors
	return total.Submitted, total.Lost, total.ObservationErrors, err == nil, nil
}
