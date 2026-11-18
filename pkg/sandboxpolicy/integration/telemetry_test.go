package integration

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
)

type kernelStatsBackend struct {
	*serviceTestBackend
	stats igbackend.KernelEventStats
	err   error
}

func (b *kernelStatsBackend) KernelEventStats(context.Context) (igbackend.KernelEventStats, error) {
	return b.stats, b.err
}

func telemetryService(t *testing.T) (*Service, *metricsmanager.MetricsMock, *[]error) {
	t.Helper()
	s, _ := testService(t)
	metrics := metricsmanager.NewMetricsMock()
	var reported []error
	s.options.Metrics = metrics
	s.options.OnError = func(err error) { reported = append(reported, err) }
	return s, metrics, &reported
}

func assertSandboxCounters(t *testing.T, m *metricsmanager.MetricsMock, want map[string]uint64) {
	t.Helper()
	for key, value := range want {
		if got := m.SandboxPolicyCounter.Get(key); got != value {
			t.Fatalf("%s = %d, want %d", key, got, value)
		}
	}
}

func assertKernelStatsComplete(t *testing.T, m *metricsmanager.MetricsMock, want bool) {
	t.Helper()
	if got, ok := m.SandboxPolicyKernelStatsComplete.Load().(bool); !ok || got != want {
		t.Fatalf("kernel stats complete = %v (set %v), want %v", got, ok, want)
	}
}

func TestServiceExportsVerdictTelemetry(t *testing.T) {
	s, metrics, reported := telemetryService(t)
	backend := &kernelStatsBackend{serviceTestBackend: s.backend.(*serviceTestBackend)}
	s.backend = backend
	verdicts := func(n int) {
		for range n {
			_ = s.exporter.ReportVerdict(context.Background(), sandboxpolicy.Verdict{})
		}
	}
	verdicts(10) // capacity 8, no Run: 2 dropped
	s.report(fmt.Errorf("%w: unknown generation", igbackend.ErrVerdictDecode))
	s.report(fmt.Errorf("%w: short record", igbackend.ErrVerdictDecode))
	s.report(errors.New("unrelated diagnostic"))
	if s.decodeErrors.Load() != 2 || len(*reported) != 3 {
		t.Fatalf("decode errors %d, reports %v", s.decodeErrors.Load(), *reported)
	}
	*reported = nil
	backend.stats = igbackend.KernelEventStats{Owned: igbackend.KernelEventTotals{Submitted: 5, Lost: 1}, Retired: igbackend.KernelEventTotals{Submitted: 3, ObservationErrors: 2}, OwnedInstances: 1, RetiredInstances: 1}

	t0 := time.Unix(1000, 0)
	s.exportTelemetry(context.Background(), t0)
	assertSandboxCounters(t, metrics, map[string]uint64{"exporter/enqueued": 8, "exporter/delivered": 0, "exporter/dropped": 2, "decode_error": 2, "kernel/submitted": 8, "kernel/lost": 1, "kernel/observation_error": 2})
	assertKernelStatsComplete(t, metrics, true)
	if len(*reported) != 1 || !strings.Contains((*reported)[0].Error(), "exporter dropped=2 ") || !strings.Contains((*reported)[0].Error(), "decodeErrors=2,") || !strings.Contains((*reported)[0].Error(), "kernel lost=1 observationErrors=2,") {
		t.Fatalf("loss reports %v", *reported)
	}

	// An unreadable owned instance lowers the totals: incomplete, never negative.
	verdicts(3)
	backend.stats.Owned = igbackend.KernelEventTotals{}
	backend.stats.OwnedUnavailable = 1
	backend.err = errors.New("instance kernel counters unavailable")
	s.exportTelemetry(context.Background(), t0.Add(telemetryInterval))
	assertSandboxCounters(t, metrics, map[string]uint64{"exporter/dropped": 5, "kernel/submitted": 8, "kernel/lost": 1})
	assertKernelStatsComplete(t, metrics, false)
	if len(*reported) != 1 {
		t.Fatalf("loss report not rate-limited: %v", *reported)
	}

	// Readable again: only growth above the high-water mark is counted, and the
	// next report carries every loss since the last one.
	backend.stats.Owned = igbackend.KernelEventTotals{Submitted: 7, Lost: 4}
	backend.stats.OwnedUnavailable = 0
	backend.err = nil
	s.exportTelemetry(context.Background(), t0.Add(lossReportInterval))
	assertSandboxCounters(t, metrics, map[string]uint64{"exporter/dropped": 5, "kernel/submitted": 10, "kernel/lost": 4, "kernel/observation_error": 2})
	assertKernelStatsComplete(t, metrics, true)
	if len(*reported) != 2 || !strings.Contains((*reported)[1].Error(), "exporter dropped=3 ") || !strings.Contains((*reported)[1].Error(), "decodeErrors=0,") || !strings.Contains((*reported)[1].Error(), "kernel lost=3 observationErrors=0,") {
		t.Fatalf("loss reports %v", *reported)
	}

	// No loss growth: no report, even after the interval.
	s.exportTelemetry(context.Background(), t0.Add(3*lossReportInterval))
	if len(*reported) != 2 {
		t.Fatalf("report without loss: %v", *reported)
	}

	// A read cut short by its deadline exports no kernel totals, even above
	// the high-water mark, and marks them unknown.
	backend.stats.Owned = igbackend.KernelEventTotals{Submitted: 100}
	backend.err = context.DeadlineExceeded
	s.exportTelemetry(context.Background(), t0.Add(4*lossReportInterval))
	assertSandboxCounters(t, metrics, map[string]uint64{"kernel/submitted": 10})
	assertKernelStatsComplete(t, metrics, false)
}

func TestServiceTelemetrySharedNodeCounters(t *testing.T) {
	s, metrics, reported := telemetryService(t)
	s.backend = &kernelStatsBackend{serviceTestBackend: s.backend.(*serviceTestBackend), err: errors.New("per-binding counters must not be read")}
	t0 := time.Unix(1000, 0)

	s.health = fakeSharedHealthEngine{health: igbackend.SharedNodeHealth{}}
	s.exportTelemetry(context.Background(), t0)
	assertKernelStatsComplete(t, metrics, true) // no node, no kernel event

	s.health = fakeSharedHealthEngine{health: igbackend.SharedNodeHealth{Started: true, Counters: fullruntime.KernelEventCounters{Submitted: 4, Lost: 2, ObservationErrors: 1}}}
	s.exportTelemetry(context.Background(), t0.Add(telemetryInterval))
	assertSandboxCounters(t, metrics, map[string]uint64{"kernel/submitted": 4, "kernel/lost": 2, "kernel/observation_error": 1})
	assertKernelStatsComplete(t, metrics, true)

	// Unreadable counters are unknown, never zero.
	s.health = fakeSharedHealthEngine{health: igbackend.SharedNodeHealth{Started: true, CountersErr: errors.New("counters map unreadable")}}
	s.exportTelemetry(context.Background(), t0.Add(2*telemetryInterval))
	assertSandboxCounters(t, metrics, map[string]uint64{"kernel/submitted": 4, "kernel/lost": 2, "kernel/observation_error": 1})
	assertKernelStatsComplete(t, metrics, false)
	if len(*reported) != 1 || !strings.Contains((*reported)[0].Error(), "kernel lost=2 observationErrors=1,") {
		t.Fatalf("loss reports %v", *reported)
	}
}

func TestServiceTelemetryWithoutMetrics(t *testing.T) {
	s, _ := testService(t)
	s.exportTelemetry(context.Background(), time.Unix(1000, 0))
}

type statsSectionOwner struct{ stats igbackend.VerdictStats }

func (f *statsSectionOwner) SlotPolicies(uint64, uint32) ([]sandboxpolicy.CompiledPolicy, bool) {
	return nil, false
}
func (f *statsSectionOwner) VerdictStats() igbackend.VerdictStats { return f.stats }

// Review 5: the section verdict queue and the kernel counters of each section
// gadget reach the metrics, and their loss reaches the loss report.
func TestServiceExportsSectionTelemetry(t *testing.T) {
	s, metrics, reported := telemetryService(t)
	exporter, err := sandboxpolicy.NewSectionExporter(sandboxpolicy.SectionExporterOptions{Capacity: 2})
	if err != nil {
		t.Fatal(err)
	}
	s.sectionExporter = exporter
	for range 3 { // capacity 2, no Run: 1 dropped
		s.reportSection(sandboxpolicy.NewFileVerdictEvent(sandboxpolicy.SectionVerdict{}, sandboxpolicy.Binding{}, sandboxpolicy.FileTarget{}))
	}
	file := &statsSectionOwner{stats: igbackend.VerdictStats{
		Live:    enforcement.VerdictCounters{Denied: 9, Submitted: 6, Dropped: 2, RateLimited: 1},
		Retired: enforcement.VerdictCounters{Denied: 1, Submitted: 1, SectionErrors: 3},
	}}
	s.sectionOwners = map[string]sectionOwner{"file": file}
	t0 := time.Unix(1000, 0)
	s.exportTelemetry(context.Background(), t0)
	assertSandboxCounters(t, metrics, map[string]uint64{
		"section_exporter/enqueued": 2, "section_exporter/dropped": 1,
		"section_kernel/file/denied": 10, "section_kernel/file/submitted": 7, "section_kernel/file/dropped": 2,
		"section_kernel/file/rate_limited": 1, "section_kernel/file/section_error": 3,
	})
	if len(*reported) != 1 || !strings.Contains((*reported)[0].Error(), "section exporter dropped=1 ") || !strings.Contains((*reported)[0].Error(), "section kernel dropped=2 rateLimited=1 ") {
		t.Fatalf("loss reports %v", *reported)
	}
	// Growth only: a later read adds the difference.
	file.stats.Live.Dropped = 5
	s.exportTelemetry(context.Background(), t0.Add(lossReportInterval))
	assertSandboxCounters(t, metrics, map[string]uint64{"section_kernel/file/dropped": 5})
	if len(*reported) != 2 || !strings.Contains((*reported)[1].Error(), "section kernel dropped=3 rateLimited=0 ") {
		t.Fatalf("loss reports %v", *reported)
	}
}
