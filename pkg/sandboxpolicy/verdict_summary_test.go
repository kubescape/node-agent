package sandboxpolicy

import (
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/utils"
)

// summaryReceiver takes events and summary records.
type summaryReceiver struct{ got []VerdictSummary }

func (*summaryReceiver) ReportEvent(utils.EventType, utils.K8sEvent) {}
func (r *summaryReceiver) ReportVerdictSummary(s VerdictSummary)     { r.got = append(r.got, s) }

// eventOnly takes events only.
type eventOnly struct{}

func (eventOnly) ReportEvent(utils.EventType, utils.K8sEvent) {}

// A summary goes to the section's receivers that take summaries, with the
// cgroup's binding; others get nothing.
func TestReportVerdictSummary(t *testing.T) {
	receivers := maps.NewSafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]()
	takes := &summaryReceiver{}
	receivers.Set(utils.FileAuthorizationEventType, mapset.NewSet[containerwatcher.GenericEventReceiver](takes, eventOnly{}))
	exporter, err := NewSectionExporter(SectionExporterOptions{Capacity: 1, Receivers: receivers,
		ResolveCgroup: func(id uint64) (Binding, bool) { return Binding{CgroupID: id, ContainerID: "c1"}, id == 7 }})
	if err != nil {
		t.Fatal(err)
	}
	resolved, n := exporter.ReportVerdictSummary(VerdictSummary{Section: SectionFile, CgroupID: 7, Rule: "agent-config", Count: 3})
	if n != 1 || resolved.Binding.ContainerID != "c1" {
		t.Fatalf("delivered to %d receivers, want 1; binding %+v", n, resolved.Binding)
	}
	if len(takes.got) != 1 || takes.got[0].Binding.ContainerID != "c1" || takes.got[0].Rule != "agent-config" {
		t.Fatalf("got %+v", takes.got)
	}
	if resolved, n := exporter.ReportVerdictSummary(VerdictSummary{Section: SectionNetwork, CgroupID: 7}); n != 0 || resolved.Binding.ContainerID != "c1" {
		t.Fatalf("no network receiver: %d; the binding is resolved anyway: %+v", n, resolved.Binding)
	}
}
