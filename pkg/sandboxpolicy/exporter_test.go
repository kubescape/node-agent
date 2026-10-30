package sandboxpolicy

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

type rawVerdictReceiver struct{ received chan utils.K8sEvent }

func (r *rawVerdictReceiver) ReportEvent(_ utils.EventType, event utils.K8sEvent) {
	r.received <- event
}

type enrichedVerdictReceiver struct{ received chan *events.EnrichedEvent }

func (r *enrichedVerdictReceiver) ReportEnrichedEvent(event *events.EnrichedEvent) {
	r.received <- event
}

type failingVerdictReceiver struct{ calls atomic.Int32 }

func (r *failingVerdictReceiver) ReportVerdict(context.Context, Verdict) error {
	r.calls.Add(1)
	return errors.New("export unavailable")
}

type panicVerdictReceiver struct{}

func (*panicVerdictReceiver) ReportEvent(utils.EventType, utils.K8sEvent) { panic("consumer bug") }

type fakeVerdictEnricher struct {
	event    utils.EnrichEvent
	syscalls []uint64
	calls    int
	callback containerwatcher.ResultCallback
	delayed  bool
}

func (f *fakeVerdictEnricher) SubmitEnrichmentTask(event utils.EnrichEvent, syscalls []uint64, callback containerwatcher.ResultCallback, _ string, _ uint32) {
	f.event = event
	f.syscalls = syscalls
	f.calls++
	f.callback = callback
	if !f.delayed {
		event.SetExtra("stack-context")
		callback(event, "must-not-replace-container", 99999)
	}
}

func receiverMap(receivers ...containerwatcher.GenericEventReceiver) *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]] {
	result := &maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]{}
	result.Set(utils.ExecAuthorizationEventType, mapset.NewSet[containerwatcher.GenericEventReceiver](receivers...))
	return result
}
func sampleVerdict() Verdict {
	uid := uint32(1000)
	image := false
	return Verdict{Time: time.Unix(1710000000, 1234), Policy: PolicyIdentity{Kind: "SandboxPolicy", Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 3}, Revision: "revision", Rule: "rule", Origin: "authored", Mode: api.RuleEnforce, Verdict: api.ActionDeny, Reason: "matched deny", ContainerID: "container", CgroupID: 12, PID: 41, ParentPID: 40, UID: &uid, ActorPath: "/bin/actor", TargetPath: "/bin/target", Argv: []string{"target", "--flag"}, FromImage: &image}
}
func TestExecVerdictEventRetainsKnownMetadataWithoutInventingExec(t *testing.T) {
	v := sampleVerdict()
	b := binding()
	b.MountNamespace = 123
	event := NewExecVerdictEvent(v, b)
	if event.GetEventType() != utils.ExecAuthorizationEventType || event.GetEventType() == utils.ExecveEventType {
		t.Fatal("verdict classified as successful exec observation")
	}
	if _, ok := any(event).(utils.ExecEvent); ok {
		t.Fatal("attempt must not implement observer ExecEvent")
	}
	if !reflect.DeepEqual(event.Verdict, v) || event.GetNamespace() != "ns" || event.GetPod() != "pod" || event.GetContainer() != "app" || event.GetMountNsID() != 123 || event.GetPID() != 41 || event.GetPpid() != 40 || *event.GetUid() != 1000 {
		t.Fatalf("lost correlation: %+v", event)
	}
	if event.FieldPresent("comm") || event.FieldPresent("error") || event.FieldPresent("gid") || event.GetComm() != "" || event.GetGid() != nil || event.GetContainerImage() != "" {
		t.Fatal("unknown values fabricated")
	}
	if !event.FieldPresent("uid") || !event.FieldPresent("pid") {
		t.Fatal("known fields hidden")
	}
	v.Argv[0] = "mutated"
	*v.UID = 2
	*v.FromImage = true
	b.PodLabels["app"] = "mutated"
	if event.Verdict.Argv[0] != "target" || *event.GetUid() != 1000 || *event.Verdict.FromImage || event.GetPodLabels()["app"] != "test" {
		t.Fatal("event aliases producer memory")
	}
}

// An authorization-only receiver must not depend on observation dispatch keys
// or on a serializer's choice to reuse an existing exec wire format.
func TestExecAuthorizationDispatchKey(t *testing.T) {
	if utils.ExecAuthorizationEventType != "execAuthorization" || utils.ExecAuthorizationEventType == utils.ExecveEventType {
		t.Fatal("exec authorization must retain its own internal dispatch key")
	}
	receiver := &dispatchKeyReceiver{received: make(chan utils.EventType, 1)}
	exporter, err := NewVerdictExporter(ExporterOptions{Capacity: 1, Receivers: receiverMap(receiver)})
	if err != nil {
		t.Fatal(err)
	}
	exporter.dispatch(context.Background(), NewExecVerdictEvent(sampleVerdict(), binding()))
	select {
	case got := <-receiver.received:
		if got != utils.ExecAuthorizationEventType {
			t.Fatalf("raw receiver dispatched under %q", got)
		}
	default:
		t.Fatal("authorization receiver was not called")
	}
}

type dispatchKeyReceiver struct{ received chan utils.EventType }

func (r *dispatchKeyReceiver) ReportEvent(eventType utils.EventType, _ utils.K8sEvent) {
	r.received <- eventType
}

func TestDeniedAuditAndAllowedEventsReachPublicReceivers(t *testing.T) {
	raw := &rawVerdictReceiver{make(chan utils.K8sEvent, 3)}
	enriched := &enrichedVerdictReceiver{make(chan *events.EnrichedEvent, 3)}
	observe := &rawVerdictReceiver{make(chan utils.K8sEvent, 1)}
	receivers := receiverMap(raw, enriched)
	receivers.Set(utils.ExecveEventType, mapset.NewSet[containerwatcher.GenericEventReceiver](observe))
	exporter, err := NewVerdictExporter(ExporterOptions{Capacity: 4, Receivers: receivers, ResolveBinding: func(Verdict) (Binding, bool) { return binding(), true }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- exporter.Run(ctx) }()
	defer func() { cancel(); <-done }()
	for _, test := range []struct {
		action api.Action
		mode   api.RuleMode
		would  bool
	}{{api.ActionDeny, api.RuleEnforce, false}, {api.ActionDeny, api.RuleAudit, true}, {api.ActionAllow, api.RuleEnforce, false}} {
		v := sampleVerdict()
		v.Verdict = test.action
		v.Mode = test.mode
		v.WouldDeny = test.would
		if err := exporter.ReportVerdict(ctx, v); err != nil {
			t.Fatal(err)
		}
		select {
		case event := <-raw.received:
			if !reflect.DeepEqual(event.(*ExecVerdictEvent).Verdict, v) {
				t.Fatal("raw verdict lost")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("raw receiver did not receive attempt")
		}
		select {
		case event := <-enriched.received:
			if !reflect.DeepEqual(event.Event.(*ExecVerdictEvent).Verdict, v) || event.PID != v.PID || event.ContainerID != v.ContainerID || event.ProcessTree.PID != 0 {
				t.Fatal("enrichment lost verdict or fabricated process tree")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("enriched receiver did not receive attempt")
		}
	}
	select {
	case <-observe.received:
		t.Fatal("verdict leaked into observer exec receivers")
	default:
	}
}

func TestReceiverFailuresCannotChangeVerdictsOrBlockOtherSubscribers(t *testing.T) {
	failing := &failingVerdictReceiver{}
	raw := &rawVerdictReceiver{make(chan utils.K8sEvent, 1)}
	exporter, err := NewVerdictExporter(ExporterOptions{Capacity: 1, Receivers: receiverMap(failing, &panicVerdictReceiver{}, raw)})
	if err != nil {
		t.Fatal(err)
	}
	original := sampleVerdict()
	exporter.dispatch(context.Background(), NewExecVerdictEvent(original, binding()))
	if failing.calls.Load() != 1 || exporter.Stats().ReceiverErrors != 2 || exporter.Stats().Delivered != 1 {
		t.Fatalf("errors not isolated/reported: %+v", exporter.Stats())
	}
	if got := (<-raw.received).(*ExecVerdictEvent); !reflect.DeepEqual(got.Verdict, original) {
		t.Fatal("receiver failures changed enforcement verdict")
	}
}

func TestOptionalEnrichmentDoesNotFabricateForkOrReplaceVerdict(t *testing.T) {
	enricher := &fakeVerdictEnricher{}
	receiver := &enrichedVerdictReceiver{make(chan *events.EnrichedEvent, 1)}
	exporter, err := NewVerdictExporter(ExporterOptions{Capacity: 1, Receivers: receiverMap(receiver), Enricher: enricher})
	if err != nil {
		t.Fatal(err)
	}
	v := sampleVerdict()
	exporter.deliver(context.Background(), NewExecVerdictEvent(v, binding()))
	got := <-receiver.received
	if enricher.calls != 1 || len(enricher.syscalls) != 0 || got.PID != v.PID || got.ContainerID != v.ContainerID || !reflect.DeepEqual(got.Event.(*ExecVerdictEvent).Verdict, v) || got.Event.(utils.EnrichEvent).GetExtra() != "stack-context" {
		t.Fatal("enricher invented fork or replaced authoritative attempt metadata")
	}
}

func TestQueueAndShutdownLossAreExplicit(t *testing.T) {
	exporter, err := NewVerdictExporter(ExporterOptions{Capacity: 1})
	if err != nil {
		t.Fatal(err)
	}
	v := sampleVerdict()
	if err := exporter.ReportVerdict(context.Background(), v); err != nil {
		t.Fatal(err)
	}
	if err := exporter.ReportVerdict(context.Background(), v); !errors.Is(err, ErrVerdictQueueFull) {
		t.Fatalf("expected nonblocking overflow: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := exporter.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := exporter.ReportVerdict(context.Background(), v); !errors.Is(err, ErrVerdictExporterStopped) {
		t.Fatal("accepted after shutdown")
	}
	if stats := exporter.Stats(); stats.Enqueued != 1 || stats.Dropped != 3 {
		t.Fatalf("loss not counted: %+v", stats)
	}
	if v.Verdict != api.ActionDeny || v.Mode != api.RuleEnforce {
		t.Fatal("queue state changed verdict")
	}
}

func TestMissingBindingDoesNotUseReusedIdentity(t *testing.T) {
	wrong := binding()
	wrong.CgroupID++
	exporter, err := NewVerdictExporter(ExporterOptions{Capacity: 1, ResolveBinding: func(Verdict) (Binding, bool) { return wrong, true }})
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.ReportVerdict(context.Background(), sampleVerdict()); err != nil {
		t.Fatal(err)
	}
	got := <-exporter.queue
	if got.GetNamespace() != "" || got.GetPod() != "" || got.GetMountNsID() != 0 || got.GetContainerID() != "container" {
		t.Fatal("reused runtime identity incorrectly enriched")
	}
}

func TestCancelledPendingEnrichmentCountsLossOnce(t *testing.T) {
	enricher := &fakeVerdictEnricher{delayed: true}
	receiver := &rawVerdictReceiver{make(chan utils.K8sEvent, 1)}
	exporter, err := NewVerdictExporter(ExporterOptions{Capacity: 1, Receivers: receiverMap(receiver), Enricher: enricher})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	exporter.deliver(ctx, NewExecVerdictEvent(sampleVerdict(), binding()))
	enricher.callback(enricher.event, "container", 41)
	if exporter.Stats().Dropped != 1 || exporter.Stats().Delivered != 0 {
		t.Fatalf("late callback double-counted or delivered after cancellation: %+v", exporter.Stats())
	}
}

func TestFullVerdictProvenanceCloneBoundaries(t *testing.T) {
	v := sampleVerdict()
	v.PolicySet = []PolicyRevision{{Policy: v.Policy, Revision: v.Revision}}
	v.Matches = []RuleMatch{{Policy: v.Policy, Name: "original"}}
	v.MatchesComplete = true
	a, b := &rawVerdictReceiver{received: make(chan utils.K8sEvent, 1)}, &rawVerdictReceiver{received: make(chan utils.K8sEvent, 1)}
	exporter, err := NewVerdictExporter(ExporterOptions{Capacity: 1, Receivers: receiverMap(a, b)})
	if err != nil {
		t.Fatal(err)
	}
	if err = exporter.ReportVerdict(context.Background(), v); err != nil {
		t.Fatal(err)
	}
	v.PolicySet[0].Revision = "producer mutation"
	v.Matches[0].Name = "producer mutation"
	queued := <-exporter.queue
	exporter.dispatch(context.Background(), queued)
	first := (<-a.received).(*ExecVerdictEvent)
	second := (<-b.received).(*ExecVerdictEvent)
	first.Verdict.PolicySet[0].Revision = "receiver mutation"
	first.Verdict.Matches[0].Name = "receiver mutation"
	if second.Verdict.PolicySet[0].Revision != "revision" || second.Verdict.Matches[0].Name != "original" || queued.Verdict.Matches[0].Name != "original" || !second.Verdict.MatchesComplete {
		t.Fatal("provenance aliases producer/queue/receiver memory")
	}
}
