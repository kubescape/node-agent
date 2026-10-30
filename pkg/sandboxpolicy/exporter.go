package sandboxpolicy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	gadgettypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
)

// ExecVerdictEvent is an exec authorization attempt, NOT an observed process creation.
// It deliberately does not implement utils.ExecEvent. The raw Verdict retains
// policy/rule provenance and audit/deny semantics even after optional enrichment.
// Unknown enrichment fields are absent (FieldPresent=false), not fabricated from
// the target executable. In particular GetError's zero means unavailable, not a
// successful exec syscall: this event describes an LSM decision, not syscall exit.
// Keep this event exec-specific. When a second enforce gadget is added, give its
// operation facts a distinct event and dispatch key; extract only metadata proven
// common to both. See docs/features/sandbox-policy.md#adding-a-second-enforcement-gadget.
type ExecVerdictEvent struct {
	Verdict Verdict
	Binding Binding
	extra   any
}

var _ utils.EnrichEvent = (*ExecVerdictEvent)(nil)

func NewExecVerdictEvent(verdict Verdict, binding Binding) *ExecVerdictEvent {
	verdict.PolicySet = append([]PolicyRevision(nil), verdict.PolicySet...)
	verdict.Matches = append([]RuleMatch(nil), verdict.Matches...)
	verdict.Argv = append([]string(nil), verdict.Argv...)
	if verdict.UID != nil {
		value := *verdict.UID
		verdict.UID = &value
	}
	if verdict.FromImage != nil {
		value := *verdict.FromImage
		verdict.FromImage = &value
	}
	binding.PodLabels = cloneLabels(binding.PodLabels)
	binding.NamespaceLabels = cloneLabels(binding.NamespaceLabels)
	return &ExecVerdictEvent{Verdict: verdict, Binding: binding}
}
func (e *ExecVerdictEvent) GetContainerID() string      { return e.Verdict.ContainerID }
func (*ExecVerdictEvent) GetEventType() utils.EventType { return utils.ExecAuthorizationEventType }
func (e *ExecVerdictEvent) GetNamespace() string        { return e.Binding.Namespace }
func (e *ExecVerdictEvent) GetPod() string              { return e.Binding.PodName }
func (e *ExecVerdictEvent) GetTimestamp() gadgettypes.Time {
	if e.Verdict.Time.IsZero() {
		return 0
	}
	return gadgettypes.Time(e.Verdict.Time.UnixNano())
}
func (*ExecVerdictEvent) HasDroppedEvents() bool            { return false } // loss is exposed by ExporterStats, never invented per record
func (*ExecVerdictEvent) Release()                          {}
func (*ExecVerdictEvent) GetComm() string                   { return "" }
func (e *ExecVerdictEvent) GetContainer() string            { return e.Binding.ContainerName }
func (*ExecVerdictEvent) GetContainerImage() string         { return "" }
func (*ExecVerdictEvent) GetContainerImageDigest() string   { return "" }
func (*ExecVerdictEvent) GetError() int64                   { return 0 }
func (e *ExecVerdictEvent) GetExtra() any                   { return e.extra }
func (e *ExecVerdictEvent) SetExtra(extra any)              { e.extra = extra }
func (*ExecVerdictEvent) GetGid() *uint32                   { return nil }
func (*ExecVerdictEvent) GetHostNetwork() bool              { return false }
func (e *ExecVerdictEvent) GetMountNsID() uint64            { return e.Binding.MountNamespace }
func (*ExecVerdictEvent) GetPcomm() string                  { return "" }
func (e *ExecVerdictEvent) GetPID() uint32                  { return e.Verdict.PID }
func (e *ExecVerdictEvent) GetPID64() uint64                { return uint64(e.Verdict.PID) }
func (e *ExecVerdictEvent) GetPodLabels() map[string]string { return cloneLabels(e.Binding.PodLabels) }
func (e *ExecVerdictEvent) GetPpid() uint32                 { return e.Verdict.ParentPID }
func (e *ExecVerdictEvent) GetUid() *uint32 {
	if e.Verdict.UID == nil {
		return nil
	}
	value := *e.Verdict.UID
	return &value
}
func (*ExecVerdictEvent) GetEcsClusterName() string       { return "" }
func (*ExecVerdictEvent) GetEcsClusterARN() string        { return "" }
func (*ExecVerdictEvent) GetEcsTaskARN() string           { return "" }
func (*ExecVerdictEvent) GetEcsTaskFamily() string        { return "" }
func (*ExecVerdictEvent) GetEcsTaskDefinitionARN() string { return "" }
func (*ExecVerdictEvent) GetEcsServiceName() string       { return "" }
func (*ExecVerdictEvent) GetEcsContainerName() string     { return "" }
func (*ExecVerdictEvent) GetEcsContainerARN() string      { return "" }
func (*ExecVerdictEvent) GetEcsContainerInstance() string { return "" }
func (*ExecVerdictEvent) GetEcsAvailabilityZone() string  { return "" }
func (*ExecVerdictEvent) GetEcsLaunchType() string        { return "" }
func (e *ExecVerdictEvent) FieldPresent(name string) bool {
	switch name {
	case "timestamp":
		return !e.Verdict.Time.IsZero()
	case "pid":
		return e.Verdict.PID != 0
	case "ppid":
		return e.Verdict.ParentPID != 0
	case "uid":
		return e.Verdict.UID != nil
	case "mntns_id":
		return e.Binding.MountNamespace != 0
	default:
		return false
	}
}

const MaxVerdictQueueCapacity = 65536

var ErrVerdictQueueFull = errors.New("sandbox verdict reporting queue is full")
var ErrVerdictExporterStopped = errors.New("sandbox verdict exporter is stopped")

type ExporterOptions struct {
	Capacity  int
	Receivers *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]
	Enricher  containerwatcher.TaskBasedEnricher
	// ResolveBinding must be a nonblocking cache lookup. Only return identities
	// verified for this event's full container ID and cgroup ID, never a current
	// container reusing the same short ID. A missing result leaves metadata absent.
	ResolveBinding func(Verdict) (Binding, bool)
}

type ExporterStats struct {
	Enqueued         uint64
	Delivered        uint64 // successful receiver invocations, not kernel decisions
	Dropped          uint64 // full queue, cancellation or stopped exporter
	ReceiverErrors   uint64
	EnrichmentErrors uint64
}

// VerdictExporter separates bounded, best-effort telemetry from kernel decisions.
// ReportVerdict never calls receivers/enrichers and never changes enforcement.
// Start exactly one Run goroutine; register receivers under the distinct verdict
// event type, not ExecveEventType. Void receiver/enricher APIs cannot be cancelled
// mid-call, so implementations must return promptly; a slow consumer fills this
// queue and drops telemetry rather than blocking the enforcement producer.
type VerdictExporter struct {
	options          ExporterOptions
	queue            chan *ExecVerdictEvent
	mu               sync.Mutex
	stopped          bool
	started          atomic.Bool
	enqueued         atomic.Uint64
	delivered        atomic.Uint64
	dropped          atomic.Uint64
	receiverErrors   atomic.Uint64
	enrichmentErrors atomic.Uint64
}

var _ VerdictReceiver = (*VerdictExporter)(nil)

func NewVerdictExporter(options ExporterOptions) (*VerdictExporter, error) {
	if options.Capacity <= 0 || options.Capacity > MaxVerdictQueueCapacity {
		return nil, fmt.Errorf("verdict queue capacity must be between 1 and %d", MaxVerdictQueueCapacity)
	}
	return &VerdictExporter{options: options, queue: make(chan *ExecVerdictEvent, options.Capacity)}, nil
}
func (e *VerdictExporter) ReportVerdict(ctx context.Context, verdict Verdict) error {
	binding := Binding{}
	if e.options.ResolveBinding != nil {
		resolved, ok := e.options.ResolveBinding(verdict)
		if ok && resolved.ContainerID == verdict.ContainerID && resolved.CgroupID == verdict.CgroupID {
			binding = resolved
		}
	}
	event := NewExecVerdictEvent(verdict, binding)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		e.dropped.Add(1)
		return ErrVerdictExporterStopped
	}
	if err := ctx.Err(); err != nil {
		e.dropped.Add(1)
		return err
	}
	select {
	case e.queue <- event:
		e.enqueued.Add(1)
		return nil
	default:
		e.dropped.Add(1)
		return ErrVerdictQueueFull
	}
}
func (e *VerdictExporter) Stats() ExporterStats {
	return ExporterStats{e.enqueued.Load(), e.delivered.Load(), e.dropped.Load(), e.receiverErrors.Load(), e.enrichmentErrors.Load()}
}
func (e *VerdictExporter) Run(ctx context.Context) error {
	if !e.started.CompareAndSwap(false, true) {
		return fmt.Errorf("verdict exporter Run may only be called once")
	}
	defer func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.stopped = true
		for {
			select {
			case <-e.queue:
				e.dropped.Add(1)
			default:
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event := <-e.queue:
			if err := ctx.Err(); err != nil {
				e.dropped.Add(1)
				return err
			}
			e.deliver(ctx, event)
		}
	}
}
func (e *VerdictExporter) deliver(ctx context.Context, event *ExecVerdictEvent) {
	if e.options.Enricher == nil {
		e.dispatch(ctx, event)
		return
	}
	done := make(chan struct{})
	var once sync.Once
	callback := func(_ utils.K8sEvent, _ string, _ uint32) {
		once.Do(func() {
			defer close(done)
			if ctx.Err() != nil {
				e.dropped.Add(1)
				return
			}
			e.dispatch(ctx, event)
		})
	}
	// No SYS_FORK hint: an allowed/audited attempt is not evidence of process
	// creation. Enrichment may attach extra context but cannot replace the verdict.
	if err := guardReceiver(func() error {
		e.options.Enricher.SubmitEnrichmentTask(event, nil, callback, event.GetContainerID(), event.GetPID())
		return nil
	}); err != nil {
		e.enrichmentErrors.Add(1)
		callback(event, event.GetContainerID(), event.GetPID())
	}
	select {
	case <-done:
	case <-ctx.Done():
		once.Do(func() { e.dropped.Add(1); close(done) })
	}
}
func (e *VerdictExporter) dispatch(ctx context.Context, event *ExecVerdictEvent) {
	if e.options.Receivers == nil {
		e.dropped.Add(1)
		return
	}
	receivers, ok := e.options.Receivers.Load(utils.ExecAuthorizationEventType)
	if !ok || receivers.Cardinality() == 0 {
		e.dropped.Add(1)
		return
	}
	for _, receiver := range receivers.ToSlice() {
		copy := NewExecVerdictEvent(event.Verdict, event.Binding)
		copy.extra = event.extra
		err := guardReceiver(func() error {
			if enriched, ok := receiver.(containerwatcher.EnrichedEventReceiver); ok {
				// No process tree is fabricated and no process manager mutation occurs.
				enriched.ReportEnrichedEvent(&events.EnrichedEvent{Event: copy, Timestamp: copy.Verdict.Time, ContainerID: copy.Verdict.ContainerID, PID: copy.Verdict.PID, PPID: copy.Verdict.ParentPID, MountNamespaceID: copy.Binding.MountNamespace})
				return nil
			}
			if raw, ok := receiver.(containerwatcher.EventReceiver); ok {
				raw.ReportEvent(utils.ExecAuthorizationEventType, copy)
				return nil
			}
			if verdict, ok := receiver.(VerdictReceiver); ok {
				return verdict.ReportVerdict(ctx, copy.Verdict)
			}
			return fmt.Errorf("unsupported sandbox verdict receiver %T", receiver)
		})
		if err != nil {
			e.receiverErrors.Add(1)
		} else {
			e.delivered.Add(1)
		}
	}
}
func guardReceiver(call func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("verdict receiver panic: %v", recovered)
		}
	}()
	return call()
}
