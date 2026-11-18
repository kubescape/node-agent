package sandboxpolicy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

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
	for i := range verdict.Matches {
		verdict.Matches[i].Origins = append([]string{}, verdict.Matches[i].Origins...)
	}
	verdict.Origins = append([]string{}, verdict.Origins...)
	verdict.Argv = append([]string(nil), verdict.Argv...)
	if verdict.UID != nil {
		value := *verdict.UID
		verdict.UID = &value
	}
	if verdict.FromImage != nil {
		value := *verdict.FromImage
		verdict.FromImage = &value
	}
	if verdict.Pass != nil {
		value := *verdict.Pass
		verdict.Pass = &value
	}
	if verdict.ExecID != nil {
		value := *verdict.ExecID
		verdict.ExecID = &value
	}
	if verdict.TaskCookie != nil {
		value := *verdict.TaskCookie
		verdict.TaskCookie = &value
	}
	if verdict.LoadEpoch != nil {
		value := *verdict.LoadEpoch
		verdict.LoadEpoch = &value
	}
	if verdict.ExecClass != nil {
		value := *verdict.ExecClass
		verdict.ExecClass = &value
	}
	if verdict.Scope != nil {
		value := *verdict.Scope
		verdict.Scope = &value
	}
	if verdict.Uncertain != nil {
		value := *verdict.Uncertain
		verdict.Uncertain = &value
	}
	if verdict.FactsUnknown != nil {
		value := *verdict.FactsUnknown
		verdict.FactsUnknown = &value
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
	Dropped          uint64 // full queue, stopped exporter, or still queued at the drain deadline
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
	stopRequested    bool            // under mu
	stopCh           chan struct{}   // closed by Stop
	drainCtx         context.Context // written before stopCh is closed
	claimed          chan struct{}   // closed once Run has claimed the start
	exited           chan struct{}   // closed when Run returns
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
	return &VerdictExporter{options: options, queue: make(chan *ExecVerdictEvent, options.Capacity), stopCh: make(chan struct{}), claimed: make(chan struct{}), exited: make(chan struct{})}, nil
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

// Run delivers queued verdicts until Stop or ctx cancellation, then drains:
// already-queued verdicts are still delivered until the drain deadline (Stop's
// ctx, or VerdictDrainTimeout after ctx cancellation). Only what is still
// queued at the deadline is counted as dropped. Run returns nil after Stop.
func (e *VerdictExporter) Run(ctx context.Context) error {
	if !e.started.CompareAndSwap(false, true) {
		return fmt.Errorf("verdict exporter Run may only be called once")
	}
	close(e.claimed)
	defer close(e.exited)
	// cancelled delivers the dequeued event, if any, and the rest of the queue
	// under one VerdictDrainTimeout budget rather than the cancelled ctx.
	cancelled := func(event *ExecVerdictEvent) error {
		drainCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), VerdictDrainTimeout)
		defer cancel()
		if event != nil {
			e.deliver(drainCtx, event)
		}
		e.drain(drainCtx)
		return ctx.Err()
	}
	for {
		select {
		case <-ctx.Done():
			return cancelled(nil)
		case <-e.stopCh:
			e.drain(e.drainCtx)
			return nil
		case event := <-e.queue:
			// select may pick a queued event over an already-cancelled ctx.
			if ctx.Err() != nil {
				return cancelled(event)
			}
			e.deliver(ctx, event)
		}
	}
}

// Started is closed once Run has claimed the start. A caller that launches Run
// on a goroutine waits on it so a later Stop drains rather than finding the
// exporter never started and dropping its queue.
func (e *VerdictExporter) Started() <-chan struct{} { return e.claimed }

// VerdictDrainTimeout bounds the drain after Run's ctx is cancelled (Stop
// bounds it by its own ctx instead).
const VerdictDrainTimeout = 2 * time.Second

// Stop refuses new verdicts at once, lets Run deliver those already queued
// until ctx ends, and waits for Run to return, at most until ctx ends. Whatever
// is still queued then is counted as dropped, also when Run is stuck in a
// receiver that never returns (that in-flight event is counted when, if ever,
// it returns). If Run never started, queued verdicts are counted as dropped at
// once. Stop is idempotent; the first call's ctx bounds Run's drain.
func (e *VerdictExporter) Stop(ctx context.Context) error {
	e.mu.Lock()
	e.stopped = true // queued verdicts are still delivered
	if !e.stopRequested {
		e.stopRequested = true
		e.drainCtx = ctx
		close(e.stopCh)
	}
	e.mu.Unlock()
	var err error
	if e.started.Load() {
		select {
		case <-e.exited:
			return nil
		case <-ctx.Done():
			// A drain that finished as ctx ended is still a clean stop.
			select {
			case <-e.exited:
				return nil
			default:
				err = ctx.Err()
			}
		}
	}
	// No Run delivers any more: count the queue. Each event is counted once,
	// by whichever of Stop or Run takes it.
	e.dropQueued()
	return err
}

// drain refuses new verdicts, then delivers queued ones until ctx ends; what is
// still queued then is counted as dropped.
func (e *VerdictExporter) drain(ctx context.Context) {
	e.mu.Lock()
	e.stopped = true // the queue only shrinks from here
	e.mu.Unlock()
	for ctx.Err() == nil {
		select {
		case event := <-e.queue:
			e.deliver(ctx, event)
		default:
			return
		}
	}
	e.dropQueued()
}

// dropQueued counts every still-queued verdict as dropped.
func (e *VerdictExporter) dropQueued() {
	for {
		select {
		case <-e.queue:
			e.dropped.Add(1)
		default:
			return
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
