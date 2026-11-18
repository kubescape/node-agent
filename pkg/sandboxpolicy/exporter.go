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
	drainErr         error           // under mu: first deadline error that lost a verdict
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
// queued at the deadline is counted as dropped. Run returns nil after Stop;
// Stop reports whether the drain lost verdicts.
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
		e.drain(drainCtx, event)
		return ctx.Err()
	}
	for {
		select {
		case <-ctx.Done():
			return cancelled(nil)
		case <-e.stopCh:
			e.drain(e.drainCtx, nil)
			return nil
		case event := <-e.queue:
			// select may pick a queued event over an already-cancelled ctx or
			// a requested stop: deliver it within that drain's deadline.
			if ctx.Err() != nil {
				return cancelled(event)
			}
			select {
			case <-e.stopCh:
				e.drain(e.drainCtx, event)
				return nil
			default:
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
// until ctx ends, and waits for Run to return, at most until ctx ends. It
// returns nil only for a clean drain, and the deadline error when verdicts were
// lost to it or when Run is still delivering at the deadline (concurrent Stop
// callers may briefly observe different outcomes). At the first Stop's deadline whatever is still queued is counted
// as dropped, also when Run is stuck in a receiver that never returns (that
// in-flight event is counted when, if ever, it returns). If Run never started,
// queued verdicts are counted as dropped at once. Stop is idempotent; only the
// first call's ctx bounds Run's drain, and a later call only waits.
func (e *VerdictExporter) Stop(ctx context.Context) error {
	e.mu.Lock()
	e.stopped = true // queued verdicts are still delivered
	first := !e.stopRequested
	if first {
		e.stopRequested = true
		e.drainCtx = ctx
		close(e.stopCh)
	}
	e.mu.Unlock()
	if !e.started.Load() {
		// No Run delivers: count the queue. Each event is counted once, by
		// whichever of Stop or a late Run takes it.
		e.dropQueued()
		return nil
	}
	select {
	case <-e.exited:
		return e.drainLoss()
	case <-ctx.Done():
		// A drain that finished as ctx ended still reports its own outcome.
		select {
		case <-e.exited:
			return e.drainLoss()
		default:
		}
	}
	if first {
		// The drain deadline passed with Run still busy (a receiver that has
		// not returned): count the queue. A later Stop must not shorten the
		// first one's drain, so it only returns its own ctx error.
		if e.dropQueued() > 0 {
			e.recordDrainLoss(ctx.Err())
		}
	}
	return ctx.Err()
}

// recordDrainLoss keeps the first deadline error that lost a verdict, whether
// Run's drain or Stop's deadline counted it.
func (e *VerdictExporter) recordDrainLoss(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.drainErr == nil {
		e.drainErr = err
	}
}
func (e *VerdictExporter) drainLoss() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.drainErr
}

// drain refuses new verdicts, then delivers first (if any) and the queued ones
// until ctx ends; what is still queued then is counted as dropped. A deadline
// that lost any verdict is recorded for Stop.
func (e *VerdictExporter) drain(ctx context.Context, first *ExecVerdictEvent) {
	e.mu.Lock()
	e.stopped = true // the queue only shrinks from here
	e.mu.Unlock()
	lost := first != nil && e.deliver(ctx, first)
loop:
	for ctx.Err() == nil {
		select {
		case event := <-e.queue:
			lost = e.deliver(ctx, event) || lost
		default:
			break loop
		}
	}
	if e.dropQueued() > 0 {
		lost = true
	}
	if lost {
		e.recordDrainLoss(ctx.Err())
	}
}

// dropQueued counts every still-queued verdict as dropped and returns how many.
func (e *VerdictExporter) dropQueued() (n uint64) {
	for {
		select {
		case <-e.queue:
			e.dropped.Add(1)
			n++
		default:
			return n
		}
	}
}

// deliver reports whether ctx's end lost the event (pending enrichment).
func (e *VerdictExporter) deliver(ctx context.Context, event *ExecVerdictEvent) (lost bool) {
	if e.options.Enricher == nil {
		e.dispatch(ctx, event)
		return false
	}
	done := make(chan struct{})
	var once sync.Once // lost is written only inside once.Do: read after it
	callback := func(_ utils.K8sEvent, _ string, _ uint32) {
		once.Do(func() {
			defer close(done)
			if ctx.Err() != nil {
				e.dropped.Add(1)
				lost = true
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
		once.Do(func() { e.dropped.Add(1); lost = true; close(done) })
	}
	return lost
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
