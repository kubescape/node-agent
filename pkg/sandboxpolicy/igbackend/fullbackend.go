package igbackend

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	execruntime "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// FullBindingLease is authenticated runtime evidence, never policy input. Origins
// must describe the same pinned image root for the entire owner lifetime.
// Close consumes all owned resources even on OS close errors; repeated Close is
// harmless. This matches the native Owner.ReleaseAfterDetach contract.
type FullBindingLease interface {
	fullruntime.BindingLease
	ImageOrigins() *execruntime.ImageOriginSnapshot
}

// FullBindingSource transfers an owned lease, including any nonnil lease returned
// alongside an error. The backend retains it until cleanup is confirmed.
// Prepare may run concurrently for distinct bindings.
type FullBindingSource interface {
	Prepare(context.Context, sandboxpolicy.Binding) (FullBindingLease, error)
}

type fullRecord struct {
	// mu serializes native operations. Never wait for it while holding b.mu.
	mu sync.Mutex
	// cancel, draining and drainSequence are protected by b.mu; binding is immutable.
	cancel                    context.CancelFunc
	draining                  bool
	drainSequence             uint64
	binding                   sandboxpolicy.Binding
	instance                  FullInstance
	lease                     FullBindingLease // only until the engine's Acquire transfers it
	catalog                   *FullVerdictCatalog
	revision, pendingRevision string
	pending                   uint64
	retiring                  bool
	protocolFault             bool
}

// FullBackendMaxBindings includes owners awaiting cleanup.
const FullBackendMaxBindings = 1024

// Bound whole-exec drain/re-attestation even when the service lifetime context
// has no deadline. First admission may need a longer bounded image walk/load.
const FullOperationTimeout = 5 * time.Second
const FullStartupTimeout = 2 * time.Minute

// FullBackend publishes into one persistent native owner per exact binding.
// Native engine and trusted lease source are explicit: there is no legacy fallback.
type FullBackend struct {
	retiredCounters    KernelEventTotals
	retiredInstances   uint64
	retiredUnavailable uint64
	mu                 sync.Mutex
	closeMu            sync.Mutex
	engineClosed       bool
	engine             FullEngine
	source             FullBindingSource
	receiver           sandboxpolicy.VerdictReceiver
	onError            func(error)
	records            map[identity]*fullRecord
	sequence           uint64
	closed             bool
	operationTimeout   time.Duration
}

var _ sandboxpolicy.Backend = (*FullBackend)(nil)
var _ sandboxpolicy.ProtectionAttester = (*FullBackend)(nil)

func NewFull(engine FullEngine, source FullBindingSource, receiver sandboxpolicy.VerdictReceiver, onError func(error)) (*FullBackend, error) {
	if engine == nil || source == nil {
		return nil, fmt.Errorf("full engine and trusted binding source required")
	}
	return &FullBackend{engine: engine, source: source, receiver: receiver, onError: onError, records: map[identity]*fullRecord{}, operationTimeout: FullOperationTimeout}, nil
}

// Attest observes only the exact committed owner; it never resumes a pending
// publication, including an uncommitted candidate from a previously failed reload.
func (b *FullBackend) Attest(ctx context.Context, binding sandboxpolicy.Binding, revision string) error {
	ctx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	defer cancel()
	r, _, err := b.lockRecord(ctx, binding, false)
	if err != nil {
		return err
	}
	if r == nil {
		return fmt.Errorf("binding has no attestable enforcement owner")
	}
	defer b.unlockRecord(key(binding), r)
	if r.instance == nil || r.retiring || r.protocolFault {
		return fmt.Errorf("binding has no attestable enforcement owner")
	}
	if !sameFullBindingMetadata(r.binding, binding) || revision == "" || r.revision != revision {
		return fmt.Errorf("binding or active revision does not match attestation")
	}
	if r.pending != 0 || r.instance.PendingGeneration() != 0 {
		return fmt.Errorf("pending publication prevents read-only protection attestation")
	}
	return r.instance.Check(ctx)
}

func (b *FullBackend) Replace(ctx context.Context, binding sandboxpolicy.Binding, plan sandboxpolicy.Plan) (result sandboxpolicy.ReplaceResult, resultErr error) {
	k := key(binding)
	// The startup bound also bounds queueing; established owners get the shorter
	// native-operation bound after acquiring their own record.
	ctx, cancel := context.WithTimeout(ctx, FullStartupTimeout)
	defer cancel()
	r, drainSequence, err := b.lockRecord(ctx, binding, true)
	if err != nil {
		return sandboxpolicy.ReplaceResult{ProtectionUnconfirmed: true}, err
	}
	defer func() { b.unlockRecord(k, r) }()
	if r.instance != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, b.operationTimeout)
		defer cancel()
	}
	ctx, cancelOperation := context.WithCancel(ctx)
	b.mu.Lock()
	if b.closed || b.records[k] != r || r.drainSequence != drainSequence {
		b.mu.Unlock()
		cancelOperation()
		return sandboxpolicy.ReplaceResult{ProtectionUnconfirmed: true}, fmt.Errorf("binding is draining")
	}
	r.cancel = cancelOperation
	draining := r.draining
	b.mu.Unlock()
	defer cancelOperation()
	defer func() {
		if r.instance != nil {
			if r.retiring {
				result.ProtectionUnconfirmed = true
				return
			}
			health := r.instance.Check(ctx)
			result.ProtectionUnconfirmed = result.ProtectionUnconfirmed || r.protocolFault || health != nil
			resultErr = errors.Join(resultErr, health)
		}
	}()
	if !sameFullBindingMetadata(r.binding, binding) {
		return result, fmt.Errorf("binding metadata changed for persistent identity")
	}
	if r.retiring || draining {
		r.retiring = true
		if err := b.stop(ctx, k, r); err != nil {
			return result, err
		}
		// Successful retirement is a new ownership lifetime, not a reopening of
		// the old record. Both queued Replace and Withdraw calls retain the old
		// pointer and must fail revalidation rather than touch the replacement.
		b.mu.Lock()
		if b.closed || b.records[k] != r || r.drainSequence != drainSequence || ctx.Err() != nil {
			b.mu.Unlock()
			return sandboxpolicy.ReplaceResult{ProtectionUnconfirmed: true}, errors.Join(fmt.Errorf("binding ownership changed during retirement"), ctx.Err())
		}
		next := &fullRecord{binding: r.binding, cancel: cancelOperation}
		next.mu.Lock()
		b.records[k] = next
		r.cancel = nil
		b.mu.Unlock()
		r.mu.Unlock()
		r = next
	}
	if r.pending != 0 && r.pendingRevision != plan.Revision && r.instance.Generation() != r.pending {
		// An uncommitted candidate is not authority to publish a now-superseded
		// revision. Abort its staging before considering the current request.
		aborter, ok := r.instance.(FullPendingAborter)
		if !ok {
			return sandboxpolicy.ReplaceResult{ProtectionUnconfirmed: true}, fmt.Errorf("superseded pending publication cannot be safely aborted")
		}
		if err := aborter.AbortPending(ctx); err != nil {
			return sandboxpolicy.ReplaceResult{ProtectionUnconfirmed: true}, err
		}
		if r.instance.PendingGeneration() != 0 {
			return sandboxpolicy.ReplaceResult{ProtectionUnconfirmed: true}, fmt.Errorf("superseded publication remains pending after abort")
		}
		if err := r.catalog.Abort(r.pending); err != nil {
			r.protocolFault = true
			return sandboxpolicy.ReplaceResult{ProtectionUnconfirmed: true}, err
		}
		r.pending = 0
		r.pendingRevision = ""
	}
	if r.pending != 0 {
		publication, err := r.instance.Resume(ctx)
		if e := b.publication(r, publication); e != nil {
			err = errors.Join(err, e)
		}
		if r.revision == plan.Revision {
			result.Committed = true
			result.ActiveRevision = r.revision
		}
		if err != nil || r.pending != 0 {
			return result, errors.Join(err, pendingError(r))
		}
	}
	if r.instance != nil && r.revision == plan.Revision {
		return sandboxpolicy.ReplaceResult{Committed: true, ActiveRevision: r.revision}, nil
	}
	b.mu.Lock()
	if b.sequence == math.MaxUint64 {
		b.mu.Unlock()
		return result, fmt.Errorf("full generation exhausted")
	}
	b.sequence++
	generation := b.sequence
	b.mu.Unlock()
	var epochs map[string]uint64
	if r.instance != nil {
		epochs = r.instance.Epochs()
	}
	program, err := CompileFull(binding, plan, generation, epochs)
	if err != nil {
		return result, err
	}
	if r.instance == nil {
		catalog := NewFullVerdictCatalog(binding)
		if err := catalog.Stage(generation, plan, program); err != nil {
			return result, err
		}
		var lease FullBindingLease
		lease, err = b.source.Prepare(ctx, binding)
		if err != nil || lease == nil {
			if lease != nil {
				r.lease, r.retiring = lease, true
				err = errors.Join(err, b.stop(ctx, k, r))
			}
			if lease == nil {
				err = errors.Join(err, fmt.Errorf("trusted source returned no binding lease"))
			}
			return result, err
		}
		r.lease, r.catalog, r.pending, r.pendingRevision = lease, catalog, generation, plan.Revision
		// Acquisition is synchronous during Start. Ownership transfers exactly once;
		// a failure before Acquire leaves the lease here for ordered cleanup.
		acquire := func(ctx context.Context) (fullruntime.BindingLease, error) {
			if r.lease == nil {
				return nil, fmt.Errorf("binding lease already transferred")
			}
			owned := r.lease
			r.lease = nil
			return owned, nil
		}
		origins := lease.ImageOrigins()
		r.instance, err = b.engine.Start(ctx, fmt.Sprintf("sandbox-full-%d-%d", binding.CgroupID, generation), FullStartConfig{Binding: binding, Program: program, Acquire: acquire, ImageOrigins: origins}, func(raw RawFullVerdict) {
			verdict, e := catalog.Decode(raw)
			if e == nil && b.receiver != nil {
				e = b.receiver.ReportVerdict(context.Background(), verdict)
			}
			if e != nil && b.onError != nil {
				b.onError(e)
			}
		})
		if err != nil || r.instance == nil {
			r.retiring = true
			if err == nil {
				err = fmt.Errorf("full engine returned no instance")
			}
			return result, errors.Join(err, b.stop(ctx, k, r))
		}
		publication, e := r.instance.Activate(ctx)
		err = errors.Join(e, b.publication(r, publication))
	} else {
		if err = r.catalog.Stage(generation, plan, program); err != nil {
			return result, err
		}
		r.pending = generation
		r.pendingRevision = plan.Revision
		publication, e := r.instance.Update(ctx, program)
		err = errors.Join(e, b.publication(r, publication))
	}
	if r.revision == plan.Revision {
		result.Committed = true
		result.ActiveRevision = r.revision
	}
	if r.revision == "" && r.pending == 0 {
		r.retiring = true
		err = errors.Join(err, b.stop(ctx, k, r))
	}
	return result, errors.Join(err, pendingError(r))
}

func pendingError(r *fullRecord) error {
	if r.pending != 0 {
		return fmt.Errorf("full publication %d requires finalization", r.pending)
	}
	return nil
}
func (b *FullBackend) publication(r *fullRecord, p fullruntime.PublicationResult) (err error) {
	defer func() {
		if err != nil {
			r.protocolFault = true
		}
	}()
	if p.Committed {
		if p.Generation != r.pending || r.instance.Generation() != r.pending {
			return fmt.Errorf("native publication generation mismatch")
		}
		if err := r.catalog.Commit(r.pending); err != nil {
			return err
		}
		r.revision = r.pendingRevision
	}
	if r.instance.PendingGeneration() == 0 {
		if !p.Committed {
			if err := r.catalog.Abort(r.pending); err != nil {
				return err
			}
		}
		r.pending = 0
		r.pendingRevision = ""
	} else if r.instance.PendingGeneration() != r.pending {
		return fmt.Errorf("native pending generation mismatch")
	}
	return nil
}
func (b *FullBackend) stop(ctx context.Context, _ identity, r *fullRecord) error {
	ctx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	defer cancel()
	if r.instance != nil {
		if err := r.instance.Stop(ctx); err != nil {
			return err
		}
		b.retainKernelCounters(r.instance)
		r.instance = nil
	}
	if r.lease != nil {
		if err := r.lease.Close(); err != nil {
			return err
		}
		r.lease = nil
	}
	return nil
}

// lockFullMutex permits canceled waiters to leave without spawning lock goroutines.
func lockFullMutex(ctx context.Context, mu *sync.Mutex) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if mu.TryLock() {
		return nil
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		if mu.TryLock() {
			return nil
		}
	}
}

// lockRecord snapshots the drain sequence before waiting. Only a fresh Replace
// may reconcile a draining record; pre-drain waiters and Attest cannot reopen it.
func (b *FullBackend) lockRecord(ctx context.Context, binding sandboxpolicy.Binding, create bool) (*fullRecord, uint64, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	k := key(binding)
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, 0, fmt.Errorf("backend closed")
	}
	r := b.records[k]
	if r == nil && create {
		if len(b.records) >= FullBackendMaxBindings {
			b.mu.Unlock()
			return nil, 0, fmt.Errorf("full binding ownership capacity exceeded")
		}
		for other := range b.records {
			if other != k && other.cgroup == k.cgroup {
				b.mu.Unlock()
				return nil, 0, fmt.Errorf("cgroup is still owned by another binding")
			}
		}
		r = &fullRecord{binding: sandboxpolicy.Binding{PodUID: binding.PodUID, Namespace: binding.Namespace, PodName: binding.PodName, ContainerName: binding.ContainerName, Kind: binding.Kind}}
		// Lock before publishing the reservation, so no waiter can overtake its creator.
		r.mu.Lock()
		b.records[k] = r
		b.mu.Unlock()
		return r, 0, nil
	}
	var drainSequence uint64
	if r != nil {
		drainSequence = r.drainSequence
	}
	b.mu.Unlock()
	if r == nil {
		return nil, 0, nil
	}
	if err := lockFullMutex(ctx, &r.mu); err != nil {
		return nil, 0, err
	}
	b.mu.Lock()
	valid := !b.closed && b.records[k] == r && r.drainSequence == drainSequence && (create || !r.draining)
	b.mu.Unlock()
	if !valid {
		r.mu.Unlock()
		return nil, 0, fmt.Errorf("binding ownership changed or is draining")
	}
	return r, drainSequence, nil
}

// Drop an empty reservation only after native cleanup; stale waiters retain the
// old pointer and cannot operate on or delete a newly admitted identity.
func (b *FullBackend) unlockRecord(k identity, r *fullRecord) {
	b.mu.Lock()
	r.cancel = nil
	if b.records[k] == r && r.instance == nil && r.lease == nil {
		delete(b.records, k)
	}
	b.mu.Unlock()
	r.mu.Unlock()
}

func (b *FullBackend) Withdraw(ctx context.Context, binding sandboxpolicy.Binding) (sandboxpolicy.WithdrawResult, error) {
	ctx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	defer cancel()
	k := key(binding)
	b.mu.Lock()
	r := b.records[k]
	if r == nil || !sameFullBindingMetadata(r.binding, binding) {
		b.mu.Unlock()
		return sandboxpolicy.WithdrawResult{Committed: true}, nil
	}
	if r.drainSequence == math.MaxUint64 {
		b.mu.Unlock()
		return sandboxpolicy.WithdrawResult{ProtectionUnconfirmed: true}, fmt.Errorf("binding withdrawal sequence exhausted")
	}
	r.drainSequence++
	r.draining = true
	if r.cancel != nil {
		r.cancel()
	}
	b.mu.Unlock()
	if err := lockFullMutex(ctx, &r.mu); err != nil {
		return sandboxpolicy.WithdrawResult{ProtectionUnconfirmed: true}, err
	}
	defer b.unlockRecord(k, r)
	b.mu.Lock()
	current := b.records[k] == r
	b.mu.Unlock()
	if !current {
		return sandboxpolicy.WithdrawResult{Committed: true}, nil
	}
	r.retiring = true
	if err := b.stop(ctx, k, r); err != nil {
		return sandboxpolicy.WithdrawResult{Committed: r.instance != nil && r.instance.Detached(), ProtectionUnconfirmed: true}, err
	}
	return sandboxpolicy.WithdrawResult{Committed: true}, nil
}

func (b *FullBackend) Close(ctx context.Context) error {
	if err := lockFullMutex(ctx, &b.closeMu); err != nil {
		return err
	}
	defer b.closeMu.Unlock()
	b.mu.Lock()
	b.closed = true
	records := make(map[identity]*fullRecord, len(b.records))
	for k, r := range b.records {
		records[k] = r
		r.draining = true
		if r.cancel != nil {
			r.cancel()
		}
	}
	b.mu.Unlock()
	var errs []error
	for k, r := range records {
		if err := lockFullMutex(ctx, &r.mu); err != nil {
			errs = append(errs, err)
			continue
		}
		r.retiring = true
		errs = append(errs, b.stop(ctx, k, r))
		b.unlockRecord(k, r)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if !b.engineClosed {
		if closer, ok := b.engine.(FullEngineCloser); ok {
			if err := closer.Close(ctx); err != nil {
				return err
			}
		}
		b.engineClosed = true
	}
	return nil
}

func addKernelCounters(total *KernelEventTotals, counters fullruntime.KernelEventCounters) {
	total.Submitted += counters.Submitted
	total.Lost += counters.Lost
	total.ObservationErrors += counters.ObservationErrors
}

func instanceKernelCounters(instance FullInstance) (fullruntime.KernelEventCounters, error) {
	source, ok := instance.(FullKernelCounterSource)
	if !ok {
		return fullruntime.KernelEventCounters{}, fmt.Errorf("instance kernel counters unavailable")
	}
	return source.KernelEventCounters()
}

// Called exactly once before dropping an instance. Never accept a live sample
// as a final lifetime total, and never let telemetry errors block withdrawal.
func (b *FullBackend) retainKernelCounters(instance FullInstance) {
	counters, err := instanceKernelCounters(instance)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.retiredInstances++
	if err != nil || !counters.Final {
		b.retiredUnavailable++
	}
	addKernelCounters(&b.retiredCounters, counters)
}

// KernelEventStats reads telemetry only; it does not check/repair enforcement.
// Errors describe incomplete totals, never successful zero-loss observations.
func (b *FullBackend) KernelEventStats(ctx context.Context) (KernelEventStats, error) {
	if err := ctx.Err(); err != nil {
		return KernelEventStats{}, err
	}
	// Acquire a consistent registry/retirement snapshot without waiting for any
	// record while holding the registry lock (record operations take reverse order).
	var records []*fullRecord
	var result KernelEventStats
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if err := lockFullMutex(ctx, &b.mu); err != nil {
			return KernelEventStats{}, err
		}
		complete := true
		for _, r := range b.records {
			if !r.mu.TryLock() {
				complete = false
				break
			}
			records = append(records, r)
		}
		if complete {
			result = KernelEventStats{Retired: b.retiredCounters, RetiredInstances: b.retiredInstances, RetiredUnavailable: b.retiredUnavailable}
			b.mu.Unlock()
			break
		}
		for _, r := range records {
			r.mu.Unlock()
		}
		records = nil
		b.mu.Unlock()
		select {
		case <-ctx.Done():
			return KernelEventStats{}, ctx.Err()
		case <-ticker.C:
		}
	}
	defer func() {
		for _, r := range records {
			r.mu.Unlock()
		}
	}()
	var errs []error
	if result.RetiredUnavailable != 0 {
		errs = append(errs, fmt.Errorf("kernel counters unavailable for %d retired instances", result.RetiredUnavailable))
	}
	for _, record := range records {
		if record.instance == nil {
			continue
		}
		result.OwnedInstances++
		if err := ctx.Err(); err != nil {
			return KernelEventStats{}, err
		}
		counters, err := instanceKernelCounters(record.instance)
		addKernelCounters(&result.Owned, counters)
		if err != nil {
			result.OwnedUnavailable++
			errs = append(errs, err)
			continue
		}
	}
	return result, errors.Join(errs...)
}

func sameFullBindingMetadata(a, b sandboxpolicy.Binding) bool {
	return a.PodUID == b.PodUID && a.Namespace == b.Namespace && a.PodName == b.PodName && a.ContainerName == b.ContainerName && a.Kind == b.Kind
}
