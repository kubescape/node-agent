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
type FullBindingSource interface {
	Prepare(context.Context, sandboxpolicy.Binding) (FullBindingLease, error)
}

type fullRecord struct {
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
	b.mu.Lock()
	defer b.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	defer cancel()
	r := b.records[key(binding)]
	if b.closed || r == nil || r.instance == nil || r.retiring || r.protocolFault {
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
	b.mu.Lock()
	defer b.mu.Unlock()
	k := key(binding)
	timeout := b.operationTimeout
	if b.records[k] == nil {
		timeout = FullStartupTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	defer func() {
		r := b.records[k]
		if r != nil && r.instance != nil {
			if r.retiring {
				result.ProtectionUnconfirmed = true
				return
			}
			health := r.instance.Check(ctx)
			result.ProtectionUnconfirmed = result.ProtectionUnconfirmed || r.protocolFault || health != nil
			resultErr = errors.Join(resultErr, health)
		}
	}()
	if b.closed {
		return sandboxpolicy.ReplaceResult{ProtectionUnconfirmed: true}, fmt.Errorf("backend closed")
	}
	r := b.records[k]
	if r != nil && !r.retiring && !sameFullBindingMetadata(r.binding, binding) {
		return result, fmt.Errorf("binding metadata changed for persistent identity")
	}
	if r != nil && r.retiring {
		if err := b.stop(ctx, k, r); err != nil {
			return result, err
		}
		r = nil
	}
	for other := range b.records {
		if other != k && other.cgroup == k.cgroup {
			return result, fmt.Errorf("cgroup is still owned by another binding")
		}
	}
	if r != nil && r.pending != 0 && r.pendingRevision != plan.Revision && r.instance.Generation() != r.pending {
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
	if r != nil && r.pending != 0 {
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
	if r != nil && r.revision == plan.Revision {
		return sandboxpolicy.ReplaceResult{Committed: true, ActiveRevision: r.revision}, nil
	}
	if r == nil && len(b.records) >= FullBackendMaxBindings {
		return result, fmt.Errorf("full binding ownership capacity exceeded")
	}
	if b.sequence == math.MaxUint64 {
		return result, fmt.Errorf("full generation exhausted")
	}
	b.sequence++
	generation := b.sequence
	var epochs map[string]uint64
	if r != nil {
		epochs = r.instance.Epochs()
	}
	program, err := CompileFull(binding, plan, generation, epochs)
	if err != nil {
		return result, err
	}
	if r == nil {
		catalog := NewFullVerdictCatalog(binding)
		if err := catalog.Stage(generation, plan, program); err != nil {
			return result, err
		}
		lease, err := b.source.Prepare(ctx, binding)
		if err != nil || lease == nil {
			if lease != nil {
				r = &fullRecord{binding: sandboxpolicy.Binding{PodUID: binding.PodUID, Namespace: binding.Namespace, PodName: binding.PodName, ContainerName: binding.ContainerName, Kind: binding.Kind}, lease: lease, retiring: true}
				b.records[k] = r
				err = errors.Join(err, b.stop(ctx, k, r))
			}
			if lease == nil {
				err = errors.Join(err, fmt.Errorf("trusted source returned no binding lease"))
			}
			return result, err
		}
		r = &fullRecord{binding: sandboxpolicy.Binding{PodUID: binding.PodUID, Namespace: binding.Namespace, PodName: binding.PodName, ContainerName: binding.ContainerName, Kind: binding.Kind}, lease: lease, catalog: catalog, pending: generation, pendingRevision: plan.Revision}
		b.records[k] = r
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
func (b *FullBackend) stop(ctx context.Context, k identity, r *fullRecord) error {
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
	delete(b.records, k)
	return nil
}
func (b *FullBackend) Withdraw(ctx context.Context, binding sandboxpolicy.Binding) (sandboxpolicy.WithdrawResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := key(binding)
	r := b.records[k]
	if r == nil || !sameFullBindingMetadata(r.binding, binding) {
		return sandboxpolicy.WithdrawResult{Committed: true}, nil
	}
	r.retiring = true
	if err := b.stop(ctx, k, r); err != nil {
		return sandboxpolicy.WithdrawResult{Committed: r.instance != nil && r.instance.Detached(), ProtectionUnconfirmed: true}, err
	}
	return sandboxpolicy.WithdrawResult{Committed: true}, nil
}
func (b *FullBackend) Close(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	var errs []error
	for k, r := range b.records {
		r.retiring = true
		errs = append(errs, b.stop(ctx, k, r))
	}
	return errors.Join(errs...)
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
	b.retiredInstances++
	counters, err := instanceKernelCounters(instance)
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
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return KernelEventStats{}, err
	}
	result := KernelEventStats{Retired: b.retiredCounters, RetiredInstances: b.retiredInstances, RetiredUnavailable: b.retiredUnavailable}
	var errs []error
	if result.RetiredUnavailable != 0 {
		errs = append(errs, fmt.Errorf("kernel counters unavailable for %d retired instances", result.RetiredUnavailable))
	}
	for _, record := range b.records {
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
