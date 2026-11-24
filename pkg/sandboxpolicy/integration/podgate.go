package integration

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/startgate"
	"k8s.io/apimachinery/pkg/types"
)

// gateBackend is the pod gate of the section backend
// (sandboxpolicy.SectionBackend): one call reaches every section.
type gateBackend interface {
	MarkPod(ctx context.Context, pod sandboxpolicy.PodBinding, seq sandboxpolicy.Seq) []sandboxpolicy.PodSectionResult
	EnsurePodBound(ctx context.Context, uid types.UID, plan sandboxpolicy.Plan) []sandboxpolicy.PodSectionResult
	ConfirmPod(uid types.UID, cgroupID uint64, plan sandboxpolicy.Plan) []sandboxpolicy.PodSectionConfirmation
	ReleasePod(ctx context.Context, uid types.UID, cgroupID uint64) error
	UnmarkPod(ctx context.Context, uid types.UID, cgroupID uint64, seq sandboxpolicy.Seq) error
	BindPodsAt(ctx context.Context, pods []sandboxpolicy.PodBinding, seq sandboxpolicy.Seq) error
	SetStartGate(enabled bool)
	SetCgroupGone(gone func(cgroup uint64) bool)
}

var _ gateBackend = (*sandboxpolicy.SectionBackend)(nil)

// The gate's own reply errors. None wraps context.DeadlineExceeded or
// context.Canceled. That keeps the handler's answer apart from its own
// context; it is not what keeps a reply from being fatal at the runtime
// (ttrpc sends any handler error as a status, which containerd never takes
// as fatal; the fatal case is a handler that overruns, see
// startgate.ReturnMargin).
var (
	// errWorkDeadline: the work deadline passed before the pod write
	// completed. The worker goes on; its write applies if its sequence is
	// still current.
	errWorkDeadline = errors.New("start gate: the work deadline passed before the pod write completed")
	// errHandlerGone: the handler's context ended before the pod write
	// completed. The worker goes on, as for errWorkDeadline.
	errHandlerGone = errors.New("start gate: the handler stopped waiting before the pod write completed")
	// errNoWorkDeadline: the caller gave no work deadline
	// (startgate.WorkDeadline).
	errNoWorkDeadline = errors.New("start gate: no work deadline")
	// errSandboxRemoved: the sandbox ID is tombstoned (RemovePodSandbox).
	// A removed sandbox is never marked again; a new sandbox of the pod
	// has a new ID.
	// It is startgate.ErrSandboxRemoved, so the plugin can tell it apart.
	errSandboxRemoved = startgate.ErrSandboxRemoved
	// errNotJoined: the pod has no live sandbox in the gate's set.
	errNotJoined = errors.New("start gate: the pod sandbox never joined the gate")
	// errNotSelected: only a Selected pod with a section plan is marked.
	errNotSelected = errors.New("start gate: only a Selected pod with a section plan is marked")
	// errNoCgroup: the sandbox's pod cgroup was not resolved (cgroup ID 0).
	errNoCgroup = errors.New("start gate: the pod sandbox has no resolved pod cgroup")
	// errGateClosed: the service is closing; no new work is queued.
	errGateClosed = errors.New("start gate: closed")
)

// holdRetry is the pause between two bind attempts of a held create.
const holdRetry = 20 * time.Millisecond

// maxTombstones bounds the sandbox tombstones kept without a cgroup-gone
// proof; the oldest go first. A sandbox ID is never reused, so a dropped
// tombstone only matters for a worker still in flight for that sandbox,
// far older than this many removals.
const maxTombstones = 8192

// gateSandbox is one pod sandbox as the NRI payload names it, with its
// resolved pod cgroup.
type gateSandbox struct {
	UID        types.UID
	Namespace  string
	Name       string
	SandboxID  string
	CgroupID   uint64
	CgroupPath string
}

// gatePod is an NRI-joined pod in the gate's set.
type gatePod struct {
	sandbox gateSandbox
	// sandboxes are the pod's live joined sandbox IDs (Selected or
	// Unselected), each with its own pod cgroup. Only these count for "the
	// pod's last sandbox".
	sandboxes map[string]uint64
	// plan and seq are the newest classification the gate holds for the
	// pod (a mark's plan; empty for an Unselected join or after an
	// unmark). An NRI-only pod (one the API path never lists) keeps this
	// plan until the next NRI event: the refresh never sends it at a newer
	// sequence (see merge), so S5 must reclassify such pods.
	plan sandboxpolicy.Plan
	seq  sandboxpolicy.Seq
	// unmarked: an UnmarkPod at unmarkSeq completed and no mark followed.
	unmarked  bool
	unmarkSeq sandboxpolicy.Seq
	// fresh: no classification was recorded yet (a new entry, or one that
	// a recreated sandbox restarted); the next one is taken whatever its
	// sequence.
	fresh bool
	// released: the pod's last sandbox is gone (ReleasePod). releasedAt
	// orders the release against a refresh (podGate.releases).
	released   bool
	releasedAt uint64
	// release is the last release job queued for the pod (a retried
	// removal waits for it).
	release *gateJob
}

type tombstone struct {
	uid      types.UID
	cgroupID uint64
}

// gateJob is one unit of a pod's single-flight worker.
type gateJob struct {
	// key merges a retried request into the queued or running job with
	// the same key. An empty key is never merged (a release that must run
	// again after the running one).
	key  string
	run  func(ctx context.Context) gateResult
	done chan struct{}
	res  gateResult
}

type gateResult struct {
	sections      []sandboxpolicy.PodSectionResult
	confirmations []sandboxpolicy.PodSectionConfirmation
	err           error
}

// podWorker runs one pod's jobs in order, one at a time.
type podWorker struct {
	queue   []*gateJob
	current *gateJob
}

// podGate is the start gate's single writer: the set of NRI-joined pods, the
// sandbox tombstones, and a single-flight worker per pod that makes the
// backend calls (MarkPod, EnsurePodBound with ConfirmPod, UnmarkPod,
// ReleasePod). A handler waits for its job until its work deadline and then
// abandons it: the worker goes on, and its write applies when its sequence is
// still current (the backend orders it); the deadline only governs the
// reply.
//
// podMu guards only the set, the tombstones and the queues: no backend call
// and no wait runs under it.
type podGate struct {
	backend gateBackend
	// ctx is the workers' context: they outlive the handlers; close
	// cancels it.
	ctx    context.Context
	cancel context.CancelFunc
	// gone is the cgroup-gone proof (by cgroup ID), or nil. notePath, when
	// set, gives the proof a cgroup's path for its live veto (the checker's
	// notePath).
	gone     func(uint64) bool
	notePath func(id uint64, path string)

	podMu      sync.Mutex
	pods       map[types.UID]*gatePod
	tombstones map[string]tombstone
	tombOrder  []string
	workers    map[types.UID]*podWorker
	// releases counts the releases; a refresh compares it before and
	// after its BindPodsAt.
	releases uint64
	closed   bool
	running  sync.WaitGroup
}

func newPodGate(ctx context.Context, backend gateBackend, gone func(uint64) bool) *podGate {
	ctx, cancel := context.WithCancel(ctx)
	return &podGate{backend: backend, ctx: ctx, cancel: cancel, gone: gone, pods: map[types.UID]*gatePod{}, tombstones: map[string]tombstone{}, workers: map[types.UID]*podWorker{}}
}

// classificationPlan is the pod plan of a Selected classification: the
// section plans' policies, merged by UID, so every section finds its part
// (the section plans hold one section each).
func classificationPlan(c sandboxpolicy.PodClassification) sandboxpolicy.Plan {
	names := make([]string, 0, len(c.Sections))
	for name := range c.Sections {
		names = append(names, name)
	}
	slices.Sort(names)
	var plan sandboxpolicy.Plan
	at := map[types.UID]int{}
	for _, name := range names {
		for _, p := range c.Sections[name].Plan.Policies {
			i, ok := at[p.Identity.UID]
			if !ok {
				at[p.Identity.UID] = len(plan.Policies)
				plan.Policies = append(plan.Policies, p)
				continue
			}
			q := &plan.Policies[i]
			if p.Privilege != nil {
				q.Privilege = p.Privilege
			}
			if p.Network != nil {
				q.Network = p.Network
			}
			if p.File != nil {
				q.File = p.File
			}
		}
	}
	return plan
}

// replyError strips context errors from err's chain: the text stays, the
// identity goes (see errWorkDeadline). An ErrStaleSequence keeps its
// identity: the handler retries on it.
func replyError(err error) error {
	if err == nil || (!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)) {
		return err
	}
	if errors.Is(err, sandboxpolicy.ErrStaleSequence) {
		return errors.Join(sandboxpolicy.ErrStaleSequence, errors.New(err.Error()))
	}
	return errors.New(err.Error())
}

func replySections(in []sandboxpolicy.PodSectionResult) []sandboxpolicy.PodSectionResult {
	out := slices.Clone(in)
	for i := range out {
		out[i].Err = replyError(out[i].Err)
	}
	return out
}

// notePathLocked hands a cgroup's path to the gone proof's live veto.
// Runs under podMu (notePath takes only the checker's own lock).
func (g *podGate) notePathLocked(id uint64, path string) {
	if g.notePath != nil && id != 0 && path != "" {
		g.notePath(id, path)
	}
}

// tombstonedLocked reports whether sandboxID was removed. Runs under podMu.
func (g *podGate) tombstonedLocked(sandboxID string) bool {
	_, ok := g.tombstones[sandboxID]
	return ok
}

// enqueueLocked adds job to the pod's worker, or returns the queued or
// running job with the same key (a retried handler joins the work in
// flight). Runs under podMu.
func (g *podGate) enqueueLocked(uid types.UID, job *gateJob) *gateJob {
	if g.closed {
		job.done = make(chan struct{})
		job.res = gateResult{err: errGateClosed}
		close(job.done)
		return job
	}
	w := g.workers[uid]
	if w == nil {
		w = &podWorker{}
		g.workers[uid] = w
		g.running.Add(1)
		go g.drain(uid, w)
	}
	if job.key != "" {
		if w.current != nil && w.current.key == job.key {
			return w.current
		}
		for _, queued := range w.queue {
			if queued.key == job.key {
				return queued
			}
		}
	}
	job.done = make(chan struct{})
	w.queue = append(w.queue, job)
	return job
}

// drain runs the pod's jobs until its queue is empty.
func (g *podGate) drain(uid types.UID, w *podWorker) {
	defer g.running.Done()
	for {
		g.podMu.Lock()
		if len(w.queue) == 0 {
			w.current = nil
			delete(g.workers, uid)
			g.podMu.Unlock()
			return
		}
		job := w.queue[0]
		w.queue = w.queue[1:]
		w.current = job
		g.podMu.Unlock()
		job.res = job.run(g.ctx)
		close(job.done)
	}
}

// await waits for job until deadline or the handler's ctx ends.
func await(ctx context.Context, job *gateJob, deadline time.Time) (gateResult, error) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-job.done:
		return job.res, nil
	case <-timer.C:
		return gateResult{}, errWorkDeadline
	case <-ctx.Done():
		return gateResult{}, errHandlerGone
	}
}

// JoinAndMark joins a Selected pod's sandbox to the set and writes its
// pending mark (PodGate.MarkPod) at the classification's sequence. It
// returns each section's result, or an error when no result came: a
// tombstoned sandbox, a pod that is not Selected, or the deadline (the mark
// still goes on). A section result of sandboxpolicy.ErrStaleSequence means
// a newer classification wrote the pod: the caller classifies again (a
// fresh capture) and retries once.
func (g *podGate) JoinAndMark(ctx context.Context, sb gateSandbox, c sandboxpolicy.PodClassification, deadline time.Time) ([]sandboxpolicy.PodSectionResult, error) {
	if deadline.IsZero() {
		return nil, errNoWorkDeadline
	}
	if c.Class != sandboxpolicy.PodSelected || len(c.Sections) == 0 {
		return nil, errNotSelected
	}
	plan := classificationPlan(c)
	g.podMu.Lock()
	if g.tombstonedLocked(sb.SandboxID) {
		g.podMu.Unlock()
		return nil, errSandboxRemoved
	}
	// The sandbox counts for "the pod's last sandbox" even when its cgroup
	// is not resolved: otherwise an old sandbox's removal would release a
	// pod this sandbox keeps alive (S3 review v2 N1).
	p := g.joinLocked(sb)
	if sb.CgroupID == 0 {
		g.podMu.Unlock()
		return nil, errNoCgroup
	}
	g.notePathLocked(sb.CgroupID, sb.CgroupPath)
	if p.fresh || c.Seq.Compare(p.seq) == sandboxpolicy.SeqNewer || c.Seq.Compare(p.seq) == sandboxpolicy.SeqEqual {
		p.sandbox, p.plan, p.seq, p.unmarked, p.fresh = sb, plan, c.Seq, false, false
	}
	pod := sandboxpolicy.PodBinding{PodUID: sb.UID, Namespace: sb.Namespace, PodName: sb.Name, CgroupID: sb.CgroupID, CgroupPath: sb.CgroupPath, Plan: plan}
	seq := c.Seq
	job := g.enqueueLocked(sb.UID, &gateJob{
		key: fmt.Sprintf("mark/%s/%d/%d/%d/%s", sb.SandboxID, sb.CgroupID, seq.Config, seq.Input, planKey(c)),
		run: func(ctx context.Context) gateResult {
			// A worker for a sandbox removed meanwhile never marks it again.
			g.podMu.Lock()
			removed := g.tombstonedLocked(sb.SandboxID)
			g.podMu.Unlock()
			if removed {
				return gateResult{err: errSandboxRemoved}
			}
			return gateResult{sections: g.backend.MarkPod(ctx, pod, seq)}
		},
	})
	g.podMu.Unlock()
	res, err := await(ctx, job, deadline)
	if err != nil {
		return nil, err
	}
	return replySections(res.sections), replyError(res.err)
}

// joinLocked records sb as a live joined sandbox of its pod and returns the
// pod's entry. A new pod, or a recreated sandbox of a released one, starts
// fresh (ReleasePod forgot the pod's order in the backend): its entry has
// no plan and fresh set. Runs under podMu.
func (g *podGate) joinLocked(sb gateSandbox) *gatePod {
	p := g.pods[sb.UID]
	if p == nil || p.released {
		p = &gatePod{sandbox: sb, sandboxes: map[string]uint64{}, fresh: true}
		g.pods[sb.UID] = p
	}
	p.sandboxes[sb.SandboxID] = sb.CgroupID
	return p
}

// JoinUnselected joins a sandbox that the classification found Unselected
// (or exempt): it records the sandbox, so that "the pod's last sandbox" is
// counted over every sandbox of the pod, and writes nothing to the backend.
// S5 calls it (or JoinAndMark) for every sandbox it learns about:
// RunPodSandbox and Synchronize. A pod that is not joined has nothing the
// gate wrote, and its sandbox's removal releases nothing (ReleaseSandbox).
func (g *podGate) JoinUnselected(sb gateSandbox) error {
	g.podMu.Lock()
	defer g.podMu.Unlock()
	if g.tombstonedLocked(sb.SandboxID) {
		return errSandboxRemoved
	}
	// A sandbox whose cgroup is not resolved (0) is recorded too: it counts
	// for "the pod's last sandbox" (S3 review v2 N1).
	// An unresolved sandbox never replaces a known cgroup (S3 review v3
	// R1): the release and the gone proof need it. (JoinAndMark returns
	// before it updates p.sandbox when the cgroup is 0.)
	if p := g.joinLocked(sb); p.fresh && (sb.CgroupID != 0 || p.sandbox.CgroupID == 0) {
		p.sandbox = sb
	}
	g.notePathLocked(sb.CgroupID, sb.CgroupPath)
	return nil
}

// planKey identifies a classification's section plans (their digests).
func planKey(c sandboxpolicy.PodClassification) string {
	names := make([]string, 0, len(c.Sections))
	for name := range c.Sections {
		names = append(names, name)
	}
	slices.Sort(names)
	key := ""
	for _, name := range names {
		key += name + "=" + c.Sections[name].Digest + ";"
	}
	return key
}

// HoldUntilConfirmed is the create hold: it moves the pod to its record's
// plan's slot (PodGate.EnsurePodBound) and reads back each section against
// the caller's own classification (PodGate.ConfirmPod), again every
// holdRetry, until every section is Confirmed or the deadline passes. It
// returns the last confirmations it read, with errWorkDeadline (joined with
// the last bind errors) when not every section was Confirmed by then. The
// caller decides from the confirmations (a Strict create needs Confirmed,
// or Pending with Strict).
func (g *podGate) HoldUntilConfirmed(ctx context.Context, uid types.UID, sandboxID string, c sandboxpolicy.PodClassification, deadline time.Time) ([]sandboxpolicy.PodSectionConfirmation, error) {
	if deadline.IsZero() {
		return nil, errNoWorkDeadline
	}
	if c.Class != sandboxpolicy.PodSelected || len(c.Sections) == 0 {
		return nil, errNotSelected
	}
	plan := classificationPlan(c)
	key := fmt.Sprintf("hold/%s/%s", sandboxID, planKey(c))
	var last []sandboxpolicy.PodSectionConfirmation
	var bindErrs []error
	for {
		g.podMu.Lock()
		if g.tombstonedLocked(sandboxID) {
			g.podMu.Unlock()
			return nil, errSandboxRemoved
		}
		p := g.pods[uid]
		cgroupID, joined := uint64(0), false
		if p != nil && !p.released {
			cgroupID, joined = p.sandboxes[sandboxID]
		}
		if !joined {
			g.podMu.Unlock()
			return nil, errNotJoined
		}
		job := g.enqueueLocked(uid, &gateJob{key: key, run: func(ctx context.Context) gateResult {
			g.podMu.Lock()
			removed := g.tombstonedLocked(sandboxID)
			g.podMu.Unlock()
			if removed {
				return gateResult{err: errSandboxRemoved}
			}
			bound := g.backend.EnsurePodBound(ctx, uid, plan)
			return gateResult{sections: bound, confirmations: g.backend.ConfirmPod(uid, cgroupID, plan)}
		}})
		g.podMu.Unlock()
		res, err := await(ctx, job, deadline)
		if err != nil {
			return last, errors.Join(append([]error{err}, bindErrs...)...)
		}
		if res.err != nil {
			return nil, replyError(res.err)
		}
		last, bindErrs = res.confirmations, nil
		for _, r := range res.sections {
			if r.Err != nil {
				bindErrs = append(bindErrs, replyError(r.Err))
			}
		}
		if len(last) > 0 && !slices.ContainsFunc(last, func(c sandboxpolicy.PodSectionConfirmation) bool { return c.State != sandboxpolicy.PodSectionConfirmed }) {
			return last, nil
		}
		wait := time.NewTimer(min(holdRetry, time.Until(deadline)))
		select {
		case <-wait.C:
		case <-ctx.Done():
			wait.Stop()
			return last, errors.Join(append([]error{errHandlerGone}, bindErrs...)...)
		}
		if !time.Now().Before(deadline) {
			return last, errors.Join(append([]error{errWorkDeadline}, bindErrs...)...)
		}
	}
}

// Unmark removes the pod's start gate binding because a classification at
// seq found it Unselected (PodGate.UnmarkPod). The pod stays in the set
// (only a tombstone, its last sandbox's removal or the cgroup-gone proof
// remove it); once the backend accepts the unmark, the entry has no plan.
// A retry whose UnmarkPod is refused as stale after an unmark at the same or
// a newer sequence completed is done, not failed (S2 review v6, note 1).
func (g *podGate) Unmark(ctx context.Context, sb gateSandbox, seq sandboxpolicy.Seq, deadline time.Time) error {
	if deadline.IsZero() {
		return errNoWorkDeadline
	}
	g.podMu.Lock()
	if g.tombstonedLocked(sb.SandboxID) {
		g.podMu.Unlock()
		return errSandboxRemoved
	}
	cgroupID := sb.CgroupID
	if p := g.pods[sb.UID]; p != nil && !p.released {
		cgroupID = p.sandbox.CgroupID
	}
	if cgroupID == 0 {
		g.podMu.Unlock()
		return errNoCgroup
	}
	job := g.enqueueLocked(sb.UID, &gateJob{
		key: fmt.Sprintf("unmark/%d/%d/%d", cgroupID, seq.Config, seq.Input),
		run: func(ctx context.Context) gateResult {
			err := g.backend.UnmarkPod(ctx, sb.UID, cgroupID, seq)
			g.podMu.Lock()
			defer g.podMu.Unlock()
			p := g.pods[sb.UID]
			switch {
			case p == nil || p.released:
			case err == nil:
				// Accepted: from now on the pod has no plan (merge never
				// sends it). A loosening takes a strictly newer sequence.
				if seq.Compare(p.seq) == sandboxpolicy.SeqNewer {
					p.plan, p.seq = sandboxpolicy.Plan{}, seq
				}
				if !p.unmarked || seq.Compare(p.unmarkSeq) == sandboxpolicy.SeqNewer {
					p.unmarked, p.unmarkSeq = true, seq
				}
			case sandboxpolicy.OnlyStale(err) && p.unmarked:
				if o := seq.Compare(p.unmarkSeq); o == sandboxpolicy.SeqEqual || o == sandboxpolicy.SeqOlder {
					err = nil // done: an unmark at this or a newer sequence completed
				}
			}
			return gateResult{err: err}
		},
	})
	g.podMu.Unlock()
	res, err := await(ctx, job, deadline)
	if err != nil {
		return err
	}
	return replyError(res.err)
}

// ReleaseSandbox is RemovePodSandbox: it tombstones the sandbox ID first, so
// no worker marks it again. When the sandbox was the pod's last live joined
// sandbox, it releases the pod (PodGate.ReleasePod, whatever the sequence)
// on the pod's worker, after any write in flight. A sandbox that never
// joined (an old sandbox the kubelet garbage-collects, one from before
// node-agent, or one S5 did not report) is only tombstoned: the gate wrote
// nothing for it, and releasing would unbind a live pod that another
// sandbox, or the API path, protects (S3 review v1 #1). A recreated sandbox
// has a new ID and starts fresh.
func (g *podGate) ReleaseSandbox(ctx context.Context, sb gateSandbox, deadline time.Time) error {
	if deadline.IsZero() {
		return errNoWorkDeadline
	}
	g.podMu.Lock()
	p := g.pods[sb.UID]
	cgroupID, joined := uint64(0), false
	if p != nil && !p.released {
		cgroupID, joined = p.sandboxes[sb.SandboxID]
	}
	retry := g.tombstonedLocked(sb.SandboxID)
	// A sandbox that never joined keeps its caller's cgroup, for the
	// gone proof that prunes the tombstone.
	g.tombstoneLocked(sb.SandboxID, sb.UID, cmp.Or(cgroupID, sb.CgroupID))
	if !joined {
		// A retried RemovePodSandbox (the runtime timed the first one out)
		// waits for the release the first one queued, while it is queued
		// or running (S3 review v2 N4). A finished release is not waited
		// for again: its result went to the first call, and S2 retries a
		// failed unbind at its next ready bindPods.
		var job *gateJob
		if retry && p != nil && p.released && p.release != nil {
			select {
			case <-p.release.done:
			default:
				job = p.release
			}
		}
		g.podMu.Unlock()
		if job == nil {
			return nil
		}
		res, err := await(ctx, job, deadline)
		if err != nil {
			return err
		}
		return replyError(res.err)
	}
	delete(p.sandboxes, sb.SandboxID)
	if len(p.sandboxes) > 0 {
		g.podMu.Unlock()
		return nil
	}
	g.releases++
	p.released, p.releasedAt = true, g.releases
	// A sandbox whose cgroup was not resolved releases the pod's known one.
	p.sandbox.CgroupID = cmp.Or(cgroupID, p.sandbox.CgroupID)
	job := g.enqueueReleaseLocked(sb.UID, p.sandbox.CgroupID, false)
	p.release = job
	g.podMu.Unlock()
	res, err := await(ctx, job, deadline)
	if err != nil {
		return err
	}
	return replyError(res.err)
}

// enqueueReleaseLocked queues the pod's ReleasePod. A release is never
// merged into the running job: it may have deleted the record already, and
// a later write may have bound the pod again (S3 review v1 #2). again: a
// release that must run after every queued job too (afterBind). Runs under
// podMu.
func (g *podGate) enqueueReleaseLocked(uid types.UID, cgroupID uint64, again bool) *gateJob {
	job := &gateJob{run: func(ctx context.Context) gateResult {
		return gateResult{err: g.backend.ReleasePod(ctx, uid, cgroupID)}
	}}
	if !again {
		// A queued release that has not started yet runs after this
		// point: share it.
		if w := g.workers[uid]; w != nil {
			for _, queued := range w.queue {
				if queued.key == fmt.Sprintf("release/%d", cgroupID) {
					return queued
				}
			}
		}
	}
	job = g.enqueueLocked(uid, job)
	job.key = fmt.Sprintf("release/%d", cgroupID)
	return job
}

// tombstoneLocked records a removed sandbox ID. Runs under podMu.
func (g *podGate) tombstoneLocked(sandboxID string, uid types.UID, cgroupID uint64) {
	if _, ok := g.tombstones[sandboxID]; ok {
		return
	}
	g.tombstones[sandboxID] = tombstone{uid: uid, cgroupID: cgroupID}
	g.tombOrder = append(g.tombOrder, sandboxID)
	for len(g.tombOrder) > maxTombstones {
		delete(g.tombstones, g.tombOrder[0])
		g.tombOrder = g.tombOrder[1:]
	}
}

// merge is bindPodPlans' set: pods from the API, with the NRI entries
// merged in, for BindPodsAt at seq.
//   - A released pod is left out: its last sandbox is gone, so the API path
//     must not bind it again (only a new sandbox's JoinAndMark does).
//   - An NRI pod the API path does not list (an informer miss, a failed
//     cgroup lookup) is added with its own plan, so its mark moves to its
//     slot (a same-plan bind is sequence-neutral), unless seq is newer than
//     the entry's: then the entry's plan may be older than one the backend
//     holds, and the pod is left out (missing never removes it).
//   - An entry with no plan (unmarked) is never added.
//
// It returns the releases counter for afterBind.
func (g *podGate) merge(pods []sandboxpolicy.PodBinding, seq sandboxpolicy.Seq, started func(types.UID, string) bool) ([]sandboxpolicy.PodBinding, uint64) {
	g.podMu.Lock()
	defer g.podMu.Unlock()
	out := make([]sandboxpolicy.PodBinding, 0, len(pods)+len(g.pods))
	listed := make(map[types.UID]bool, len(pods))
	for _, p := range pods {
		if e := g.pods[p.PodUID]; e != nil && e.released {
			continue
		}
		listed[p.PodUID] = true
		out = append(out, p)
	}
	for uid, e := range g.pods {
		if listed[uid] || e.released || len(e.plan.Policies) == 0 || seq.Compare(e.seq) == sandboxpolicy.SeqNewer {
			continue
		}
		out = append(out, sandboxpolicy.PodBinding{PodUID: uid, Namespace: e.sandbox.Namespace, PodName: e.sandbox.Name, CgroupID: e.sandbox.CgroupID, CgroupPath: e.sandbox.CgroupPath,
			Plan: e.plan, ContainersStarted: started != nil && started(uid, e.sandbox.CgroupPath)})
	}
	slices.SortFunc(out, func(a, b sandboxpolicy.PodBinding) int {
		switch {
		case a.PodUID < b.PodUID:
			return -1
		case a.PodUID > b.PodUID:
			return 1
		}
		return 0
	})
	return out, g.releases
}

// afterBind releases again every pod of sent that was released while the
// BindPodsAt that sent it ran (after releasesBefore): that call may have
// bound it again after its ReleasePod. It runs whatever BindPodsAt
// returned: an ErrStaleSequence never means nothing changed (S2 review v6,
// note 2).
func (g *podGate) afterBind(sent []sandboxpolicy.PodBinding, releasesBefore uint64) {
	g.podMu.Lock()
	defer g.podMu.Unlock()
	for _, p := range sent {
		if e := g.pods[p.PodUID]; e != nil && e.released && e.releasedAt > releasesBefore {
			e.release = g.enqueueReleaseLocked(p.PodUID, e.sandbox.CgroupID, true)
		}
	}
}

// prune removes the entries and tombstones whose cgroups are proven gone
// (by cgroup ID): an entry once every cgroup it tracks (its sandboxes' and
// its own) is gone. The proof is I/O: it runs outside podMu.
// It makes one check per distinct tracked ID on every gate refresh: up to
// the entries plus maxTombstones (S3 review v2 N7; many tombstones name a
// live pod's cgroup and stay). A performance note for S5/S9, not a
// correctness one.
func (g *podGate) prune() {
	if g.gone == nil {
		return
	}
	g.podMu.Lock()
	cgroups := map[uint64]bool{}
	for _, e := range g.pods {
		for _, id := range e.cgroups() {
			cgroups[id] = false
		}
	}
	for _, t := range g.tombstones {
		cgroups[t.cgroupID] = false
	}
	g.podMu.Unlock()
	found := false
	for id := range cgroups {
		if id != 0 && g.gone(id) {
			cgroups[id], found = true, true
		}
	}
	if !found {
		return
	}
	g.podMu.Lock()
	defer g.podMu.Unlock()
	for uid, e := range g.pods {
		ids := e.cgroups()
		all := len(ids) > 0
		for _, id := range ids {
			all = all && cgroups[id]
		}
		if all {
			delete(g.pods, uid)
		}
	}
	kept := g.tombOrder[:0]
	for _, id := range g.tombOrder {
		if cgroups[g.tombstones[id].cgroupID] {
			delete(g.tombstones, id)
			continue
		}
		kept = append(kept, id)
	}
	g.tombOrder = kept
}

// cgroups are the pod cgroups the entry tracks.
// ID 0 (a sandbox whose cgroup was not resolved) is left out: it can never
// be proven gone. An entry that tracks no cgroup at all is never pruned
// (bounded by the pods of the node's lifetime; see S3-S5-NOTES.md).
func (e *gatePod) cgroups() []uint64 {
	var out []uint64
	for _, id := range append([]uint64{e.sandbox.CgroupID}, slices.Collect(maps.Values(e.sandboxes))...) {
		if id != 0 && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// close stops the gate: no new job is queued, the workers' context is
// canceled, and it waits for the workers (each finishes its current job:
// the backend returns on the canceled context) until ctx ends. The
// service calls it before it closes the backend.
func (g *podGate) close(ctx context.Context) error {
	g.podMu.Lock()
	g.closed = true
	g.podMu.Unlock()
	g.cancel()
	done := make(chan struct{})
	go func() {
		g.running.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("start gate: workers still running at close: %w", ctx.Err())
	}
}

// wait waits for every worker to finish (tests).
func (g *podGate) wait() { g.running.Wait() }
