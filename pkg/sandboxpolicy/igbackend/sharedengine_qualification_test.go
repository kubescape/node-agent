//go:build sandbox_shared_qualification

package igbackend

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type fakeSharedSession struct {
	node     *fakeSharedNode
	cgroup   uint64
	scope    uint64
	route    uint64 // last committed route generation
	epoch    uint64 // root epoch of the committed policy
	lease    fullruntime.BindingLease
	compiles int
	// stale: PublishCompiled refusals as stale (another commit moved the route).
	stale      int
	publishErr error
	onPublish  func(fullruntime.SharedCompiled)
	// receiptScope overrides the scope PublishCompiled reports.
	receiptScope *uint64
	removedAt    []uint64
	removeErr    error
}

func (s *fakeSharedSession) Compile(p fullruntime.SharedBindingPolicy) (fullruntime.SharedCompiled, error) {
	s.compiles++
	if p.Source == nil || p.Container == "" {
		return fullruntime.SharedCompiled{}, fmt.Errorf("fake: invalid policy")
	}
	// Like IG: a revision of the same policy UID retains its root epoch.
	activated := map[string]uint64{}
	if s.epoch != 0 {
		activated[p.Source.ID] = s.epoch
	}
	program, err := fullpolicy.CompileKernelWithRoleEpochs([]fullpolicy.Policy{*p.Source}, s.route+1, p.Container, activated)
	if err != nil {
		return fullruntime.SharedCompiled{}, err
	}
	kp, err := fullpolicy.Decode[fullpolicy.KernelPolicy](program.Entries[fullpolicy.KernelPolicyBase])
	if err != nil {
		return fullruntime.SharedCompiled{}, err
	}
	return fullruntime.SharedCompiled{Generation: s.route + 1, Program: program, Epochs: map[string]uint64{p.Source.ID: kp.RootEpoch}}, nil
}

func (s *fakeSharedSession) PublishCompiled(_ context.Context, c fullruntime.SharedCompiled) (fullruntime.SharedRouteState, error) {
	if c.Generation != s.route+1 {
		return fullruntime.SharedRouteState{}, fmt.Errorf("fake: %w", fullruntime.ErrSharedCompiledStale)
	}
	if s.stale > 0 {
		s.stale--
		s.route++ // a concurrent commit moved the route
		return fullruntime.SharedRouteState{}, fmt.Errorf("fake race: %w", fullruntime.ErrSharedCompiledStale)
	}
	if s.publishErr != nil {
		return fullruntime.SharedRouteState{}, s.publishErr
	}
	if s.onPublish != nil {
		s.onPublish(c) // kernel commit precedes the Go receipt
	}
	s.route = c.Generation
	for _, epoch := range c.Epochs {
		s.epoch = epoch
	}
	scope := s.scope
	if s.receiptScope != nil {
		scope = *s.receiptScope
	}
	return fullruntime.SharedRouteState{Cgroup: s.cgroup, Scope: scope, Generation: s.route, Class: 2}, nil
}

func (s *fakeSharedSession) Inspect() fullruntime.SharedBindingStatus {
	return fullruntime.SharedBindingStatus{ScopeCookie: s.scope, CgroupID: s.cgroup, Generation: s.route, RoutePublished: s.route != 0}
}

func (s *fakeSharedSession) Remove(_ context.Context, generation uint64) error {
	s.removedAt = append(s.removedAt, generation)
	if generation != s.route {
		return fmt.Errorf("fake: remove at %d, route %d", generation, s.route)
	}
	return s.removeErr
}

type fakeSharedNode struct {
	mu        sync.Mutex
	sessions  []*fakeSharedSession
	route0    uint64 // initial route generation of new sessions (retained account)
	nextScope uint64
	stopErr   error
	stops     int
	ready     error
	fail      fullruntime.SharedFailClosedHealth
	failErr   error
	counters  fullruntime.KernelEventCounters
	onBind    func(*fakeSharedSession)
}

func (n *fakeSharedNode) Bind(ctx context.Context, c fullruntime.SharedBindingConfig) (sharedSession, error) {
	lease, err := c.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.nextScope++
	s := &fakeSharedSession{node: n, cgroup: c.CgroupID, scope: 100 + n.nextScope, route: n.route0, lease: lease}
	n.sessions = append(n.sessions, s)
	if n.onBind != nil {
		n.onBind(s)
	}
	return s, nil
}

func (n *fakeSharedNode) StopNode(context.Context) error {
	n.stops++
	if n.stopErr != nil {
		return n.stopErr
	}
	for _, s := range n.sessions {
		if s.lease != nil {
			_ = s.lease.Close() // pins are released with the node
			s.lease = nil
		}
	}
	return nil
}
func (n *fakeSharedNode) Ready() error { return n.ready }
func (n *fakeSharedNode) KernelEventCounters() (fullruntime.KernelEventCounters, error) {
	return n.counters, nil
}
func (n *fakeSharedNode) FailClosedHealth() (fullruntime.SharedFailClosedHealth, error) {
	return n.fail, n.failErr
}
func (n *fakeSharedNode) FactHealth() (fullruntime.SharedFactHealth, error) {
	return fullruntime.SharedFactHealth{Passes: 3}, nil
}

type collectingReceiver struct {
	mu       sync.Mutex
	verdicts []sandboxpolicy.Verdict
}

func (r *collectingReceiver) ReportVerdict(_ context.Context, v sandboxpolicy.Verdict) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.verdicts = append(r.verdicts, v)
	return nil
}

func singlePlan() sandboxpolicy.Plan {
	p := verdictPlan()
	p.Policies = p.Policies[:1]
	return p
}

type sharedFixture struct {
	engine   *SharedEngine
	node     *fakeSharedNode
	backend  *FullBackend
	source   *fullTestSource
	receiver *collectingReceiver
	errs     []error
	starts   int
	binding  sandboxpolicy.Binding
}

func newSharedFixture(t *testing.T) *sharedFixture {
	t.Helper()
	f := &sharedFixture{node: &fakeSharedNode{route0: 9}, source: &fullTestSource{lease: &fullTestLease{}}, receiver: &collectingReceiver{}}
	f.engine = newSharedEngine(func(context.Context) (sharedNode, error) { f.starts++; return f.node, nil }, func(err error) { f.errs = append(f.errs, err) })
	var err error
	f.backend, err = NewFull(f.engine, f.source, f.receiver, func(err error) { f.errs = append(f.errs, err) })
	if err != nil {
		t.Fatal(err)
	}
	f.binding = sandboxpolicy.Binding{Runtime: "containerd", ContainerID: "id", ContainerName: "app", CgroupID: 19, PID: 20, MountNamespace: 21}
	return f
}

// event is one shared verdict of rule bit 2 (enforce-deny) at route generation.
func sharedEvent(scope, route uint64) RawFullVerdict { return sharedEventFor(19, scope, route) }

func sharedEventFor(cgroup, scope, route uint64) RawFullVerdict {
	return RawFullVerdict{RawVerdict: RawVerdict{Generation: route, Cgroup: cgroup, Deny: 1, Mode: 2, PID: 7, PathResult: -1}, MatchedRules: [4]uint64{4}, Shared: true, ExecClass: 2, Scope: scope, ExecID: 3, Pass: 1, FactsUnknown: 1, HasTaskCookie: true, TaskCookie: 77, LoadEpoch: 0x5eed}
}

func TestSharedEngineBackendLifecycle(t *testing.T) {
	f := newSharedFixture(t)
	ctx := context.Background()
	r, err := f.backend.Replace(ctx, f.binding, singlePlan())
	// Committed, but never confirmed: the shared engine stays NotReady.
	if !r.Committed || !r.ProtectionUnconfirmed || r.ActiveRevision != "combined-revision" || !errors.Is(err, fullruntime.ErrSharedNativeUnavailable) {
		t.Fatalf("first replace %+v %v", r, err)
	}
	if f.starts != 1 || len(f.node.sessions) != 1 || f.source.calls != 1 {
		t.Fatalf("starts %d sessions %d prepares %d", f.starts, len(f.node.sessions), f.source.calls)
	}
	s := f.node.sessions[0]
	if s.route != 10 || s.lease == nil {
		t.Fatalf("route %d lease %v", s.route, s.lease)
	}
	// Route generation 10 decodes with the backend's generation-1 provenance.
	f.engine.route(sharedEvent(s.scope, 10))
	if len(f.receiver.verdicts) != 1 || len(f.errs) != 0 {
		t.Fatalf("verdicts %+v errors %v", f.receiver.verdicts, f.errs)
	}
	v := f.receiver.verdicts[0]
	if v.Rule != "enforce-deny" || v.Verdict != api.ActionDeny || v.PID != 7 || v.Pass == nil || *v.Pass != 1 || v.ExecID == nil || *v.ExecID != 3 || v.TaskCookie == nil || *v.TaskCookie != 77 || v.LoadEpoch == nil || *v.LoadEpoch != 0x5eed {
		t.Fatalf("verdict %+v", v)
	}
	// D1: an Audit fault event decodes as a would-deny operational error.
	fault := sharedEvent(s.scope, 10)
	fault.Mode, fault.Error, fault.Pass, fault.MatchedRules = 1, 1, sharedVerdictPassUnknown, [4]uint64{}
	f.engine.route(fault)
	if len(f.receiver.verdicts) != 2 || len(f.errs) != 0 {
		t.Fatalf("fault verdicts %d errors %v", len(f.receiver.verdicts), f.errs)
	}
	if v := f.receiver.verdicts[1]; !v.WouldDeny || v.Reason != "operational_error" || v.Pass != nil || v.MatchesComplete {
		t.Fatalf("audit fault %+v", v)
	}

	// Reload: one stale race is recompiled at the moved route generation.
	next := singlePlan()
	next.Revision, next.Policies[0].Revision = "next", "policy-next"
	s.stale = 1
	r, err = f.backend.Replace(ctx, f.binding, next)
	if !r.Committed || r.ActiveRevision != "next" || !errors.Is(err, fullruntime.ErrSharedNativeUnavailable) {
		t.Fatalf("reload %+v %v", r, err)
	}
	if s.route != 12 || s.compiles != 3 || f.starts != 1 || f.source.calls != 1 {
		t.Fatalf("route %d compiles %d starts %d", s.route, s.compiles, f.starts)
	}
	// Root epochs stay in backend generations (IG retained its route epoch 10).
	if epochs := f.backend.records[key(f.binding)].instance.Epochs(); epochs["uid-one"] != 1 || s.epoch != 10 {
		t.Fatalf("epochs %v, IG epoch %d", epochs, s.epoch)
	}
	// The raced generation 11 was never this binding's: dropped, not decoded.
	f.engine.route(sharedEvent(s.scope, 11))
	f.engine.route(sharedEvent(s.scope, 12))
	f.engine.route(sharedEvent(s.scope, 10)) // previous generation still decodes
	if len(f.receiver.verdicts) != 4 || len(f.errs) != 1 || !strings.Contains(f.errs[0].Error(), "unknown route generation 11") {
		t.Fatalf("verdicts %d errors %v", len(f.receiver.verdicts), f.errs)
	}
	if f.receiver.verdicts[2].Revision != "next" || f.receiver.verdicts[3].Revision != "combined-revision" {
		t.Fatalf("provenance %q %q", f.receiver.verdicts[2].Revision, f.receiver.verdicts[3].Revision)
	}

	// Close refuses while a binding is live; Withdraw removes at the route generation.
	if err := f.engine.Close(ctx); err == nil {
		t.Fatal("closed with a live binding")
	}
	w, err := f.backend.Withdraw(ctx, f.binding)
	if err != nil || !w.Committed || len(s.removedAt) != 1 || s.removedAt[0] != 12 {
		t.Fatalf("withdraw %+v %v removed %v", w, err, s.removedAt)
	}
	// The retired scope's in-flight events are dropped silently; another
	// scope of the unbound cgroup is reported.
	f.engine.route(sharedEvent(s.scope, 12))
	f.engine.route(sharedEvent(s.scope+50, 12))
	if len(f.receiver.verdicts) != 4 || len(f.errs) != 2 || !strings.Contains(f.errs[1].Error(), "unbound cgroup") {
		t.Fatalf("event after removal: %v", f.errs)
	}
	f.node.stopErr = errors.New("teardown pending")
	if err := f.backend.Close(ctx); err == nil || f.source.lease.closed != 0 {
		t.Fatalf("close %v lease closed %d", err, f.source.lease.closed)
	}
	f.node.stopErr = nil
	if err := f.backend.Close(ctx); err != nil || f.node.stops != 2 || f.source.lease.closed != 1 {
		t.Fatalf("close %v stops %d lease closed %d", err, f.node.stops, f.source.lease.closed)
	}
	if _, err := f.engine.Start(ctx, "x", FullStartConfig{}, nil); err == nil {
		t.Fatal("started after close")
	}
}

func TestSharedEngineStaleRetryIsBounded(t *testing.T) {
	f := newSharedFixture(t)
	f.node.route0 = 0
	ctx := context.Background()
	if _, err := f.backend.Replace(ctx, f.binding, singlePlan()); !errors.Is(err, fullruntime.ErrSharedNativeUnavailable) {
		t.Fatal(err)
	}
	s := f.node.sessions[0]
	next := singlePlan()
	next.Revision = "next"
	s.stale = SharedPublishAttempts
	r, err := f.backend.Replace(ctx, f.binding, next)
	if r.Committed || !errors.Is(err, fullruntime.ErrSharedCompiledStale) || s.compiles != 1+SharedPublishAttempts {
		t.Fatalf("stale replace %+v %v compiles %d", r, err, s.compiles)
	}
	instance := f.backend.records[key(f.binding)].instance.(*sharedInstance)
	if instance.Generation() != 1 || len(instance.generations) != 1 || instance.generations[1] != 1 {
		t.Fatalf("staged provenance leaked: generation %d map %v", instance.Generation(), instance.generations)
	}
	// A non-stale publication refusal keeps last-good without retrying. Its
	// outcome may be unknown, so the staging stays: an event the kernel
	// produced at that route generation still decodes.
	s.publishErr = errors.New("refused")
	compiles := s.compiles
	if _, err := f.backend.Replace(ctx, f.binding, next); err == nil || s.compiles != compiles+1 || len(instance.generations) != 2 || instance.generations[s.route+1] == 0 {
		t.Fatalf("refusal %v compiles %d map %v", err, s.compiles-compiles, instance.generations)
	}
	f.engine.route(sharedEvent(s.scope, s.route+1))
	if len(f.receiver.verdicts) != 1 || f.receiver.verdicts[0].Revision != "next" {
		t.Fatalf("unknown-outcome verdicts %+v errors %v", f.receiver.verdicts, f.errs)
	}
	// A later publication at the same route generation replaces the staging.
	s.publishErr = nil
	if _, err := f.backend.Replace(ctx, f.binding, next); !errors.Is(err, fullruntime.ErrSharedNativeUnavailable) || instance.generations[s.route] != instance.Generation() {
		t.Fatalf("resolved %v map %v generation %d", err, instance.generations, instance.Generation())
	}
	// A superseded unknown-outcome publication is aborted with its staging.
	s.publishErr = errors.New("refused")
	if _, err := f.backend.Replace(ctx, f.binding, singlePlan()); err == nil || instance.PendingGeneration() == 0 {
		t.Fatalf("second refusal %v pending %d", err, instance.PendingGeneration())
	}
	pendingRoute := s.route + 1
	s.publishErr = nil
	third := singlePlan()
	third.Revision = "third"
	if r, err := f.backend.Replace(ctx, f.binding, third); !r.Committed || !errors.Is(err, fullruntime.ErrSharedNativeUnavailable) || instance.PendingGeneration() != 0 || instance.generations[pendingRoute] != instance.Generation() {
		t.Fatalf("superseded %+v %v map %v", r, err, instance.generations)
	}
}

// M10: a reused cgroup ID never receives a retired binding's in-flight events.
func TestSharedEngineReusedCgroupDropsRetiredScope(t *testing.T) {
	f := newSharedFixture(t)
	ctx := context.Background()
	if _, err := f.backend.Replace(ctx, f.binding, singlePlan()); !errors.Is(err, fullruntime.ErrSharedNativeUnavailable) {
		t.Fatal(err)
	}
	old := f.node.sessions[0]
	if _, err := f.backend.Withdraw(ctx, f.binding); err != nil {
		t.Fatal(err)
	}
	if f.engine.cgroups[19] != nil {
		t.Fatal("cgroup still bound after withdraw")
	}
	// A new container reuses cgroup 19 with the same route generations. The
	// retired scope's event at the shared route generation must reach the
	// new binding neither between its Bind and commit nor after it.
	f.binding.ContainerID, f.binding.PID = "id2", 30
	var fresh *fakeSharedSession
	f.node.onBind = func(s *fakeSharedSession) {
		fresh = s
		s.onPublish = func(fullruntime.SharedCompiled) {
			f.engine.route(sharedEvent(old.scope, 10))
			f.engine.route(sharedEvent(s.scope, 10)) // the new commit's event
		}
	}
	errs := len(f.errs)
	r, err := f.backend.Replace(ctx, f.binding, singlePlan())
	if !r.Committed || !errors.Is(err, fullruntime.ErrSharedNativeUnavailable) || fresh == nil || fresh.scope == old.scope {
		t.Fatalf("rebind %+v %v", r, err)
	}
	f.engine.route(sharedEvent(old.scope, 10))
	if len(f.receiver.verdicts) != 1 || f.receiver.verdicts[0].Scope == nil || *f.receiver.verdicts[0].Scope != fresh.scope || len(f.errs) != errs {
		t.Fatalf("verdicts %+v errors %v", f.receiver.verdicts, f.errs[errs:])
	}
}

// The live product publisher mints the route scope in the first publication
// (IG's ScopeCookie stays 0, EKS run 16): the binding publishes and learns
// the scope from the receipt. Until then no event is attributed, so a verdict
// raced between the kernel commit and the receipt is reported, not
// delivered. A protocol scope cookie is still registered before staging, and
// a zero receipt scope is a fault that keeps checks on.
func TestSharedEngineScopeBeforeStaging(t *testing.T) {
	const minted = uint64(0x5c09e)
	f := newSharedFixture(t)
	ctx := context.Background()
	var instance *sharedInstance
	f.node.onBind = func(s *fakeSharedSession) {
		s.scope = 0
		scope := minted
		s.receiptScope = &scope
		s.onPublish = func(fullruntime.SharedCompiled) {
			instance = f.engine.cgroups[19]
			f.engine.route(sharedEvent(minted, 10)) // kernel commit precedes the receipt
		}
	}
	errs := len(f.errs)
	r, err := f.backend.Replace(ctx, f.binding, singlePlan())
	if !r.Committed || err == nil || strings.Contains(err.Error(), "scope") {
		t.Fatalf("live-minted scope publish %+v %v", r, err)
	}
	if instance == nil || instance.routeScope() != minted || len(f.receiver.verdicts) != 0 || len(f.errs) != errs+1 || !strings.Contains(f.errs[errs].Error(), "route scope 0") {
		t.Fatalf("pre-receipt verdicts %+v errors %v", f.receiver.verdicts, f.errs[errs:])
	}
	errs = len(f.errs)
	f.engine.route(sharedEvent(minted, 10))
	f.engine.route(sharedEvent(minted+1, 10))
	if len(f.receiver.verdicts) != 1 || *f.receiver.verdicts[0].Scope != minted || len(f.errs) != errs+1 {
		t.Fatalf("post-receipt verdicts %+v errors %v", f.receiver.verdicts, f.errs[errs:])
	}

	// Without a cookie, a zero receipt scope is a fault and nothing is
	// ever attributed; unknown-scope reports are rate-limited and counted.
	g := newSharedFixture(t)
	g.node.onBind = func(s *fakeSharedSession) { s.scope = 0; s.receiptScope = new(uint64) }
	if r, err := g.backend.Replace(ctx, g.binding, singlePlan()); !r.Committed || err == nil || !strings.Contains(err.Error(), "without a scope") {
		t.Fatalf("zero receipt scope without cookie %+v %v", r, err)
	}
	unknown := g.backend.records[key(g.binding)].instance.(*sharedInstance)
	clock := time.Unix(1000, 0)
	g.engine.now = func() time.Time { return clock }
	errs = len(g.errs)
	for range 5 {
		g.engine.route(sharedEvent(0, 10))
	}
	if unknown.routeScope() != 0 || len(g.receiver.verdicts) != 0 || len(g.errs) != errs+1 || !strings.Contains(g.errs[errs].Error(), "0 earlier verdicts suppressed") {
		t.Fatalf("unknown scope verdicts %+v errors %v", g.receiver.verdicts, g.errs[errs:])
	}
	clock = clock.Add(sharedUnboundReportInterval)
	g.engine.route(sharedEvent(9, 10))
	if len(g.receiver.verdicts) != 0 || len(g.errs) != errs+2 || !strings.Contains(g.errs[errs+1].Error(), "4 earlier verdicts suppressed") {
		t.Fatalf("rate-limited unknown scope errors %v", g.errs[errs:])
	}

	// With a protocol cookie, the scope is registered before staging and a
	// zero receipt scope is a fault; events stay checked against the cookie.
	h := newSharedFixture(t)
	h.node.onBind = func(s *fakeSharedSession) { s.receiptScope = new(uint64) }
	if r, err := h.backend.Replace(ctx, h.binding, singlePlan()); !r.Committed || err == nil || !strings.Contains(err.Error(), "without a scope") {
		t.Fatalf("zero receipt scope %+v %v", r, err)
	}
	s := h.node.sessions[0]
	registered := h.backend.records[key(h.binding)].instance.(*sharedInstance)
	errs = len(h.errs)
	h.engine.route(sharedEvent(0, 10))
	h.engine.route(sharedEvent(s.scope, 10))
	if len(h.receiver.verdicts) != 1 || registered.routeScope() != s.scope || len(h.errs) != errs+1 {
		t.Fatalf("verdicts %d scope %d errors %v", len(h.receiver.verdicts), registered.routeScope(), h.errs)
	}
}

func TestSharedEngineRateLimitsUnboundReports(t *testing.T) {
	f := newSharedFixture(t)
	now := time.Unix(1000, 0)
	f.engine.now = func() time.Time { return now }
	for range 5 {
		f.engine.route(sharedEventFor(42, 7, 1))
	}
	now = now.Add(sharedUnboundReportInterval)
	f.engine.route(sharedEventFor(43, 7, 1))
	if len(f.errs) != 2 || !strings.Contains(f.errs[1].Error(), "4 earlier unbound verdicts suppressed") {
		t.Fatalf("errors %v", f.errs)
	}
}

func TestSharedEngineRefusesMultiPolicyPlans(t *testing.T) {
	f := newSharedFixture(t)
	_, err := f.backend.Replace(context.Background(), f.binding, verdictPlan())
	if !errors.Is(err, fullruntime.ErrSharedMultiPolicyUnsupported) {
		t.Fatalf("multi-policy plan: %v", err)
	}
	s := f.node.sessions[0]
	// Nothing compiled or published; the failed activation retired the binding.
	if s.compiles != 0 || s.route != 9 || len(s.removedAt) != 1 || s.removedAt[0] != 9 || len(f.backend.records) != 0 {
		t.Fatalf("compiles %d route %d removed %v records %d", s.compiles, s.route, s.removedAt, len(f.backend.records))
	}
}

func TestSharedEngineRoutesEventsByCgroup(t *testing.T) {
	var errs []error
	node := &fakeSharedNode{}
	e := newSharedEngine(func(context.Context) (sharedNode, error) { return node, nil }, func(err error) { errs = append(errs, err) })
	ctx := context.Background()
	got := map[uint64][]RawFullVerdict{}
	plan := singlePlan()
	for _, cgroup := range []uint64{19, 29} {
		binding := sandboxpolicy.Binding{ContainerName: "app", CgroupID: cgroup, PID: 20}
		program, err := CompileFull(binding, plan, 40, nil)
		if err != nil {
			t.Fatal(err)
		}
		cgroup := cgroup
		i, err := e.Start(ctx, "x", FullStartConfig{Binding: binding, Program: program, Plan: plan, Acquire: func(context.Context) (fullruntime.BindingLease, error) { return &fullTestLease{}, nil }}, func(r RawFullVerdict) { got[cgroup] = append(got[cgroup], r) })
		if err != nil {
			t.Fatal(err)
		}
		s := node.sessions[len(node.sessions)-1]
		// Events between the kernel commit and PublishCompiled's return
		// (before any scope is known to Go) reach the right binding.
		s.onPublish = func(c fullruntime.SharedCompiled) { e.route(sharedEventFor(cgroup, s.scope, c.Generation)) }
		if p, err := i.Activate(ctx); err != nil || !p.Committed || p.Generation != 40 {
			t.Fatalf("activate %+v %v", p, err)
		}
	}
	if len(errs) != 0 || len(got[19]) != 1 || len(got[29]) != 1 || got[19][0].Generation != 40 || got[29][0].Cgroup != 29 {
		t.Fatalf("pre-receipt delivery %v errors %v", got, errs)
	}
	a, b := node.sessions[0], node.sessions[1]
	e.route(sharedEventFor(29, b.scope, 1))
	e.route(sharedEventFor(19, a.scope, 1))
	if len(got[19]) != 2 || len(got[29]) != 2 || len(errs) != 0 {
		t.Fatalf("routing %v errors %v", got, errs)
	}
	legacy := sharedEventFor(19, a.scope, 1)
	legacy.Shared = false
	for _, raw := range []RawFullVerdict{
		sharedEventFor(19, b.scope, 1), // scope mismatch: another binding's route
		sharedEventFor(39, a.scope, 1), // foreign cgroup
		sharedEventFor(19, a.scope, 2), // unknown generation
		legacy,
	} {
		e.route(raw)
	}
	if len(errs) != 4 || len(got[19]) != 2 || len(got[29]) != 2 || !strings.Contains(errs[0].Error(), "does not match") || !strings.Contains(errs[1].Error(), "unbound cgroup") {
		t.Fatalf("unroutable events delivered or unreported: %v", errs)
	}
	// One cgroup is bound at most once.
	binding := sandboxpolicy.Binding{ContainerName: "app", CgroupID: 19, PID: 20}
	program, _ := CompileFull(binding, plan, 41, nil)
	if _, err := e.Start(ctx, "dup", FullStartConfig{Binding: binding, Program: program, Plan: plan, Acquire: func(context.Context) (fullruntime.BindingLease, error) { return &fullTestLease{}, nil }}, nil); err == nil || len(node.sessions) != 2 {
		t.Fatalf("rebound cgroup: %v", err)
	}
}

func TestSharedEngineStartFailureKeepsLease(t *testing.T) {
	var starts int
	startErr := errors.New("collection refused")
	e := newSharedEngine(func(context.Context) (sharedNode, error) { starts++; return nil, startErr }, nil)
	source := &fullTestSource{lease: &fullTestLease{}}
	b, err := NewFull(e, source, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	binding := sandboxpolicy.Binding{ContainerID: "id", ContainerName: "app", CgroupID: 19, PID: 20}
	for range 2 {
		if _, err := b.Replace(context.Background(), binding, singlePlan()); !errors.Is(err, startErr) {
			t.Fatal(err)
		}
	}
	// Lazy start is retried; the untransferred lease is closed by the backend.
	if starts != 2 || source.lease.closed != 2 || len(b.records) != 0 {
		t.Fatalf("starts %d lease closed %d records %d", starts, source.lease.closed, len(b.records))
	}
	if err := b.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSharedEngineCheckNeverReady(t *testing.T) {
	f := newSharedFixture(t)
	if _, err := f.backend.Replace(context.Background(), f.binding, singlePlan()); err == nil {
		t.Fatal("shared engine confirmed protection")
	}
	if err := f.backend.Attest(context.Background(), f.binding, "combined-revision"); !errors.Is(err, fullruntime.ErrSharedNativeUnavailable) {
		t.Fatalf("attested: %v", err)
	}
}

func TestApplySharedNodeHealth(t *testing.T) {
	now := metav1.Now()
	condition := func(s *api.NodeStatus, kind string) metav1.Condition {
		for _, c := range s.Conditions {
			if c.Type == kind {
				return c
			}
		}
		t.Fatalf("no %s condition in %+v", kind, s.Conditions)
		return metav1.Condition{}
	}
	healthy := SharedNodeHealth{Started: true, Ready: fullruntime.ErrSharedNativeUnavailable, FailClosed: fullruntime.SharedFailClosedHealth{State: fullruntime.SharedFailClosedHealthy}}
	loss := healthy
	loss.Ready = errors.Join(fullruntime.ErrSharedNativeUnavailable, fmt.Errorf("lost=3: %w", fullruntime.ErrSharedVerdictEventLoss))
	loss.Counters = fullruntime.KernelEventCounters{Submitted: 10, Lost: 3}
	degraded := healthy
	degraded.FailClosed.State = fullruntime.SharedFailClosedDegraded
	notReady := healthy
	notReady.FailClosed.State = fullruntime.SharedFailClosedNotReady
	unknown := healthy
	unknown.FailClosedErr = fullruntime.ErrSharedFailClosedUnknown
	unknown.FactsErr = errors.New("facts unreadable")
	for _, tc := range []struct {
		name                    string
		health                  SharedNodeHealth
		readyReason, degradedOn string
	}{
		{"not started", SharedNodeHealth{}, "SharedNodeNotStarted", ""},
		{"healthy", healthy, "QualificationOnly", ""},
		{"event loss is Degraded only", loss, "QualificationOnly", "VerdictEventLoss"},
		{"fail-closed degraded", degraded, "QualificationOnly", "FailClosedDegraded"},
		{"fail-closed not ready", notReady, "SharedNodeNotReady", ""},
		{"unknown witness", unknown, "SharedNodeNotReady", "FactWitnessUnavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := &api.NodeStatus{Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}, {Type: "ActiveRevision", Status: metav1.ConditionTrue}}}
			ApplySharedNodeHealth(status, tc.health, 4, now)
			ready, deg := condition(status, "Ready"), condition(status, "Degraded")
			if ready.Status != metav1.ConditionFalse || ready.Reason != tc.readyReason || ready.ObservedGeneration != 4 {
				t.Fatalf("ready %+v", ready)
			}
			if (tc.degradedOn != "") != (deg.Status == metav1.ConditionTrue) || !strings.Contains(deg.Reason, tc.degradedOn) {
				t.Fatalf("degraded %+v", deg)
			}
			if len(status.Conditions) != 3 || condition(status, "ActiveRevision").Status != metav1.ConditionTrue {
				t.Fatalf("conditions %+v", status.Conditions)
			}
		})
	}
	if !strings.Contains(condition(func() *api.NodeStatus {
		s := &api.NodeStatus{}
		ApplySharedNodeHealth(s, loss, 1, now)
		return s
	}(), "Ready").Message, "lost=3") {
		t.Fatal("ready message omits verdict counters")
	}
}

func TestSharedEngineHealthReadsNode(t *testing.T) {
	node := &fakeSharedNode{ready: fullruntime.ErrSharedNativeUnavailable, counters: fullruntime.KernelEventCounters{Submitted: 2}}
	e := newSharedEngine(func(context.Context) (sharedNode, error) { return node, nil }, nil)
	if h := e.Health(); h.Started {
		t.Fatal("health started the node")
	}
	if _, err := e.ensureNode(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h := e.Health(); !h.Started || h.Counters.Submitted != 2 || h.Facts.Passes != 3 || !errors.Is(h.Ready, fullruntime.ErrSharedNativeUnavailable) {
		t.Fatalf("health %+v", h)
	}
}

func TestSharedEngineConfigDefaults(t *testing.T) {
	c := SharedEngineConfig{Image: "img:abi3-development", ContainerdAddress: "/host/run/containerd/containerd.sock"}.nodeConfig()
	if !c.ABI3Development || c.RecoveryDevelopment || c.ImageProcRoot != "/host/proc" || c.ImageHostRoot != "/host" || c.ContainerdAddress != "/host/run/containerd/containerd.sock" {
		t.Fatalf("node config %+v", c)
	}
	if !(SharedEngineConfig{Image: "img:abi3-recovery-development"}).nodeConfig().RecoveryDevelopment {
		t.Fatal("recovery image without opt-in")
	}
	if fullruntime.SharedNodeAPIVersion != SharedEngineAPIVersion {
		t.Fatalf("IG shared API %d, engine %d", fullruntime.SharedNodeAPIVersion, SharedEngineAPIVersion)
	}
}
