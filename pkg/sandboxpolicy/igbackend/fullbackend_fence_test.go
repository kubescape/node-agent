package igbackend

import (
	"context"
	"errors"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

type testNativeGuard func(context.Context, sandboxpolicy.Binding) error

func (f testNativeGuard) BeforeNativeChange(ctx context.Context, b sandboxpolicy.Binding) error {
	return f(ctx, b)
}

type retainedNativeGuard struct {
	testNativeGuard
	keep func(context.Context, sandboxpolicy.Binding, string) (func(), error)
}

func (g retainedNativeGuard) RetainNativeBinding(ctx context.Context, b sandboxpolicy.Binding, revision string) (func(), error) {
	return g.keep(ctx, b, revision)
}

func TestFullBackendFenceCustodyOutlivesFailedCandidateAndCleanup(t *testing.T) {
	b, engine, source, binding := fullBackendFixture(t)
	plan := verdictPlan()
	takes, releases := 0, 0
	if err := b.SetNativeChangeGuard(retainedNativeGuard{
		testNativeGuard: func(context.Context, sandboxpolicy.Binding) error {
			if takes != 1 || releases != 0 {
				t.Fatal("destructive native operation lost exact custody")
			}
			return nil
		},
		keep: func(_ context.Context, got sandboxpolicy.Binding, revision string) (func(), error) {
			takes++
			if source.calls != 0 || !sameFullBindingMetadata(got, binding) || revision != plan.Revision {
				t.Fatal("custody must precede resources and identify exact candidate")
			}
			return func() { releases++ }, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	engine.startErr = errors.New("failed Start after Acquire")
	engine.instance.failStop = true
	if result, err := b.Replace(t.Context(), binding, plan); err == nil || result.Committed || releases != 0 {
		t.Fatalf("failed candidate lost custody or committed: %v err=%v releases=%d", result, err, releases)
	}
	if result, err := b.Withdraw(t.Context(), binding); err == nil || result.Committed || releases != 0 {
		t.Fatalf("unconfirmed stop released custody: %v err=%v releases=%d", result, err, releases)
	}
	engine.instance.failStop = false
	if result, err := b.Withdraw(t.Context(), binding); err != nil || !result.Committed || takes != 1 || releases != 1 {
		t.Fatalf("confirmed cleanup did not release once: %v err=%v takes=%d releases=%d", result, err, takes, releases)
	}
}

func TestFullBackendFenceGuard(t *testing.T) {
	ctx := context.Background()
	for _, operation := range []string{"update", "resume", "withdraw", "close"} {
		t.Run(operation, func(t *testing.T) {
			b, e, s, binding := fullBackendFixture(t)
			denied := errors.New("fence write failed")
			var block bool
			calls := 0
			if err := b.SetNativeChangeGuard(testNativeGuard(func(_ context.Context, got sandboxpolicy.Binding) error {
				calls++
				if key(got) != key(binding) {
					t.Fatal("guard lost exact binding identity")
				}
				if block {
					return denied
				}
				return nil
			})); err != nil {
				t.Fatal(err)
			}
			plan := verdictPlan()
			if operation == "resume" {
				e.instance.commitFailure = true
			}
			_, err := b.Replace(ctx, binding, plan)
			if err != nil && operation != "resume" {
				t.Fatal(err)
			}
			if err := b.SetNativeChangeGuard(nil); err == nil {
				t.Fatal("guard changed after use")
			}
			if operation != "resume" {
				if _, err := b.Replace(ctx, binding, plan); err != nil {
					t.Fatal(err)
				}
				if calls != 0 {
					t.Fatal("healthy heartbeat refenced")
				}
			}
			block = true
			switch operation {
			case "update":
				plan.Revision = "next"
				_, err = b.Replace(ctx, binding, plan)
			case "resume":
				_, err = b.Replace(ctx, binding, plan)
			case "withdraw":
				_, err = b.Withdraw(ctx, binding)
			case "close":
				err = b.Close(ctx)
			}
			if !errors.Is(err, denied) {
				t.Fatalf("missing gate error: %v", err)
			}
			if calls != 1 || e.instance.updates != 0 || e.instance.resumes != 0 || e.instance.stops != 0 || s.lease.closed != 0 {
				t.Fatalf("native work escaped guard: calls=%d instance=%+v closed=%d", calls, e.instance, s.lease.closed)
			}
			if b.records[key(binding)].instance != e.instance {
				t.Fatal("lost retained instance")
			}
			block = false
			if operation == "update" || operation == "resume" {
				if _, err = b.Replace(ctx, binding, plan); err != nil {
					t.Fatal(err)
				}
			}
			if err = b.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if e.instance.stops != 1 || s.lease.closed != 1 {
				t.Fatal("ordered cleanup not retried")
			}
		})
	}
}

func TestFullBackendFenceGeneration(t *testing.T) {
	ctx := context.Background()
	f := newProductFixture(t)
	plan := singlePlan()
	if _, err := f.backend.Replace(ctx, f.binding, plan); err != nil {
		t.Fatal(err)
	}
	generation, err := f.backend.AttestFenceGeneration(ctx, f.binding, plan.Revision)
	if err != nil || generation != 10 {
		t.Fatalf("native route generation=%d error=%v", generation, err)
	}
	record := f.backend.records[key(f.binding)]
	if generation == record.instance.Generation() {
		t.Fatal("test must distinguish backend and route generations")
	}
	for _, mutation := range []string{"revision", "metadata", "pending", "fault", "retiring", "native receipt"} {
		t.Run(mutation, func(t *testing.T) {
			binding := f.binding
			revision := plan.Revision
			switch mutation {
			case "revision":
				revision = "wrong"
			case "metadata":
				binding.ContainerName = "wrong"
			case "pending":
				record.pending = 99
				defer func() { record.pending = 0 }()
			case "fault":
				record.protocolFault = true
				defer func() { record.protocolFault = false }()
			case "retiring":
				record.retiring = true
				defer func() { record.retiring = false }()
			case "native receipt":
				f.node.sessions[0].status = func(s *fullruntime.SharedBindingStatus) { s.Attached = false }
			}
			if got, err := f.backend.AttestFenceGeneration(ctx, binding, revision); err == nil || got != 0 {
				t.Fatalf("unattested generation=%d error=%v", got, err)
			}
		})
	}
	b, _, _, binding := fullBackendFixture(t)
	if _, err := b.Replace(ctx, binding, verdictPlan()); err != nil {
		t.Fatal(err)
	}
	if got, err := b.AttestFenceGeneration(ctx, binding, verdictPlan().Revision); err == nil || got != 0 {
		t.Fatal("fabricated fake native generation")
	}
}

func TestFullBackendFenceGuardBeforeAbort(t *testing.T) {
	ctx := context.Background()
	f := newProductFixture(t)
	block := false
	denied := errors.New("fence unavailable")
	if err := f.backend.SetNativeChangeGuard(testNativeGuard(func(context.Context, sandboxpolicy.Binding) error {
		if block {
			return denied
		}
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	plan := singlePlan()
	if _, err := f.backend.Replace(ctx, f.binding, plan); err != nil {
		t.Fatal(err)
	}
	r := f.backend.records[key(f.binding)]
	i := r.instance.(*sharedInstance)
	// An unresolved candidate must not be discarded when refencing fails.
	r.pending = 99
	r.pendingRevision = "superseded"
	i.pending = 99
	block = true
	if _, err := f.backend.Replace(ctx, f.binding, plan); !errors.Is(err, denied) {
		t.Fatal(err)
	}
	if r.pending != 99 || i.pending != 99 {
		t.Fatal("pending candidate aborted before guard")
	}
}
