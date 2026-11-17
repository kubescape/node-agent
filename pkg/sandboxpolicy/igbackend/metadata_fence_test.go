package igbackend

import (
	"context"
	"errors"
	"testing"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

func TestFullBackendStaleMetadataWithdrawCannotRemoveNewOwner(t *testing.T) {
	b, e, _, binding := fullBackendFixture(t)
	binding.PodUID = "new-pod"
	binding.Namespace = "ns"
	binding.PodName = "pod"
	binding.Kind = "regular"
	ctx := context.Background()
	if _, err := b.Replace(ctx, binding, verdictPlan()); err != nil {
		t.Fatal(err)
	}
	for _, stale := range []sandboxpolicy.Binding{
		func() sandboxpolicy.Binding { x := binding; x.PodUID = "old-pod"; return x }(),
		func() sandboxpolicy.Binding { x := binding; x.ContainerName = "old-container"; return x }(),
	} {
		r, err := b.Withdraw(ctx, stale)
		if err != nil || !r.Committed || e.instance.stops != 0 || len(b.records) != 1 {
			t.Fatal("stale metadata removed current owner", r, err)
		}
	}
	if r, err := b.Withdraw(ctx, binding); err != nil || !r.Committed || len(b.records) != 0 {
		t.Fatal(r, err)
	}
}

type metadataPartialLease struct {
	fullTestLease
	calls int
}

func (l *metadataPartialLease) Close() error {
	l.calls++
	if l.calls == 1 {
		return errors.New("consumed pins with OS close error")
	}
	return nil
}

type metadataPartialSource struct{ lease *metadataPartialLease }

func (s metadataPartialSource) Prepare(context.Context, sandboxpolicy.Binding) (FullBindingLease, error) {
	return s.lease, errors.New("preparation failed")
}
func TestFullBackendPartialSourceRetainsMetadataForCleanup(t *testing.T) {
	_, e, _, binding := fullBackendFixture(t)
	binding.PodUID = "pod-uid"
	lease := &metadataPartialLease{}
	b, err := NewFull(e, metadataPartialSource{lease}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Replace(context.Background(), binding, verdictPlan()); err == nil {
		t.Fatal("expected source failure")
	}
	if len(b.records) != 1 || lease.calls != 1 {
		t.Fatal("missing partial cleanup ownership")
	}
	stale := binding
	stale.PodUID = "old"
	if _, err = b.Withdraw(context.Background(), stale); err != nil || lease.calls != 1 || len(b.records) != 1 {
		t.Fatal("stale metadata consumed partial record", err)
	}
	if r, err := b.Withdraw(context.Background(), binding); err != nil || !r.Committed || len(b.records) != 0 || lease.calls != 2 {
		t.Fatal("legitimate cleanup fenced out", r, err)
	}
}
