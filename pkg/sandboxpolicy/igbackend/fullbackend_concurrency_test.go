package igbackend

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

type independentFullSource struct {
	blocked          uint64
	entered, release chan struct{}
}

func (s *independentFullSource) Prepare(ctx context.Context, b sandboxpolicy.Binding) (FullBindingLease, error) {
	if b.CgroupID == s.blocked {
		close(s.entered)
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &fullTestLease{}, nil
}

type independentFullEngine struct{}

func (*independentFullEngine) Start(ctx context.Context, name string, c FullStartConfig, emit func(RawFullVerdict)) (FullInstance, error) {
	e := &fullTestEngine{instance: &fullTestInstance{}, transfer: true}
	return e.Start(ctx, name, c, emit)
}
func TestFullBackendBlockedBindingDoesNotBlockNeighbor(t *testing.T) {
	_, _, _, a := fullBackendFixture(t)
	neighbor := a
	neighbor.CgroupID++
	neighbor.ContainerID = "neighbor"
	s := &independentFullSource{blocked: a.CgroupID, entered: make(chan struct{}), release: make(chan struct{})}
	b, err := NewFull(&independentFullEngine{}, s, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err = b.Replace(ctx, neighbor, verdictPlan()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := b.Replace(ctx, a, verdictPlan()); done <- err }()
	<-s.entered
	defer func() {
		close(s.release)
		if err := <-done; err != nil {
			t.Error(err)
		}
		if err := b.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	neighborDone := make(chan error, 1)
	go func() {
		p := verdictPlan()
		p.Revision = "neighbor-next"
		_, err := b.Replace(ctx, neighbor, p)
		if err == nil {
			_, err = b.Withdraw(ctx, neighbor)
		}
		neighborDone <- err
	}()
	select {
	case err := <-neighborDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Error("blocked binding prevented independent update/withdrawal")
	}
}

func TestFullBackendWithdrawCancelsPreparationAndReservesCgroup(t *testing.T) {
	_, _, _, binding := fullBackendFixture(t)
	s := &independentFullSource{blocked: binding.CgroupID, entered: make(chan struct{}), release: make(chan struct{})}
	b, _ := NewFull(&independentFullEngine{}, s, nil, nil)
	done := make(chan error, 1)
	go func() { _, err := b.Replace(context.Background(), binding, verdictPlan()); done <- err }()
	<-s.entered
	other := binding
	other.ContainerID = "reused-cgroup"
	if _, err := b.Replace(context.Background(), other, verdictPlan()); err == nil {
		t.Fatal("admitted cgroup reserved by in-flight preparation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := b.Withdraw(ctx, binding)
	if err != nil || !result.Committed {
		t.Fatal(result, err)
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("preparation not canceled: %v", err)
	}
	s.blocked = 0
	if result, err := b.Replace(ctx, other, verdictPlan()); err != nil || !result.Committed {
		t.Fatal(result, err)
	}
	if err := b.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestFullBackendSameBindingWaitCancelsWithoutStoppingOwner(t *testing.T) {
	_, _, _, binding := fullBackendFixture(t)
	s := &independentFullSource{blocked: binding.CgroupID, entered: make(chan struct{}), release: make(chan struct{})}
	b, _ := NewFull(&independentFullEngine{}, s, nil, nil)
	done := make(chan error, 1)
	go func() { _, err := b.Replace(context.Background(), binding, verdictPlan()); done <- err }()
	<-s.entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := b.Replace(ctx, binding, verdictPlan()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait did not honor deadline: %v", err)
	}
	close(s.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := b.Attest(context.Background(), binding, verdictPlan().Revision); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type closingFullEngine struct {
	fullTestEngine
	closes   int
	closeErr error
}

func (e *closingFullEngine) Close(context.Context) error {
	e.closes++
	if e.instance.stops == 0 || e.instance.lease != nil {
		return errors.New("engine closed before instance drained")
	}
	return e.closeErr
}
func TestFullBackendEngineCloseRetainsOwnershipUntilSuccess(t *testing.T) {
	_, _, _, binding := fullBackendFixture(t)
	lease := &fullTestLease{}
	e := &closingFullEngine{fullTestEngine: fullTestEngine{instance: &fullTestInstance{}, transfer: true}}
	b, _ := NewFull(e, &fullTestSource{lease: lease}, nil, nil)
	ctx := context.Background()
	if _, err := b.Replace(ctx, binding, verdictPlan()); err != nil {
		t.Fatal(err)
	}
	e.instance.failStop = true
	if err := b.Close(ctx); err == nil || e.closes != 0 || lease.closed != 0 {
		t.Fatal("engine/source released before failed binding cleanup", err)
	}
	if _, err := b.Replace(ctx, binding, verdictPlan()); err == nil {
		t.Fatal("closed backend admitted binding")
	}
	e.instance.failStop = false
	e.closeErr = errors.New("shared collection drain")
	if err := b.Close(ctx); err == nil || e.closes != 1 || lease.closed != 1 {
		t.Fatal("failed engine cleanup lost ownership", err)
	}
	if _, err := b.Replace(ctx, binding, verdictPlan()); err == nil {
		t.Fatal("engine cleanup failure reopened backend")
	}
	e.closeErr = nil
	if err := b.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if e.closes != 2 || e.instance.stops != 2 || lease.closed != 1 {
		t.Fatalf("duplicate successful cleanup: engine=%d stop=%d lease=%d", e.closes, e.instance.stops, lease.closed)
	}
}

func TestFullBackendCloseCancelsPreparation(t *testing.T) {
	_, _, _, binding := fullBackendFixture(t)
	s := &independentFullSource{blocked: binding.CgroupID, entered: make(chan struct{}), release: make(chan struct{})}
	b, _ := NewFull(&independentFullEngine{}, s, nil, nil)
	done := make(chan error, 1)
	go func() { _, err := b.Replace(context.Background(), binding, verdictPlan()); done <- err }()
	<-s.entered
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := b.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(b.records) != 0 {
		t.Fatal("preparation reservation leaked")
	}
}

func TestFullBackendStaleRecordCannotDeleteReplacement(t *testing.T) {
	b, _, _, binding := fullBackendFixture(t)
	old, _, err := b.lockRecord(context.Background(), binding, true)
	if err != nil {
		t.Fatal(err)
	}
	replacement := &fullRecord{binding: old.binding}
	b.mu.Lock()
	b.records[key(binding)] = replacement
	b.mu.Unlock()
	b.unlockRecord(key(binding), old)
	if b.records[key(binding)] != replacement {
		t.Fatal("stale operation deleted replacement record")
	}
}

type activationErrorInstance struct{ FullInstance }

func (i activationErrorInstance) Activate(ctx context.Context) (fullruntime.PublicationResult, error) {
	result, err := i.FullInstance.Activate(ctx)
	return result, errors.Join(err, errors.New("activation acknowledgement failed"))
}

type activationErrorEngine struct{ independentFullEngine }

func (e *activationErrorEngine) Start(ctx context.Context, name string, c FullStartConfig, emit func(RawFullVerdict)) (FullInstance, error) {
	instance, err := e.independentFullEngine.Start(ctx, name, c, emit)
	return activationErrorInstance{instance}, err
}

// Preserve first-publication errors even if the generation committed and its
// read-only health check succeeds. Neither fact erases a native operation error.
func TestFullBackendInitialPublicationErrorIsNotLost(t *testing.T) {
	_, _, _, binding := fullBackendFixture(t)
	b, err := NewFull(&activationErrorEngine{}, &independentFullSource{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := b.Replace(context.Background(), binding, verdictPlan())
	if err == nil || !result.Committed {
		t.Fatal(result, err)
	}
	if err := b.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type blockingUpdateInstance struct {
	*fullTestInstance
	entered, release chan struct{}
}

func (i *blockingUpdateInstance) Update(ctx context.Context, p *fullpolicy.KernelProgram) (fullruntime.PublicationResult, error) {
	close(i.entered)
	select {
	case <-i.release:
	case <-ctx.Done():
		return fullruntime.PublicationResult{}, ctx.Err()
	}
	return i.fullTestInstance.Update(ctx, p)
}

type qualificationEngine struct {
	blocked  uint64
	instance *blockingUpdateInstance
}

func (e *qualificationEngine) Start(ctx context.Context, name string, c FullStartConfig, emit func(RawFullVerdict)) (FullInstance, error) {
	base, err := (&independentFullEngine{}).Start(ctx, name, c, emit)
	if c.Binding.CgroupID != e.blocked {
		return base, err
	}
	e.instance.fullTestInstance = base.(*fullTestInstance)
	return e.instance, err
}
func TestFullBackendBlockedQualificationDoesNotBlockNeighbor(t *testing.T) {
	_, _, _, a := fullBackendFixture(t)
	neighbor := a
	neighbor.CgroupID++
	neighbor.ContainerID = "neighbor"
	i := &blockingUpdateInstance{entered: make(chan struct{}), release: make(chan struct{})}
	e := &qualificationEngine{blocked: a.CgroupID, instance: i}
	b, _ := NewFull(e, &independentFullSource{}, nil, nil)
	ctx := context.Background()
	for _, binding := range []sandboxpolicy.Binding{a, neighbor} {
		if _, err := b.Replace(ctx, binding, verdictPlan()); err != nil {
			t.Fatal(err)
		}
	}
	original := i.epochs["uid-one"]
	done := make(chan error, 1)
	go func() { p := verdictPlan(); p.Revision = "blocked-update"; _, err := b.Replace(ctx, a, p); done <- err }()
	<-i.entered
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	p := verdictPlan()
	p.Revision = "neighbor-update"
	if result, err := b.Replace(bounded, neighbor, p); err != nil || !result.Committed {
		t.Fatal(result, err)
	}
	if result, err := b.Withdraw(bounded, neighbor); err != nil || !result.Committed {
		t.Fatal(result, err)
	}
	if result, err := b.Withdraw(bounded, a); err != nil || !result.Committed {
		t.Fatal(result, err)
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if i.epochs["uid-one"] != original || i.updates != 0 {
		t.Fatal("canceled qualification changed accepted history")
	}
	if err := b.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestFullBackendStaleWithdrawDoesNotStopReplacement(t *testing.T) {
	b, _, _, binding := fullBackendFixture(t)
	old, _, err := b.lockRecord(context.Background(), binding, true)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { _, err := b.Withdraw(ctx, binding); done <- err }()
	// Observe the withdrawal's captured old identity while it waits on old.mu.
	for {
		b.mu.Lock()
		draining := old.draining
		b.mu.Unlock()
		if draining {
			break
		}
		select {
		case <-ctx.Done():
			old.mu.Unlock()
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	instance := &fullTestInstance{}
	replacement := &fullRecord{binding: old.binding, instance: instance}
	b.mu.Lock()
	b.records[key(binding)] = replacement
	b.mu.Unlock()
	old.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if b.records[key(binding)] != replacement || instance.stops != 0 {
		t.Fatal("stale withdrawal consumed replacement")
	}
	if err := b.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestFullBackendFreshReplaceRecoversFailedWithdrawal(t *testing.T) {
	_, _, _, binding := fullBackendFixture(t)
	e, s := &controllerIdentityEngine{}, &controllerIdentitySource{}
	b, err := NewFull(e, s, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := b.Replace(ctx, binding, verdictPlan()); err != nil {
		t.Fatal(err)
	}
	old := b.records[key(binding)]
	e.instances[0].failStop = true
	if result, err := b.Withdraw(ctx, binding); err == nil || result.Committed {
		t.Fatal(result, err)
	}
	if result, err := b.Replace(ctx, binding, verdictPlan()); err == nil || result.Committed || !result.ProtectionUnconfirmed || len(e.instances) != 1 || s.leases[0].closed != 0 {
		t.Fatal("failed retirement was reopened", result, err)
	}
	e.instances[0].failStop = false
	defer func() {
		if err := b.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	result, err := b.Replace(ctx, binding, verdictPlan())
	if err != nil || !result.Committed || result.ProtectionUnconfirmed {
		t.Fatal("fresh replacement cannot recover failed withdrawal", result, err)
	}
	if len(e.instances) != 2 || len(s.leases) != 2 || s.leases[0].closed != 1 || s.leases[1].closed != 0 || b.records[key(binding)] == old {
		t.Fatal("recovery did not retire old ownership before creating new record")
	}
}

// Signal the lock wait after lockRecord has captured its registry identity and
// drain sequence. This makes the queued-before-withdraw ordering deterministic.
type fullRecordWaitContext struct {
	context.Context
	checks  int
	waiting chan struct{}
}

func (c *fullRecordWaitContext) Err() error {
	c.checks++
	if c.checks == 2 {
		close(c.waiting)
	}
	return c.Context.Err()
}
func TestFullBackendPredrainWaiterCannotReopenRetirement(t *testing.T) {
	_, _, _, binding := fullBackendFixture(t)
	e, s := &controllerIdentityEngine{}, &controllerIdentitySource{}
	b, err := NewFull(e, s, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := b.Replace(ctx, binding, verdictPlan()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := b.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	old := b.records[key(binding)]
	old.mu.Lock()
	queued := &fullRecordWaitContext{Context: ctx, waiting: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		r, _, err := b.lockRecord(queued, binding, true)
		if err == nil {
			b.unlockRecord(key(binding), r)
		}
		done <- err
	}()
	<-queued.waiting
	bounded, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	result, err := b.Withdraw(bounded, binding)
	cancel()
	old.mu.Unlock()
	if !errors.Is(err, context.DeadlineExceeded) || result.Committed {
		t.Fatal(result, err)
	}
	if err := <-done; err == nil {
		t.Fatal("pre-drain waiter admitted after withdrawal")
	}
	if e.instances[0].stops != 0 {
		t.Fatal("timed-out withdrawal stopped locked owner")
	}
	replacement, err := b.Replace(ctx, binding, verdictPlan())
	if err != nil || !replacement.Committed || replacement.ProtectionUnconfirmed || len(e.instances) != 2 || b.records[key(binding)] == old || s.leases[0].closed != 1 {
		t.Fatal("fresh request failed to recover timed-out drain", replacement, err)
	}
}
