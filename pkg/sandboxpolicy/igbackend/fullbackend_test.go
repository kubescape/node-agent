package igbackend

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	execruntime "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

type fullTestLease struct{ closed int }

func (*fullTestLease) Check(context.Context) error                    { return nil }
func (*fullTestLease) InitProc() *os.File                             { return nil }
func (*fullTestLease) Cgroup() *os.File                               { return nil }
func (*fullTestLease) MountNamespace() *os.File                       { return nil }
func (*fullTestLease) HostMountNamespace() *os.File                   { return nil }
func (*fullTestLease) ImageOrigins() *execruntime.ImageOriginSnapshot { return nil }
func (l *fullTestLease) Close() error                                 { l.closed++; return nil }

type fullTestSource struct {
	lease *fullTestLease
	calls int
}

func (s *fullTestSource) Prepare(context.Context, sandboxpolicy.Binding) (FullBindingLease, error) {
	s.calls++
	return s.lease, nil
}

type fullTestEngine struct {
	instance *fullTestInstance
	starts   int
	startErr error
	transfer bool
}

func (e *fullTestEngine) Start(ctx context.Context, _ string, c FullStartConfig, emit func(RawFullVerdict)) (FullInstance, error) {
	e.starts++
	e.instance.program = c.Program
	e.instance.emit = emit
	if e.transfer {
		l, err := c.Acquire(ctx)
		if err != nil {
			return e.instance, err
		}
		e.instance.lease = l
	}
	return e.instance, e.startErr
}

type fullTestInstance struct {
	stallUpdate                         bool
	program                             *fullpolicy.KernelProgram
	generation, pending                 uint64
	epochs                              map[string]uint64
	failUpdate, commitFailure, failStop bool
	updates, stops, resumes             int
	lease                               fullruntime.BindingLease
	emit                                func(RawFullVerdict)
}

func (i *fullTestInstance) publish() (fullruntime.PublicationResult, error) {
	h, _ := fullpolicy.Decode[fullpolicy.KernelHeader](i.program.Entries[0])
	if i.failUpdate {
		i.failUpdate = false
		return fullruntime.PublicationResult{}, errors.New("rejected")
	}
	i.generation = h.Generation
	i.epochs = map[string]uint64{}
	for j := uint32(0); j < h.PolicyCount; j++ {
		p, _ := fullpolicy.Decode[fullpolicy.KernelPolicy](i.program.Entries[fullpolicy.KernelPolicyBase+j])
		i.epochs[i.program.Identities[p.UID]] = p.RootEpoch
	}
	if i.commitFailure {
		i.pending = h.Generation
		return fullruntime.PublicationResult{Committed: true, Generation: h.Generation}, errors.New("finalization")
	}
	i.pending = 0
	return fullruntime.PublicationResult{Committed: true, Generation: h.Generation, Admitting: true}, nil
}
func (i *fullTestInstance) Activate(context.Context) (fullruntime.PublicationResult, error) {
	return i.publish()
}
func (i *fullTestInstance) Update(ctx context.Context, p *fullpolicy.KernelProgram) (fullruntime.PublicationResult, error) {
	i.updates++
	if i.stallUpdate {
		<-ctx.Done()
		return fullruntime.PublicationResult{}, ctx.Err()
	}
	i.program = p
	return i.publish()
}
func (i *fullTestInstance) Resume(context.Context) (fullruntime.PublicationResult, error) {
	i.resumes++
	i.commitFailure = false
	return i.publish()
}
func (i *fullTestInstance) Generation() uint64        { return i.generation }
func (i *fullTestInstance) PendingGeneration() uint64 { return i.pending }
func (i *fullTestInstance) Detached() bool            { return i.lease == nil && i.stops > 0 && !i.failStop }
func (i *fullTestInstance) Epochs() map[string]uint64 { return i.epochs }
func (i *fullTestInstance) Check(context.Context) error {
	if i.pending != 0 {
		return errors.New("closed gate")
	}
	return nil
}
func (i *fullTestInstance) Stop(context.Context) error {
	i.stops++
	if i.failStop {
		return errors.New("drain")
	}
	if i.lease != nil {
		err := i.lease.Close()
		i.lease = nil
		return err
	}
	return nil
}
func fullBackendFixture(t *testing.T) (*FullBackend, *fullTestEngine, *fullTestSource, sandboxpolicy.Binding) {
	t.Helper()
	e := &fullTestEngine{instance: &fullTestInstance{}, transfer: true}
	s := &fullTestSource{lease: &fullTestLease{}}
	b, err := NewFull(e, s, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return b, e, s, sandboxpolicy.Binding{Runtime: "containerd", ContainerID: "id", ContainerName: "app", CgroupID: 19, PID: 20, MountNamespace: 21}
}
func TestFullBackendPersistentReloadAndResume(t *testing.T) {
	b, e, s, binding := fullBackendFixture(t)
	ctx := context.Background()
	p := verdictPlan()
	r, err := b.Replace(ctx, binding, p)
	if err != nil || !r.Committed {
		t.Fatal(r, err)
	}
	original := e.instance.epochs["uid-one"]
	p.Revision = "next"
	p.Policies[0].Revision = "policy-next"
	e.instance.commitFailure = true
	r, err = b.Replace(ctx, binding, p)
	if err == nil || !r.Committed || !r.ProtectionUnconfirmed || r.ActiveRevision != "next" {
		t.Fatal(r, err)
	}
	generation := e.instance.generation
	r, err = b.Replace(ctx, binding, p)
	if err != nil || !r.Committed || r.ProtectionUnconfirmed || e.instance.generation != generation || e.instance.resumes != 1 {
		t.Fatal(r, err)
	}
	if e.starts != 1 || s.calls != 1 || e.instance.updates != 1 || e.instance.epochs["uid-one"] != original {
		t.Fatal("owner or role epoch reset")
	}
	r, err = b.Replace(ctx, binding, p)
	if err != nil || !r.Committed || e.instance.updates != 1 {
		t.Fatal(r, err)
	}
}
func TestFullBackendRejectedRevisionKeepsLastGood(t *testing.T) {
	b, e, _, binding := fullBackendFixture(t)
	ctx := context.Background()
	p := verdictPlan()
	if _, err := b.Replace(ctx, binding, p); err != nil {
		t.Fatal(err)
	}
	old := e.instance.generation
	p.Revision = "bad"
	e.instance.failUpdate = true
	r, err := b.Replace(ctx, binding, p)
	if err == nil || r.Committed || r.ProtectionUnconfirmed || e.instance.generation != old {
		t.Fatal(r, err)
	}
	p.Revision = "good"
	r, err = b.Replace(ctx, binding, p)
	if err != nil || !r.Committed || e.starts != 1 {
		t.Fatal(r, err)
	}
}
func TestFullBackendRetainsFailedStartupAndUntransferredLease(t *testing.T) {
	for _, transfer := range []bool{false, true} {
		t.Run(map[bool]string{false: "untransferred", true: "transferred"}[transfer], func(t *testing.T) {
			b, e, s, binding := fullBackendFixture(t)
			ctx := context.Background()
			e.transfer = transfer
			e.startErr = errors.New("startup")
			e.instance.failStop = true
			if _, err := b.Replace(ctx, binding, verdictPlan()); err == nil {
				t.Fatal("accepted failed startup")
			}
			if s.lease.closed != 0 || len(b.records) != 1 {
				t.Fatal("released resources before confirmed cleanup")
			}
			if r, err := b.Withdraw(ctx, binding); err == nil || r.Committed {
				t.Fatal(r, err)
			}
			e.instance.failStop = false
			if r, err := b.Withdraw(ctx, binding); err != nil || !r.Committed {
				t.Fatal(r, err)
			}
			if s.lease.closed != 1 || len(b.records) != 0 {
				t.Fatal("leaked or double closed lease")
			}
		})
	}
}

func TestFullBackendRetiringOwnerIsNotHealthyLastGood(t *testing.T) {
	b, e, _, binding := fullBackendFixture(t)
	ctx := context.Background()
	p := verdictPlan()
	if _, err := b.Replace(ctx, binding, p); err != nil {
		t.Fatal(err)
	}
	e.instance.failStop = true
	if _, err := b.Withdraw(ctx, binding); err == nil {
		t.Fatal("expected stop refusal")
	}
	r, err := b.Replace(ctx, binding, p)
	if err == nil || r.Committed || !r.ProtectionUnconfirmed {
		t.Fatal(r, err)
	}
}

func TestFullBackendBoundsStalledPublication(t *testing.T) {
	b, e, _, binding := fullBackendFixture(t)
	ctx := context.Background()
	p := verdictPlan()
	if _, err := b.Replace(ctx, binding, p); err != nil {
		t.Fatal(err)
	}
	old := e.instance.Generation()
	b.operationTimeout = 20 * time.Millisecond
	e.instance.stallUpdate = true
	p.Revision = "stalled"
	started := time.Now()
	r, err := b.Replace(ctx, binding, p)
	if !errors.Is(err, context.DeadlineExceeded) || r.Committed || e.instance.Generation() != old || time.Since(started) > time.Second {
		t.Fatal(r, err)
	}
	e.instance.stallUpdate = false
	r, err = b.Replace(ctx, binding, p)
	if err != nil || !r.Committed || e.starts != 1 {
		t.Fatal(r, err)
	}
}
