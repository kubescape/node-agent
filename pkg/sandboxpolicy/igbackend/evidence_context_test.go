package igbackend

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/namespaces"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

type evidenceCaller struct {
	context.Context
	deadline time.Time
	finished atomic.Bool
	late     atomic.Int32
}

func (c *evidenceCaller) touch() {
	if c.finished.Load() {
		c.late.Add(1)
	}
}
func (c *evidenceCaller) Value(any) any { panic("caller Value must never be consulted") }
func (c *evidenceCaller) Deadline() (time.Time, bool) {
	c.touch()
	if !c.deadline.IsZero() {
		return c.deadline, true
	}
	return c.Context.Deadline()
}
func (c *evidenceCaller) Done() <-chan struct{} { c.touch(); return c.Context.Done() }
func (c *evidenceCaller) Err() error            { c.touch(); return c.Context.Err() }

func TestEvidenceContextDetachedValuesAndFinish(t *testing.T) {
	caller := &evidenceCaller{Context: context.Background(), deadline: time.Now().Add(time.Hour)}
	owned, finish := newEvidenceContext(caller)
	downstream := namespaces.WithNamespace(owned, "k8s.io")
	if downstream.Value(struct{}{}) != nil {
		t.Fatal("caller values retained")
	}
	if ns, ok := namespaces.Namespace(downstream); !ok || ns != "k8s.io" {
		t.Fatal("trusted namespace missing")
	}
	if d, ok := downstream.Deadline(); !ok || !d.Equal(caller.deadline) {
		t.Fatal("deadline metadata lost")
	}
	finish()
	caller.finished.Store(true)
	finish()
	if downstream.Err() != context.Canceled {
		t.Fatal("retained downstream context not canceled")
	}
	_ = downstream.Value(struct{}{})
	_, _ = downstream.Deadline()
	<-downstream.Done()
	if caller.late.Load() != 0 {
		t.Fatal("caller accessed after finish")
	}
}

func TestEvidenceContextCancellationReasons(t *testing.T) {
	for _, kind := range []string{"canceled", "deadline", "canceled-before-expired-deadline"} {
		t.Run(kind, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			expected := context.Canceled
			caller := &evidenceCaller{Context: parent}
			if kind == "deadline" {
				expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer stop()
				caller.Context = expired
				expected = context.DeadlineExceeded
			} else {
				cancel()
				if kind == "canceled-before-expired-deadline" {
					caller.deadline = time.Now().Add(-time.Second)
				}
			}
			owned, finish := newEvidenceContext(caller)
			defer finish()
			if owned.Err() != expected {
				t.Fatalf("reason changed: %v", owned.Err())
			}
			finish()
			if owned.Err() != expected {
				t.Fatal("finish replaced cancellation reason")
			}
		})
	}
	for range 100 {
		parent, cancel := context.WithCancel(context.Background())
		caller := &evidenceCaller{Context: parent}
		owned, finish := newEvidenceContext(caller)
		cancel()
		finish()
		caller.finished.Store(true)
		if owned.Err() != context.Canceled || caller.late.Load() != 0 {
			t.Fatal("cancellation/finish race")
		}
	}
	parent, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	owned, finish := newEvidenceContext(&evidenceCaller{Context: parent})
	defer finish()
	select {
	case <-owned.Done():
	case <-time.After(time.Second):
		t.Fatal("deadline did not propagate")
	}
	if owned.Err() != context.DeadlineExceeded {
		t.Fatal("deadline reason lost")
	}
}

type evidenceRetainingStore struct {
	containers.Store
	retained context.Context
	err      error
}

func (s *evidenceRetainingStore) Get(ctx context.Context, _ string) (containers.Container, error) {
	s.retained = ctx
	return containers.Container{}, s.err
}
func TestEvidenceRealEntryDetachesAcquisitionAndReattestation(t *testing.T) {
	store := &evidenceRetainingStore{err: errors.New("observation unavailable")}
	client, err := containerd.New("", containerd.WithServices(containerd.WithContainerStore(store)))
	if err != nil {
		t.Fatal(err)
	}
	source := &containerdImageSource{client: client}
	process := &linuxLease{identity: sandboxpolicy.Binding{Runtime: "containerd", ContainerID: strings.Repeat("a", 64), PID: 42}}
	for _, reattest := range []bool{false, true} {
		caller := &evidenceCaller{Context: context.Background()}
		store.retained = nil
		if reattest {
			lease := &trustedImageLease{source: source, process: process}
			err = lease.CheckContext(caller)
		} else {
			_, err = acquireImageEvidence(caller, source, process, "/", ImageIndexLimits{})
		}
		if err == nil || store.retained == nil {
			t.Fatal("actual source boundary not exercised")
		}
		caller.finished.Store(true)
		if store.retained.Err() != context.Canceled || store.retained.Value(struct{}{}) != nil {
			t.Fatal("real Evidence leaked caller context")
		}
		if namespace, ok := namespaces.Namespace(store.retained); !ok || namespace != "k8s.io" {
			t.Fatal("trusted namespace missing")
		}
		if caller.late.Load() != 0 {
			t.Fatal("bridge accessed caller after Evidence returned")
		}
	}
	caller := &evidenceCaller{Context: context.Background()}
	if _, err := source.Evidence(caller, "invalid"); err == nil {
		t.Fatal("invalid ID accepted")
	}
	caller.finished.Store(true)
	if caller.late.Load() != 0 {
		t.Fatal("early-return bridge not joined")
	}
}

type evidenceBlockingCaller struct {
	context.Context
	calls            atomic.Int32
	entered, release chan struct{}
	finished         atomic.Bool
	late             atomic.Int32
}

func (c *evidenceBlockingCaller) Err() error {
	if c.finished.Load() {
		c.late.Add(1)
	}
	if c.calls.Add(1) == 2 {
		close(c.entered)
		<-c.release
	}
	return c.Context.Err()
}
func TestEvidenceContextFinishJoinsCallerAccess(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	caller := &evidenceBlockingCaller{Context: parent, entered: make(chan struct{}), release: make(chan struct{})}
	owned, finish := newEvidenceContext(caller)
	cancel()
	<-caller.entered
	finished := make(chan struct{})
	go func() { finish(); close(finished) }()
	select {
	case <-finished:
		t.Fatal("finish returned while bridge still accesses caller")
	case <-time.After(20 * time.Millisecond):
	}
	close(caller.release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("bridge did not join")
	}
	caller.finished.Store(true)
	finish()
	if owned.Err() != context.Canceled || caller.late.Load() != 0 {
		t.Fatal("caller access after joined return")
	}
}

func TestEvidenceContextHasNoCallerReferenceFields(t *testing.T) {
	typ := reflect.TypeFor[evidenceContext]()
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Type.Implements(reflect.TypeFor[context.Context]()) || f.Type.Kind() == reflect.Func || f.Type.Kind() == reflect.Pointer {
			t.Fatalf("provider context retains caller/bridge-capable field %s", f.Name)
		}
	}
}

func TestEvidenceContextRealEntrySourceGuard(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "imageevidence.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var evidence *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "Evidence" {
			evidence = fn
		}
	}
	if evidence == nil || len(evidence.Body.List) < 3 {
		t.Fatal("missing real Evidence entry")
	}
	assignment, ok := evidence.Body.List[0].(*ast.AssignStmt)
	if !ok || len(assignment.Lhs) != 2 || len(assignment.Rhs) != 1 {
		t.Fatal("Evidence does not detach on entry")
	}
	call, ok := assignment.Rhs[0].(*ast.CallExpr)
	if !ok {
		t.Fatal("missing context constructor")
	}
	name, ok := call.Fun.(*ast.Ident)
	if !ok || name.Name != "newEvidenceContext" {
		t.Fatal("wrong context constructor")
	}
	left, ok := assignment.Lhs[0].(*ast.Ident)
	if !ok || left.Name != "ctx" {
		t.Fatal("downstream context not replaced")
	}
	finish, ok := assignment.Lhs[1].(*ast.Ident)
	if !ok {
		t.Fatal("missing finish owner")
	}
	deferred, ok := evidence.Body.List[1].(*ast.DeferStmt)
	if !ok {
		t.Fatal("early returns can escape without join")
	}
	joined, ok := deferred.Call.Fun.(*ast.Ident)
	if !ok || joined.Name != finish.Name {
		t.Fatal("wrong deferred owner")
	}
}

type evidenceForeignDeadline struct {
	context.Context
	deadline time.Time
	present  bool
}

func (c evidenceForeignDeadline) Deadline() (time.Time, bool) { return c.deadline, c.present }
func TestEvidenceContextDeadlineDoesNotRetainForeignLocation(t *testing.T) {
	location := time.FixedZone(strings.Repeat("caller-owned-zone-", 1<<16), 3600)
	deadline := time.Now().Add(time.Hour).In(location)
	for _, present := range []bool{true, false} {
		t.Run(fmt.Sprint(present), func(t *testing.T) {
			owned, finish := newEvidenceContext(evidenceForeignDeadline{Context: context.Background(), deadline: deadline, present: present})
			defer finish()
			got, ok := owned.Deadline()
			if ok != present {
				t.Fatal("deadline presence changed")
			}
			if got.Location() == location {
				t.Fatal("provider deadline retains caller-owned location")
			}
			if present {
				if !got.Equal(deadline) || got.Location() != time.UTC {
					t.Fatal("normalized deadline changed instant or retained zone")
				}
			} else if !got.IsZero() {
				t.Fatal("absent deadline retains unused metadata")
			}
			finish()
			if owned.Err() != context.Canceled {
				t.Fatal("normalization changed finish cancellation")
			}
		})
	}
}
