package hostsensormanager

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	coordinationfake "k8s.io/client-go/kubernetes/typed/coordination/v1/fake"
	"k8s.io/client-go/rest"
	clienttesting "k8s.io/client-go/testing"
)

func awaitGCSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(20 * time.Second):
		t.Fatal("timed out waiting for GC lifecycle event")
	}
}

func gcHTTPClient(t *testing.T, handler http.HandlerFunc) *CRDClient {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := dynamic.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	return &CRDClient{dynamicClient: client, nodeName: "test-node"}
}

func testLeaseClient() *coordinationfake.FakeCoordinationV1 {
	client := &coordinationfake.FakeCoordinationV1{Fake: &clienttesting.Fake{}}
	var lease *coordinationv1.Lease
	client.AddReactor("get", "leases", func(clienttesting.Action) (bool, runtime.Object, error) {
		if lease == nil {
			return true, nil, apierrors.NewNotFound(schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}, hostDataGCLease)
		}
		return true, lease.DeepCopy(), nil
	})
	client.AddReactor("create", "leases", func(a clienttesting.Action) (bool, runtime.Object, error) {
		lease = a.(clienttesting.CreateAction).GetObject().(*coordinationv1.Lease).DeepCopy()
		return true, lease.DeepCopy(), nil
	})
	client.AddReactor("update", "leases", func(a clienttesting.Action) (bool, runtime.Object, error) {
		lease = a.(clienttesting.UpdateAction).GetObject().(*coordinationv1.Lease).DeepCopy()
		return true, lease.DeepCopy(), nil
	})
	return client
}

func TestGCLeadershipCancellation(t *testing.T) {
	for _, stop := range []string{"parent", "lease loss"} {
		t.Run(stop, func(t *testing.T) {
			entered, cancelled, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			client := gcHTTPClient(t, func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				<-r.Context().Done()
				close(cancelled)
			})
			leases := testLeaseClient()
			var deny atomic.Bool
			leases.PrependReactor("update", "leases", func(a clienttesting.Action) (bool, runtime.Object, error) {
				if deny.Load() {
					return true, nil, errors.New("renewal unavailable")
				}
				return false, nil, nil
			})
			leases.PrependReactor("get", "leases", func(a clienttesting.Action) (bool, runtime.Object, error) {
				if deny.Load() {
					return true, nil, errors.New("lease unavailable")
				}
				return false, nil, nil
			})
			collector := &garbageCollector{client: client, leases: leases, namespace: "test", identity: "one", interval: time.Hour}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { defer close(done); collector.runElection(ctx) }()
			awaitGCSignal(t, entered)
			if stop == "parent" {
				cancel()
			} else {
				deny.Store(true)
			}
			awaitGCSignal(t, cancelled)
			awaitGCSignal(t, done)
		})
	}
}

func TestGCFollowerDoesNotCollect(t *testing.T) {
	leases := testLeaseClient()
	read := make(chan struct{}, 1)
	leases.PrependReactor("get", "leases", func(clienttesting.Action) (bool, runtime.Object, error) {
		select {
		case read <- struct{}{}:
		default:
		}
		holder := "another-agent"
		duration := int32(15)
		now := metav1.NowMicro()
		return true, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: hostDataGCLease, Namespace: "test"}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder, LeaseDurationSeconds: &duration, RenewTime: &now}}, nil
	})
	var requests atomic.Int32
	client := gcHTTPClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected GC request", 500)
	})
	collector := &garbageCollector{client: client, leases: leases, namespace: "test", identity: "follower", interval: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); collector.runElection(ctx) }()
	awaitGCSignal(t, read)
	cancel()
	awaitGCSignal(t, done)
	if requests.Load() != 0 {
		t.Fatalf("follower made %d GC requests", requests.Load())
	}
}

type gcTestSensor struct{ sensed chan struct{} }

func (s gcTestSensor) Sense() (any, error)   { s.sensed <- struct{}{}; return map[string]any{}, nil }
func (s gcTestSensor) GetKind() string       { return "OsReleaseFile" }
func (s gcTestSensor) GetPluralKind() string { return "osreleasefiles" }

func TestGCManagerLifecycle(t *testing.T) {
	entered, cancelled := make(chan struct{}), make(chan struct{})
	var gcCalls atomic.Int32
	client := gcHTTPClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/nodes" {
			gcCalls.Add(1)
			close(entered)
			<-r.Context().Done()
			close(cancelled)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": HostDataGroup + "/" + HostDataVersion, "kind": "OsReleaseFile", "metadata": map[string]string{"name": "test-node"}})
	})
	sensed := make(chan struct{}, 10)
	leases := testLeaseClient()
	m := &manager{config: Config{Interval: time.Hour}, crdClient: client, sensors: []Sensor{gcTestSensor{sensed}}, stopCh: make(chan struct{}),
		collector: &garbageCollector{client: client, leases: leases, namespace: "test", identity: "one", interval: time.Hour}}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitGCSignal(t, entered)
	awaitGCSignal(t, sensed)
	stopped := make(chan struct{})
	go func() { defer close(stopped); _ = m.Stop() }()
	awaitGCSignal(t, cancelled)
	awaitGCSignal(t, stopped)
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	if gcCalls.Load() != 1 {
		t.Fatalf("duplicate workers: %d", gcCalls.Load())
	}
	select {
	case <-sensed:
		t.Fatal("duplicate initial sensing")
	default:
	}
	// Start after Stop remains a no-op, not a new lifecycle.
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestGCElectionForbiddenDoesNotStopSensing(t *testing.T) {
	leases := testLeaseClient()
	attempt := make(chan struct{}, 1)
	leases.PrependReactor("get", "leases", func(clienttesting.Action) (bool, runtime.Object, error) {
		select {
		case attempt <- struct{}{}:
		default:
		}
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}, hostDataGCLease, errors.New("denied"))
	})
	var gcCalls atomic.Int32
	client := gcHTTPClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gcCalls.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"apiVersion":"hostdata.kubescape.cloud/v1beta1","kind":"OsReleaseFile","metadata":{"name":"test-node"}}`))
	})
	sensed := make(chan struct{}, 100)
	m := &manager{config: Config{Interval: 10 * time.Millisecond}, crdClient: client, sensors: []Sensor{gcTestSensor{sensed}}, stopCh: make(chan struct{}),
		collector: &garbageCollector{client: client, leases: leases, namespace: "test", identity: "one", interval: time.Hour}}
	_ = m.Start(context.Background())
	defer m.Stop()
	awaitGCSignal(t, attempt)
	awaitGCSignal(t, sensed)
	awaitGCSignal(t, sensed)
	if gcCalls.Load() != 0 {
		t.Fatal("GC ran without a lease")
	}
}

func TestGCDisabledManager(t *testing.T) {
	m, err := NewHostSensorManager(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.(*noopManager); !ok {
		t.Fatalf("disabled manager is %T", m)
	}
	_ = m.Start(context.Background())
	_ = m.Stop()
}

func TestGCNewTermCollectsImmediately(t *testing.T) {
	swept := make(chan struct{}, 2)
	client := gcHTTPClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"NodeList","items":[]}`))
		swept <- struct{}{}
	})
	collector := &garbageCollector{client: client, leases: testLeaseClient(), namespace: "test", identity: "one", interval: time.Hour}
	for range 2 {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); collector.runElection(ctx) }()
		awaitGCSignal(t, swept)
		cancel()
		awaitGCSignal(t, done)
	}
}

func TestGCSweepFailureDoesNotStopSensingOrRetry(t *testing.T) {
	swept := make(chan struct{}, 100)
	client := gcHTTPClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/nodes" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"InternalError","code":500}`))
			swept <- struct{}{}
			return
		}
		_, _ = w.Write([]byte(`{"apiVersion":"hostdata.kubescape.cloud/v1beta1","kind":"OsReleaseFile","metadata":{"name":"test-node"}}`))
	})
	sensed := make(chan struct{}, 100)
	m := &manager{config: Config{Interval: 10 * time.Millisecond}, crdClient: client, sensors: []Sensor{gcTestSensor{sensed}}, stopCh: make(chan struct{}),
		collector: &garbageCollector{client: client, leases: testLeaseClient(), namespace: "test", identity: "one", interval: 10 * time.Millisecond}}
	_ = m.Start(context.Background())
	defer m.Stop()
	awaitGCSignal(t, swept)
	awaitGCSignal(t, swept)
	awaitGCSignal(t, sensed)
	awaitGCSignal(t, sensed)
}
