//go:build integration

package hostsensormanager

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	coordination "k8s.io/client-go/kubernetes/typed/coordination/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type gcIntegrationTransport struct {
	base          http.RoundTripper
	hostRequests  atomic.Int64
	leaseRequests atomic.Int64
	gcRequests    atomic.Int64
}

func (r *gcIntegrationTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Path, "/apis/"+HostDataGroup+"/") {
		r.hostRequests.Add(1)
	}
	if (strings.HasPrefix(req.URL.Path, "/api/v1/nodes") && req.Method == http.MethodGet) || (strings.Contains(req.URL.Path, "/apis/"+HostDataGroup+"/") && (req.Method == http.MethodDelete || (req.Method == http.MethodGet && strings.Count(req.URL.Path, "/") == 4))) {
		r.gcRequests.Add(1)
	}
	if strings.Contains(req.URL.Path, "/leases/") {
		r.leaseRequests.Add(1)
	}
	return r.base.RoundTrip(req)
}

type gcIntegrationSensor struct{ calls chan struct{} }

func (s gcIntegrationSensor) Sense() (any, error) {
	select {
	case s.calls <- struct{}{}:
	default:
	}
	return map[string]any{"content": "integration"}, nil
}
func (gcIntegrationSensor) GetKind() string       { return "KernelVersion" }
func (gcIntegrationSensor) GetPluralKind() string { return "kernelversions" }

// Run via tests/scripts/test-hostdata-gc.sh. An explicit kubeconfig is mandatory;
// this test creates synthetic Nodes and edits RBAC only in its disposable cluster.
func TestHostDataGCIntegration(t *testing.T) {
	path := os.Getenv("HOSTDATA_GC_KUBECONFIG")
	if path == "" {
		t.Skip("set HOSTDATA_GC_KUBECONFIG to an isolated, disposable cluster")
	}
	config, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := dynamic.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	const namespace = "gc-integration"
	token, err := admin.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, "node-agent", &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{Audiences: []string{"https://kubernetes.default.svc.cluster.local"}}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// A fresh config deliberately drops the administrator's client certificate.
	serviceConfig := &rest.Config{Host: config.Host, TLSClientConfig: rest.TLSClientConfig{CAData: config.CAData, CAFile: config.CAFile}, BearerToken: token.Status.Token, QPS: 100, Burst: 100}
	makeCollector := func(identity string) (*garbageCollector, *gcIntegrationTransport) {
		cfg := rest.CopyConfig(serviceConfig)
		counter := &gcIntegrationTransport{}
		cfg.WrapTransport = func(base http.RoundTripper) http.RoundTripper { counter.base = base; return counter }
		dc, e := dynamic.NewForConfig(cfg)
		if e != nil {
			t.Fatal(e)
		}
		lc, e := coordination.NewForConfig(cfg)
		if e != nil {
			t.Fatal(e)
		}
		return &garbageCollector{client: &CRDClient{dynamicClient: dc, nodeName: "gc-live-node"}, leases: lc, namespace: namespace, identity: identity, interval: 200 * time.Millisecond}, counter
	}
	wait := func(label string, condition func() bool) {
		t.Helper()
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			if condition() {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatalf("%s: %v", label, ctx.Err())
			case <-ticker.C:
			}
		}
	}
	kinds := map[string]string{}
	crds := objects.Resource(schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"})
	for _, resource := range hostDataResources {
		crd, e := crds.Get(ctx, resource+"."+HostDataGroup, metav1.GetOptions{})
		if e != nil {
			t.Fatal(e)
		}
		kind, _, _ := unstructured.NestedString(crd.Object, "spec", "names", "kind")
		kinds[resource] = kind
	}
	createData := func(resource, name string) *unstructured.Unstructured {
		t.Helper()
		obj, e := objects.Resource(hostDataResource(resource)).Create(ctx, &unstructured.Unstructured{Object: map[string]any{"apiVersion": HostDataGroup + "/" + HostDataVersion, "kind": kinds[resource], "metadata": map[string]any{"name": name}, "spec": map[string]any{"nodeName": name}}}, metav1.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		return obj
	}
	for _, name := range []string{"gc-live-node", "gc-dead-node"} {
		if _, err = admin.CoreV1().Nodes().Create(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		for _, resource := range hostDataResources {
			createData(resource, name)
		}
	}
	first, counter1 := makeCollector("integration-first")
	second, counter2 := makeCollector("integration-second")
	ctx1, cancel1 := context.WithCancel(ctx)
	ctx2, cancel2 := context.WithCancel(ctx)
	done1, done2 := make(chan struct{}), make(chan struct{})
	go func() { defer close(done1); first.run(ctx1) }()
	defer func() { cancel1(); <-done1 }()
	wait("first leader", func() bool { return counter1.hostRequests.Load() >= int64(len(hostDataResources)) })
	go func() { defer close(done2); second.run(ctx2) }()
	defer func() { cancel2(); <-done2 }()
	wait("follower election request", func() bool { return counter2.leaseRequests.Load() > 0 })
	if counter2.gcRequests.Load() != 0 {
		t.Fatal("follower performed host-data requests")
	}
	if err = admin.CoreV1().Nodes().Delete(ctx, "gc-dead-node", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	wait("all ten orphan records removed", func() bool {
		for _, resource := range hostDataResources {
			_, e := objects.Resource(hostDataResource(resource)).Get(ctx, "gc-dead-node", metav1.GetOptions{})
			if !apierrors.IsNotFound(e) {
				return false
			}
		}
		return true
	})
	for _, resource := range hostDataResources {
		if _, err = objects.Resource(hostDataResource(resource)).Get(ctx, "gc-live-node", metav1.GetOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if counter2.gcRequests.Load() != 0 {
		t.Fatal("follower performed GC before takeover")
	}
	cancel1()
	<-done1
	before := counter1.hostRequests.Load()
	wait("follower takes over expired Lease", func() bool { return counter2.hostRequests.Load() >= int64(len(hostDataResources)) })
	if counter1.hostRequests.Load() != before {
		t.Fatal("former leader kept collecting")
	}
	cancel2()
	<-done2
	t.Log("two collectors: follower made zero host-data requests; takeover succeeded; all ten live resources preserved and orphans deleted")

	resource := objects.Resource(hostDataResource("kernelversions"))
	original := createData("kernelversions", "gc-precondition")
	uid, rv := original.GetUID(), original.GetResourceVersion()
	original.SetLabels(map[string]string{"updated": "true"})
	if _, err = resource.Update(ctx, original, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err = resource.Delete(ctx, original.GetName(), metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}); !apierrors.IsConflict(err) {
		t.Fatalf("stale resourceVersion: wanted Conflict, got %v", err)
	}
	if err = resource.Delete(ctx, original.GetName(), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	replacement := createData("kernelversions", original.GetName())
	newRV := replacement.GetResourceVersion()
	if err = resource.Delete(ctx, original.GetName(), metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &newRV}}); !apierrors.IsConflict(err) {
		t.Fatalf("stale UID: wanted Conflict, got %v", err)
	}
	if _, err = resource.Get(ctx, original.GetName(), metav1.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Log("API server rejected stale resourceVersion and stale UID without deleting replacement")

	// Revoke only election permission; host sensing retains its production RBAC.
	if err = admin.RbacV1().RoleBindings(namespace).Delete(ctx, "node-agent-hostdata-gc", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	denied, deniedCounter := makeCollector("integration-denied")
	wait("Lease permission revoked", func() bool {
		_, e := denied.leases.Leases(namespace).Get(ctx, hostDataGCLease, metav1.GetOptions{})
		return apierrors.IsForbidden(e)
	})
	baseline := deniedCounter.leaseRequests.Load()
	calls := make(chan struct{}, 10)
	m := &manager{config: Config{Interval: 100 * time.Millisecond}, crdClient: denied.client, collector: denied, sensors: []Sensor{gcIntegrationSensor{calls: calls}}, stopCh: make(chan struct{})}
	if err = m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	wait("denied manager tries election", func() bool { return deniedCounter.leaseRequests.Load() > baseline })
	for i := 0; i < 3; i++ {
		select {
		case <-calls:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if err = m.Stop(); err != nil {
		t.Fatal(err)
	}
	if deniedCounter.gcRequests.Load() != 0 {
		t.Fatal("unelected manager issued GC API operations")
	}
	// Sensor writes legitimately touch hostdata. Election denial is established
	// independently; ensure stale data remains and fresh sensing actually persisted.
	if _, err = resource.Get(ctx, "gc-precondition", metav1.GetOptions{}); err != nil {
		t.Fatalf("denied collector removed orphan: %v", err)
	}
	live, err := resource.Get(ctx, "gc-live-node", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	content, _, _ := unstructured.NestedString(live.Object, "spec", "content")
	if content != "integration" {
		t.Fatalf("sensor write missing: %s", content)
	}
	t.Log("forbidden Lease access prevented GC while repeated sensor writes succeeded")
}
