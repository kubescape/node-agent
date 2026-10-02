package networkpeer

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
)

func benchService(i int) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: fmt.Sprintf("ns-%d", i%50),
			Name:      fmt.Sprintf("svc-%d", i),
			Labels:    map[string]string{"app": fmt.Sprintf("app-%d", i), "team": fmt.Sprintf("team-%d", i%20)},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:  fmt.Sprintf("10.43.%d.%d", i/256, i%256),
			ClusterIPs: []string{fmt.Sprintf("10.43.%d.%d", i/256, i%256)},
			Ports:      []corev1.ServicePort{{Name: "http", Port: 8080, Protocol: corev1.ProtocolTCP}},
		},
	}
}

func benchSlice(svcIdx, sliceIdx, endpoints int) *discoveryv1.EndpointSlice {
	eps := make([]discoveryv1.Endpoint, 0, endpoints)
	ready := true
	for e := 0; e < endpoints; e++ {
		eps = append(eps, discoveryv1.Endpoint{
			Addresses:  []string{fmt.Sprintf("10.42.%d.%d", (svcIdx*7+e)%256, (sliceIdx*31+e)%256)},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: fmt.Sprintf("ns-%d", svcIdx%50), Name: fmt.Sprintf("pod-%d-%d-%d", svcIdx, sliceIdx, e)},
			NodeName:   ptrTo(fmt.Sprintf("node-%d", e%10)),
		})
	}
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: fmt.Sprintf("ns-%d", svcIdx%50),
			Name:      fmt.Sprintf("svc-%d-%d", svcIdx, sliceIdx),
			Labels:    map[string]string{discoveryv1.LabelServiceName: fmt.Sprintf("svc-%d", svcIdx)},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   eps,
		Ports:       []discoveryv1.EndpointPort{{Name: ptrTo("http"), Port: ptrTo(int32(8080)), Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0]}},
	}
}

func ptrTo[T any](v T) *T { return &v }

// buildBenchLister backs an InformerLister with plain cache indexers (the same
// store type a SharedInformer uses) so benchmarks measure lister/resolution
// cost without fake-clientset watch machinery.
func buildBenchLister(tb testing.TB, nServices, slicesPerSvc, endpointsPerSlice int) *InformerLister {
	tb.Helper()
	svcIdx := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	sliceIdx := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	nodeIdx := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for i := 0; i < nServices; i++ {
		if err := svcIdx.Add(benchService(i)); err != nil {
			tb.Fatal(err)
		}
		for s := 0; s < slicesPerSvc; s++ {
			if err := sliceIdx.Add(benchSlice(i, s, endpointsPerSlice)); err != nil {
				tb.Fatal(err)
			}
		}
	}
	if err := nodeIdx.Add(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "bench-node"},
		Spec:       corev1.NodeSpec{PodCIDR: "10.42.0.0/24", PodCIDRs: []string{"10.42.0.0/24"}},
		Status:     corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.168.0.191"}}},
	}); err != nil {
		tb.Fatal(err)
	}
	return NewInformerLister(
		corelisters.NewServiceLister(svcIdx),
		discoverylisters.NewEndpointSliceLister(sliceIdx),
		corelisters.NewNodeLister(nodeIdx),
		"bench-node",
	)
}

// benchProfile builds a ContainerProfile with nPlain ordinary ipAddresses
// egress neighbors, nRefs serviceRef neighbors, and some opens/execs bulk so
// DeepCopy cost is realistic.
func benchProfile(nPlain, nRefs, nOpens int) *v1beta1.ContainerProfile {
	cp := &v1beta1.ContainerProfile{}
	cp.Name = "bench-cp"
	port := int32(8080)
	for i := 0; i < nPlain; i++ {
		cp.Spec.Egress = append(cp.Spec.Egress, v1beta1.NetworkNeighbor{
			Identifier:  fmt.Sprintf("plain-%d", i),
			Type:        "external",
			IPAddresses: []string{fmt.Sprintf("52.216.%d.%d", i/256, i%256)},
			Ports:       []v1beta1.NetworkPort{{Name: "TCP-8080", Protocol: "TCP", Port: &port}},
		})
	}
	for i := 0; i < nRefs; i++ {
		cp.Spec.Egress = append(cp.Spec.Egress, v1beta1.NetworkNeighbor{
			Identifier:          fmt.Sprintf("ref-%d", i),
			Type:                "internal",
			ServiceRefNamespace: fmt.Sprintf("ns-%d", i%50),
			ServiceRefName:      fmt.Sprintf("svc-%d", i),
			Ports:               []v1beta1.NetworkPort{{Name: "TCP-8080", Protocol: "TCP", Port: &port}},
		})
	}
	for i := 0; i < nOpens; i++ {
		cp.Spec.Opens = append(cp.Spec.Opens, v1beta1.OpenCalls{
			Path:  fmt.Sprintf("/usr/lib/x86_64-linux-gnu/lib-%d.so.%d", i, i%9),
			Flags: []string{"O_RDONLY", "O_CLOEXEC"},
		})
		cp.Spec.Execs = append(cp.Spec.Execs, v1beta1.ExecCalls{
			Path: fmt.Sprintf("/usr/bin/tool-%d", i),
			Args: []string{fmt.Sprintf("--flag-%d", i)},
		})
	}
	return cp
}

func BenchmarkServiceByName_1kSvc_5kSlices(b *testing.B) {
	l := buildBenchLister(b, 1000, 5, 10)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := l.ServiceByName("ns-7", "svc-7"); !ok {
			b.Fatal("service must resolve")
		}
	}
}

func BenchmarkServicesByLabels_1kSvc(b *testing.B) {
	l := buildBenchLister(b, 1000, 5, 10)
	sel := map[string]string{"app": "app-7"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if out := l.ServicesByLabels(sel, nil); len(out) != 1 {
			b.Fatalf("want 1 service, got %d", len(out))
		}
	}
}

func BenchmarkResolveIPs_ServiceRef(b *testing.B) {
	l := buildBenchLister(b, 1000, 5, 10)
	spec := PeerSpec{ServiceRef: &ServiceRef{Namespace: "ns-7", Name: "svc-7"}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ips := ResolveIPs(spec, l); len(ips) == 0 {
			b.Fatal("must resolve")
		}
	}
}

func BenchmarkResolveIPs_Entity_Host(b *testing.B) {
	l := buildBenchLister(b, 10, 1, 2)
	spec := PeerSpec{Entity: "host"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ips := ResolveIPs(spec, l); len(ips) == 0 {
			b.Fatal("must resolve")
		}
	}
}

// BenchmarkWithResolvedServiceNeighbors_NoServiceFields is the 99% case: a
// profile with only plain ipAddresses neighbors. The function documents itself
// as a no-op then — this measures whether the no-op is actually free.
func BenchmarkWithResolvedServiceNeighbors_NoServiceFields(b *testing.B) {
	l := buildBenchLister(b, 1000, 5, 10)
	for _, n := range []int{100, 1000} {
		cp := benchProfile(n, 0, 0)
		b.Run(fmt.Sprintf("plainNeighbors=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out := WithResolvedServiceNeighbors(cp, l)
				if out != cp {
					b.Fatal("no-op path must return the same pointer")
				}
			}
		})
	}
}

// BenchmarkWithResolvedServiceNeighbors_Resolving measures the full expansion:
// resolution + DeepCopy of the whole profile (opens/execs bulk included).
func BenchmarkWithResolvedServiceNeighbors_Resolving(b *testing.B) {
	l := buildBenchLister(b, 1000, 5, 10)
	for _, tc := range []struct{ plain, refs, opens int }{
		{plain: 20, refs: 1, opens: 200},
		{plain: 20, refs: 8, opens: 200},
		{plain: 20, refs: 8, opens: 2000},
	} {
		cp := benchProfile(tc.plain, tc.refs, tc.opens)
		b.Run(fmt.Sprintf("plain=%d/refs=%d/opens=%d", tc.plain, tc.refs, tc.opens), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out := WithResolvedServiceNeighbors(cp, l)
				if out == cp {
					b.Fatal("resolving path must copy")
				}
			}
		})
	}
}

func BenchmarkHasServiceNeighbors_1kPlain(b *testing.B) {
	cp := benchProfile(1000, 0, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if HasServiceNeighbors(cp) {
			b.Fatal("plain profile must not report service neighbors")
		}
	}
}

// TestInformerCacheMemoryEstimate approximates the heap retained by a
// cluster-wide Service + EndpointSlice informer cache at 1k Services / 5k
// EndpointSlices (10 endpoints each), vs Services alone. Run with -run
// InformerCacheMemoryEstimate -v.
func TestInformerCacheMemoryEstimate(t *testing.T) {
	measure := func(build func() []interface{}) uint64 {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		objs := build()
		runtime.GC()
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(objs)
		if after.HeapAlloc < before.HeapAlloc {
			return 0
		}
		return after.HeapAlloc - before.HeapAlloc
	}

	svcBytes := measure(func() []interface{} {
		idx := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		for i := 0; i < 1000; i++ {
			_ = idx.Add(benchService(i))
		}
		return []interface{}{idx}
	})
	sliceBytes := measure(func() []interface{} {
		idx := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		for i := 0; i < 1000; i++ {
			for s := 0; s < 5; s++ {
				_ = idx.Add(benchSlice(i, s, 10))
			}
		}
		return []interface{}{idx}
	})
	strippedBytes := measure(func() []interface{} {
		idx := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		for i := 0; i < 1000; i++ {
			for s := 0; s < 5; s++ {
				full := benchSlice(i, s, 10)
				stripped := &discoveryv1.EndpointSlice{
					ObjectMeta:  metav1.ObjectMeta{Namespace: full.Namespace, Name: full.Name, Labels: full.Labels},
					AddressType: full.AddressType,
				}
				for _, ep := range full.Endpoints {
					stripped.Endpoints = append(stripped.Endpoints, discoveryv1.Endpoint{Addresses: ep.Addresses})
				}
				_ = idx.Add(stripped)
			}
		}
		return []interface{}{idx}
	})
	t.Logf("1000 Services in indexer: ~%d KiB total, ~%d B/object", svcBytes/1024, svcBytes/1000)
	t.Logf("5000 EndpointSlices (10 endpoints each) in indexer: ~%d KiB total, ~%d B/object", sliceBytes/1024, sliceBytes/5000)
	t.Logf("5000 STRIPPED EndpointSlices (addresses+labels only, SetTransform mitigation): ~%d KiB total, ~%d B/object", strippedBytes/1024, strippedBytes/5000)
}
