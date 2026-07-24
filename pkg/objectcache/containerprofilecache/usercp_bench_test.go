package containerprofilecache

import (
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BenchmarkProjection_Legacy vs BenchmarkProjection_UserDefinedCP measure the
// per-container projection cost of the two paths on the full user-defined shape
// (opens/exec wildcards, endpoints, egress/ingress + selector):
//
//	Legacy:  overlay user AP + user NN onto an empty base, then Apply.
//	New:     the converted ContainerProfile is the base — Apply with no overlay.
//
// The new path skips the two-object merge (projectUserProfiles fast-returns a
// DeepCopy when both user inputs are nil), so it does strictly less work per
// projection — which the reconciler runs on every changed tick.
func BenchmarkProjection_Legacy(b *testing.B) {
	tc := oracleCases()[0] // full_ap_and_nn
	pod := podWith("curl")
	base := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "base", Namespace: "demo"}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		legacyCP, _ := projectUserProfiles(base, tc.ap, tc.nn, pod, tc.containerName)
		_ = Apply(nil, legacyCP, nil)
	}
}

func BenchmarkProjection_UserDefinedCP(b *testing.B) {
	tc := oracleCases()[0] // full_ap_and_nn
	pod := podWith("curl")
	userCP := ConvertUserProfilesToContainerProfile(tc.ap, tc.nn, pod, tc.containerName)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		newCP, _ := projectUserProfiles(userCP, nil, nil, pod, tc.containerName)
		_ = Apply(nil, newCP, nil)
	}
}
