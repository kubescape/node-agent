package containerprofilecache

import (
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// isUserDefinedContainerProfile reports whether a fetched ContainerProfile is a
// user-authored profile (the migrated "new way"), identified by the
// managed-by: User annotation — the same marker the legacy user-authored AP/NN
// carry. A learned ContainerProfile that happens to share the label-referenced
// name is deliberately NOT treated as user-defined.
func isUserDefinedContainerProfile(cp *v1beta1.ContainerProfile) bool {
	return cp != nil && cp.Annotations[helpersv1.ManagedByMetadataKey] == helpersv1.ManagedByUserValue
}

// ConvertUserProfilesToContainerProfile builds the single user-defined
// ContainerProfile equivalent to a legacy user-authored ApplicationProfile +
// NetworkNeighborhood pair, for one container.
//
// The result's Spec is exactly what projectUserProfiles produces when overlaying
// the AP+NN onto an empty base, so projecting this CP yields a byte-identical
// ProjectedContainerProfile to the legacy AP+NN overlay path — the migration is
// behaviour-preserving by construction (see usercp_diff_oracle_test.go). This is
// the migration artifact: authoring one ContainerProfile replaces the AP+NN pair.
//
// Either userAP or userNN may be nil. Metadata (name/namespace/labels and the
// managed-by/status/completion provenance annotations) is carried from whichever
// source is present; Architectures (an AP spec-level field, not projected by
// Apply) is copied for artifact completeness.
func ConvertUserProfilesToContainerProfile(userAP *v1beta1.ApplicationProfile, userNN *v1beta1.NetworkNeighborhood, pod *corev1.Pod, containerName string) *v1beta1.ContainerProfile {
	base := &v1beta1.ContainerProfile{}
	if meta := userProfileMeta(userAP, userNN); meta != nil {
		base.Name = meta.Name
		base.Namespace = meta.Namespace
		base.Annotations = copyStringMap(meta.Annotations)
		base.Labels = copyStringMap(meta.Labels)
	}
	if userAP != nil {
		base.Spec.Architectures = append([]string(nil), userAP.Spec.Architectures...)
	}

	projected, _ := projectUserProfiles(base, userAP, userNN, pod, containerName)
	return projected
}

// userProfileMeta returns the ObjectMeta to carry onto the converted CP,
// preferring the ApplicationProfile (AP and NN share name/labels/annotations for
// a user-defined pair).
func userProfileMeta(userAP *v1beta1.ApplicationProfile, userNN *v1beta1.NetworkNeighborhood) *metav1.ObjectMeta {
	if userAP != nil {
		return &userAP.ObjectMeta
	}
	if userNN != nil {
		return &userNN.ObjectMeta
	}
	return nil
}

func copyStringMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
