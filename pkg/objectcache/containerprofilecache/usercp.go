package containerprofilecache

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConvertUserProfilesToContainerProfile builds the single user-defined
// ContainerProfile equivalent to a legacy user-authored ApplicationProfile +
// NetworkNeighborhood pair, for one container.
//
// The result carries ONLY name + namespace and the merged Spec. A user-managed
// ContainerProfile has no learning-lifecycle annotations (status/completion) and
// no managed-by marker — those are meaningless on an authored profile: the pod's
// kubescape.io/user-defined-profile label is what declares it user-authored, and
// a signature (added later by the signing tooling) is the integrity marker.
//
// The Spec is exactly what projectUserProfiles produces overlaying the AP+NN onto
// an empty base, so projecting this CP yields a byte-identical
// ProjectedContainerProfile to the legacy overlay path (see the diff oracle).
// Either userAP or userNN may be nil.
func ConvertUserProfilesToContainerProfile(userAP *v1beta1.ApplicationProfile, userNN *v1beta1.NetworkNeighborhood, pod *corev1.Pod, containerName string) *v1beta1.ContainerProfile {
	base := &v1beta1.ContainerProfile{}
	if meta := userProfileMeta(userAP, userNN); meta != nil {
		base.Name = meta.Name
		base.Namespace = meta.Namespace
	}
	if userAP != nil {
		base.Spec.Architectures = append([]string(nil), userAP.Spec.Architectures...)
	}

	projected, _ := projectUserProfiles(base, userAP, userNN, pod, containerName)
	return projected
}

// userProfileMeta returns the source name/namespace to carry onto the converted
// CP, preferring the ApplicationProfile (AP and NN share a name for a
// user-defined pair).
func userProfileMeta(userAP *v1beta1.ApplicationProfile, userNN *v1beta1.NetworkNeighborhood) *metav1.ObjectMeta {
	if userAP != nil {
		return &userAP.ObjectMeta
	}
	if userNN != nil {
		return &userNN.ObjectMeta
	}
	return nil
}
