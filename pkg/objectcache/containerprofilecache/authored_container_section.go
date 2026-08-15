package containerprofilecache

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// resolveAuthoredContainerSection maps a user-authored ContainerProfile
// document to the flat per-container view this container enforces.
//
// An authored document comes in two shapes:
//
//   - FLAT (single-container convention): the profile surfaces live directly
//     on spec; the document IS the container's profile. Returned unchanged.
//
//   - GROUPED (multi-container convention): spec carries the
//     containers/initContainers/ephemeralContainers subtype groups - the same
//     contract the legacy ApplicationProfile/NetworkNeighborhood specs
//     expressed - and one document describes every container in the pod.
//     The section whose name matches containerName is flattened into a
//     per-container view (pod-level architectures and the workload selector
//     are inherited from the document).
//
// A grouped document that does not name containerName returns nil: the
// document deliberately enumerates the pod's containers, so a container it
// does not cover has no authored profile (callers fall through to their
// unresolved handling rather than enforcing a sibling's profile - the exact
// cross-container bleed the subtype groups exist to prevent).
func resolveAuthoredContainerSection(cp *v1beta1.ContainerProfile, containerName string) *v1beta1.ContainerProfile {
	if cp == nil {
		return nil
	}
	if len(cp.Spec.Containers) == 0 && len(cp.Spec.InitContainers) == 0 && len(cp.Spec.EphemeralContainers) == 0 {
		return cp // flat document
	}
	groups := [][]v1beta1.ContainerProfileContainer{
		cp.Spec.Containers,
		cp.Spec.InitContainers,
		cp.Spec.EphemeralContainers,
	}
	for _, group := range groups {
		for i := range group {
			if group[i].Name != containerName {
				continue
			}
			section := &group[i]
			flat := cp.DeepCopy()
			flat.Spec = v1beta1.ContainerProfileSpec{
				// Pod-level fields inherited from the document.
				Architectures: cp.Spec.Architectures,
				LabelSelector: cp.Spec.LabelSelector,
				// Per-container surfaces from the matching section.
				Capabilities:         section.Capabilities,
				Execs:                section.Execs,
				Opens:                section.Opens,
				Syscalls:             section.Syscalls,
				SeccompProfile:       section.SeccompProfile,
				Endpoints:            section.Endpoints,
				ImageID:              section.ImageID,
				ImageTag:             section.ImageTag,
				PolicyByRuleId:       section.PolicyByRuleId,
				IdentifiedCallStacks: section.IdentifiedCallStacks,
				Ingress:              section.Ingress,
				Egress:               section.Egress,
			}
			return flat
		}
	}
	return nil // grouped document does not cover this container
}
