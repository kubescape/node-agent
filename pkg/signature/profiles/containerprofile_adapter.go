//go:build experimental_signing

package profiles

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// ContainerProfileAdapter wraps a ContainerProfile as a SignableObject.
//
// The AP/NN → ContainerProfile migration collapses the former
// ApplicationProfileAdapter + NetworkNeighborhoodAdapter pair into this single
// adapter: a ContainerProfile already carries both the process/file surface
// (execs/opens/caps/syscalls/seccomp/rulePolicies) and the network surface
// (ingress/egress/endpoints), so one signed object covers what previously took
// two. The signed content is metadata{name,namespace,labels} + spec and
// deliberately EXCLUDES annotations, which storage mutates on save
// (managed-by, completion, size, sync-checksum, and the signature annotations
// themselves).
type ContainerProfileAdapter struct {
	profile *v1beta1.ContainerProfile
}

func NewContainerProfileAdapter(profile *v1beta1.ContainerProfile) *ContainerProfileAdapter {
	return &ContainerProfileAdapter{
		profile: profile,
	}
}

func (a *ContainerProfileAdapter) GetAnnotations() map[string]string {
	// Read-only: must not mutate the wrapped (often cached) profile. nil-map
	// initialization belongs on the write path (SetAnnotations).
	return a.profile.Annotations
}

func (a *ContainerProfileAdapter) SetAnnotations(annotations map[string]string) {
	a.profile.Annotations = annotations
}

func (a *ContainerProfileAdapter) GetUID() string {
	return string(a.profile.UID)
}

func (a *ContainerProfileAdapter) GetNamespace() string {
	return a.profile.Namespace
}

func (a *ContainerProfileAdapter) GetName() string {
	return a.profile.Name
}

func (a *ContainerProfileAdapter) GetContent() interface{} {
	// Work on a deep copy so signing/verification never mutates the wrapped
	// profile. PolicyByRuleId is normalized (nil -> {}) on the copy only, for a
	// stable JSON representation in the signed content.
	profile := a.profile.DeepCopy()
	if profile.Spec.PolicyByRuleId == nil {
		profile.Spec.PolicyByRuleId = make(map[string]v1beta1.RulePolicy)
	}

	apiVersion := profile.APIVersion
	if apiVersion == "" {
		apiVersion = "spdx.softwarecomposition.kubescape.io/v1beta1"
	}
	kind := profile.Kind
	if kind == "" {
		kind = "ContainerProfile"
	}
	return map[string]interface{}{
		"apiVersion": apiVersion,
		"kind":       kind,
		// metadata.namespace is deliberately NOT signed: a vendor cannot know
		// which namespace a customer will install into, and re-signing per
		// namespace would defeat offline signing. Placement is a deployment
		// decision governed by RBAC; what the signature binds is the content and
		// the labels (bundle membership + fragment class), which is what confines
		// a fragment's authority.
		"metadata": map[string]interface{}{
			"name":   profile.Name,
			"labels": profile.Labels,
		},
		"spec": profile.Spec,
	}
}

func (a *ContainerProfileAdapter) GetUpdatedObject() interface{} {
	return a.profile
}

// ExpectedResourceType identifies the resource handled by this adapter, independently of live TypeMeta.
func (*ContainerProfileAdapter) ExpectedResourceType() (apiVersion, kind string) {
	return "spdx.softwarecomposition.kubescape.io/v1beta1", "ContainerProfile"
}
