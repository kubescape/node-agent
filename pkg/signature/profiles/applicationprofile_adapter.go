package profiles

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type ApplicationProfileAdapter struct {
	profile *v1beta1.ApplicationProfile
}

func NewApplicationProfileAdapter(profile *v1beta1.ApplicationProfile) *ApplicationProfileAdapter {
	return &ApplicationProfileAdapter{
		profile: profile,
	}
}

func (a *ApplicationProfileAdapter) GetAnnotations() map[string]string {
	// Read-only: must not mutate the wrapped profile. VerifyObject and
	// GetObjectSignature read annotations on cached objects; nil-map
	// initialization belongs on the write path (SetAnnotations).
	return a.profile.Annotations
}

func (a *ApplicationProfileAdapter) SetAnnotations(annotations map[string]string) {
	a.profile.Annotations = annotations
}

func (a *ApplicationProfileAdapter) GetUID() string {
	return string(a.profile.UID)
}

func (a *ApplicationProfileAdapter) GetNamespace() string {
	return a.profile.Namespace
}

func (a *ApplicationProfileAdapter) GetName() string {
	return a.profile.Name
}

func (a *ApplicationProfileAdapter) GetContent() interface{} {
	// Work on a deep copy so signing/verification never mutates the wrapped
	// (often cached) profile. PolicyByRuleId is normalized (nil -> {}) on the
	// copy only, for a stable JSON representation in the signed content.
	profile := a.profile.DeepCopy()
	for i := range profile.Spec.Containers {
		if profile.Spec.Containers[i].PolicyByRuleId == nil {
			profile.Spec.Containers[i].PolicyByRuleId = make(map[string]v1beta1.RulePolicy)
		}
	}
	for i := range profile.Spec.InitContainers {
		if profile.Spec.InitContainers[i].PolicyByRuleId == nil {
			profile.Spec.InitContainers[i].PolicyByRuleId = make(map[string]v1beta1.RulePolicy)
		}
	}
	for i := range profile.Spec.EphemeralContainers {
		if profile.Spec.EphemeralContainers[i].PolicyByRuleId == nil {
			profile.Spec.EphemeralContainers[i].PolicyByRuleId = make(map[string]v1beta1.RulePolicy)
		}
	}

	apiVersion := profile.APIVersion
	if apiVersion == "" {
		apiVersion = "spdx.softwarecomposition.kubescape.io/v1beta1"
	}
	kind := profile.Kind
	if kind == "" {
		kind = "ApplicationProfile"
	}
	return map[string]interface{}{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]interface{}{
			"name":      profile.Name,
			"namespace": profile.Namespace,
			"labels":    profile.Labels,
		},
		"spec": profile.Spec,
	}
}

func (a *ApplicationProfileAdapter) GetUpdatedObject() interface{} {
	return a.profile
}
