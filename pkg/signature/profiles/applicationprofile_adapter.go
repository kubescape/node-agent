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
	if a.profile.Annotations == nil {
		a.profile.Annotations = make(map[string]string)
	}
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
	// Normalize PolicyByRuleId to ensure consistent JSON representation
	// Empty maps become {} instead of null
	for i := range a.profile.Spec.Containers {
		if a.profile.Spec.Containers[i].PolicyByRuleId == nil {
			a.profile.Spec.Containers[i].PolicyByRuleId = make(map[string]v1beta1.RulePolicy)
		}
	}
	for i := range a.profile.Spec.InitContainers {
		if a.profile.Spec.InitContainers[i].PolicyByRuleId == nil {
			a.profile.Spec.InitContainers[i].PolicyByRuleId = make(map[string]v1beta1.RulePolicy)
		}
	}
	for i := range a.profile.Spec.EphemeralContainers {
		if a.profile.Spec.EphemeralContainers[i].PolicyByRuleId == nil {
			a.profile.Spec.EphemeralContainers[i].PolicyByRuleId = make(map[string]v1beta1.RulePolicy)
		}
	}

	apiVersion := a.profile.APIVersion
	if apiVersion == "" {
		apiVersion = "spdx.softwarecomposition.kubescape.io/v1beta1"
	}
	kind := a.profile.Kind
	if kind == "" {
		kind = "ApplicationProfile"
	}
	return map[string]interface{}{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]interface{}{
			"name":      a.profile.Name,
			"namespace": a.profile.Namespace,
			"labels":    a.profile.Labels,
		},
		"spec": a.profile.Spec,
	}
}

func (a *ApplicationProfileAdapter) GetUpdatedObject() interface{} {
	return a.profile
}
