package profiles

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type SeccompProfileAdapter struct {
	profile *v1beta1.SeccompProfile
}

func NewSeccompProfileAdapter(profile *v1beta1.SeccompProfile) *SeccompProfileAdapter {
	return &SeccompProfileAdapter{
		profile: profile,
	}
}

func (s *SeccompProfileAdapter) GetAnnotations() map[string]string {
	// Read-only: must not mutate the wrapped object on read (see
	// ApplicationProfileAdapter.GetAnnotations).
	return s.profile.Annotations
}

func (s *SeccompProfileAdapter) SetAnnotations(annotations map[string]string) {
	s.profile.Annotations = annotations
}

func (s *SeccompProfileAdapter) GetUID() string {
	return string(s.profile.UID)
}

func (s *SeccompProfileAdapter) GetNamespace() string {
	return s.profile.Namespace
}

func (s *SeccompProfileAdapter) GetName() string {
	return s.profile.Name
}

func (s *SeccompProfileAdapter) GetContent() interface{} {
	apiVersion := s.profile.APIVersion
	if apiVersion == "" {
		apiVersion = "spdx.softwarecomposition.kubescape.io/v1beta1"
	}
	kind := s.profile.Kind
	if kind == "" {
		kind = "SeccompProfile"
	}
	return map[string]interface{}{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]interface{}{
			"name":      s.profile.Name,
			"namespace": s.profile.Namespace,
			"labels":    s.profile.Labels,
		},
		"spec": s.profile.Spec,
	}
}

func (s *SeccompProfileAdapter) GetUpdatedObject() interface{} {
	return s.profile
}
