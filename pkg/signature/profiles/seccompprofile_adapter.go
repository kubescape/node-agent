package profiles

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	if s.profile.Annotations == nil {
		s.profile.Annotations = make(map[string]string)
	}
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
	return &v1beta1.SeccompProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: s.profile.APIVersion,
			Kind:       s.profile.Kind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.profile.Name,
			Namespace: s.profile.Namespace,
			Labels:    s.profile.Labels,
		},
		Spec: s.profile.Spec,
	}
}
