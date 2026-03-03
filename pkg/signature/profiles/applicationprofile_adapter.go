package profiles

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
		return make(map[string]string)
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
	return &v1beta1.ApplicationProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: a.profile.APIVersion,
			Kind:       a.profile.Kind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      a.profile.Name,
			Namespace: a.profile.Namespace,
			Labels:    a.profile.Labels,
		},
		Spec: a.profile.Spec,
	}
}
