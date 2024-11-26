package seccompmanager

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type SeccompManagerClient interface {
	AddSeccompProfile(obj *unstructured.Unstructured) error
	DeleteSeccompProfile(obj *unstructured.Unstructured) error
	GetSeccompProfile(name string, path *string) (v1beta1.SingleSeccompProfile, error)
}
