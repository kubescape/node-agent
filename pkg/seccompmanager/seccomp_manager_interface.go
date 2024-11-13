package seccompmanager

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	v1beta1api "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type SeccompManagerClient interface {
	AddSeccompProfile(obj *v1beta1api.SeccompProfile) error
	DeleteSeccompProfile(obj *v1beta1api.SeccompProfile) error
	GetSeccompProfile(name string, path *string) (v1beta1.SingleSeccompProfile, error)
}
