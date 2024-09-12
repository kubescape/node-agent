package seccompmanager

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	v1beta1api "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type SeccompManagerMock struct {
}

func NewSeccompManagerMock() *SeccompManagerMock {
	return &SeccompManagerMock{}
}

var _ SeccompManagerClient = (*SeccompManagerMock)(nil)

func (s *SeccompManagerMock) AddSeccompProfile(_ *v1beta1api.SeccompProfile) error {
	return nil
}

func (s *SeccompManagerMock) DeleteSeccompProfile(_ *v1beta1api.SeccompProfile) error {
	return nil
}

func (s *SeccompManagerMock) GetSeccompProfile(_ string, _ *string) (v1beta1.SingleSeccompProfile, error) {
	return v1beta1.SingleSeccompProfile{}, nil
}
