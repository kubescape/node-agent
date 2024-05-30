package seccompmanager

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type SeccompManagerMock struct {
}

func NewSeccompManagerMock() *SeccompManagerMock {
	return &SeccompManagerMock{}
}

var _ SeccompManagerClient = (*SeccompManagerMock)(nil)

func (s *SeccompManagerMock) AddSeccompProfile(_ *unstructured.Unstructured) error {
	return nil
}

func (s *SeccompManagerMock) DeleteSeccompProfile(_ *unstructured.Unstructured) error {
	return nil
}

func (s *SeccompManagerMock) GetSeccompProfile(_ string, _ *string) (v1beta1.SingleSeccompProfile, error) {
	return v1beta1.SingleSeccompProfile{}, nil
}
