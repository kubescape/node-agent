package objectcache

import "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

type ApplicationProfileCache interface {
	GetApplicationProfile(containerID string) *v1beta1.ApplicationProfile
}

var _ ApplicationProfileCache = (*ApplicationProfileCacheMock)(nil)

type ApplicationProfileCacheMock struct {
}

func (ap *ApplicationProfileCacheMock) GetApplicationProfile(_ string) *v1beta1.ApplicationProfile {
	return nil
}
