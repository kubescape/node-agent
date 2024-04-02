package objectcache

import "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

type ApplicationProfileCache interface {
	IsCached(kind, namespace, name string) bool
	GetApplicationProfile(namespace, name string) *v1beta1.ApplicationProfile
}

var _ ApplicationProfileCache = (*ApplicationProfileCacheMock)(nil)

type ApplicationProfileCacheMock struct {
}

func (ap *ApplicationProfileCacheMock) GetApplicationProfile(namespace, name string) *v1beta1.ApplicationProfile {
	return nil
}
func (ap *ApplicationProfileCacheMock) IsCached(kind, namespace, name string) bool {
	return true
}
