package objectcache

import "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

type ApplicationActivityCache interface {
	IsCached(kind, namespace, name string) bool
	GetApplicationActivity(namespace, name string) *v1beta1.ApplicationActivity
}

var _ ApplicationActivityCache = (*ApplicationActivityCacheMock)(nil)

type ApplicationActivityCacheMock struct {
}

func (ap *ApplicationActivityCacheMock) GetApplicationActivity(namespace, name string) *v1beta1.ApplicationActivity {
	return nil
}
func (ap *ApplicationActivityCacheMock) IsCached(kind, namespace, name string) bool {
	return true
}
