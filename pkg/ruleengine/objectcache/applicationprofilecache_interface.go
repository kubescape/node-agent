package objectcache

import "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

// Path: pkg/ruleengine/objectcache/applicationprofilecache.go
// Compare this snippet from pkg/ruleengine/objectcache/objectcache_interface.go:
// package objectcache
//

type ApplicationProfileCache interface {
	GetApplicationProfile(namespace, name string) *v1beta1.ApplicationProfile
}

var _ ApplicationProfileCache = (*ApplicationProfileCacheMock)(nil)

type ApplicationProfileCacheMock struct {
}

func (ap *ApplicationProfileCacheMock) GetApplicationProfile(namespace, name string) *v1beta1.ApplicationProfile {
	return nil
}
