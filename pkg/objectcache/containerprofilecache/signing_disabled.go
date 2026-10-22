//go:build !experimental_signing

package containerprofilecache

import (
	"context"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type signingState struct{}

func (*ContainerProfileCacheImpl) loadSignedBundle(context.Context, string, string, string) (*v1beta1.ContainerProfile, bool, error) {
	return nil, false, nil
}
func (*ContainerProfileCacheImpl) admitSignedProfile(cp *v1beta1.ContainerProfile, _ string) (*v1beta1.ContainerProfile, bool) {
	return cp, false
}
func (*ContainerProfileCacheImpl) requiresSignedProfile() bool                         { return false }
func (*ContainerProfileCacheImpl) refuseSignedProfile(string, *CachedContainerProfile) {}
