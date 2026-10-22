//go:build !experimental_signing

package containerprofilecache

import (
	"context"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type signingState struct{}
type signingProvenance struct{}
type signingBinding struct{}

func (*ContainerProfileCacheImpl) loadSignedBundle(context.Context, string, string, string) (*v1beta1.ContainerProfile, bool, signingProvenance, error) {
	return nil, false, signingProvenance{}, nil
}
func (*ContainerProfileCacheImpl) admitSignedProfile(cp *v1beta1.ContainerProfile, _ string) (*v1beta1.ContainerProfile, bool, signingProvenance) {
	return cp, false, signingProvenance{}
}
func (*ContainerProfileCacheImpl) requiresSignedProfile() bool                         { return false }
func (*ContainerProfileCacheImpl) refuseSignedProfile(string, *CachedContainerProfile) {}

func (*ContainerProfileCacheImpl) handleBundleError(string, *CachedContainerProfile) {}

func (*ContainerProfileCacheImpl) setSigningBinding(*CachedContainerProfile, string)       {}
func (*ContainerProfileCacheImpl) signingBundleName(*CachedContainerProfile) string        { return "" }
func (*ContainerProfileCacheImpl) handleProfileFetchError(string, *CachedContainerProfile) {}
func (*ContainerProfileCacheImpl) noteAdoptedProfile(signingProvenance, *v1beta1.ContainerProfile, string) {
}

func (*ContainerProfileCacheImpl) preserveSignedBundleReference(*CachedContainerProfile, *CachedContainerProfile) {
}

func (*ContainerProfileCacheImpl) canSkipSignedRefresh(*CachedContainerProfile) bool { return true }
