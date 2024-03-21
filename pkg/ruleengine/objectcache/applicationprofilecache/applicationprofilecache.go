package applicationprofilecache

import (
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/ruleengine/objectcache"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

var _ objectcache.ApplicationProfileCache = (*ApplicationProfileCacheImpl)(nil)

type ApplicationProfileCacheImpl struct {
	k8sClient k8sclient.K8sClientInterface
}

func NewApplicationProfileCache(k8sClient k8sclient.K8sClientInterface) (*ApplicationProfileCacheImpl, error) {
	return &ApplicationProfileCacheImpl{
		k8sClient: k8sClient,
	}, nil

}

func (k *ApplicationProfileCacheImpl) GetApplicationProfile(namespace, name string) *v1beta1.ApplicationProfile {
	// TODO: implement
	return nil
}
