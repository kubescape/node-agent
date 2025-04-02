package cache

import (
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/ruleengine"
)

func NewCacheMock(nodeName string) *RBCache {
	return &RBCache{
		nodeName:     nodeName,
		allPods:      mapset.NewSet[string](),
		k8sClient:    k8sinterface.NewKubernetesApiMock(),
		ruleCreator:  &ruleengine.RuleCreatorMock{},
		podToRBNames: maps.SafeMap[string, mapset.Set[string]]{},
		rbNameToPods: maps.SafeMap[string, mapset.Set[string]]{},
	}
}
