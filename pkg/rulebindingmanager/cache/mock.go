package cache

import (
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	rulemanagertypesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

func NewCacheMock(nodeName string) *RBCache {
	return &RBCache{
		nodeName:     nodeName,
		allPods:      mapset.NewSet[string](),
		k8sClient:    k8sinterface.NewKubernetesApiMock(),
		ruleCreator:  &rulecreator.RuleCreatorMock{},
		podToRBNames: maps.SafeMap[string, mapset.Set[string]]{},
		rbNameToPods: maps.SafeMap[string, mapset.Set[string]]{},
		rulesForPod:  expirable.NewLRU[string, []rulemanagertypesv1.Rule](1000, nil, 60*time.Second),
	}
}
