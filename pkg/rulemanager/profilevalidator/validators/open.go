package validators

import (
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
)

type OpenProfileValidator struct {
}

func NewOpenProfileValidator(objectCache objectcache.ObjectCache) profilevalidator.ProfileValidator {
	return &OpenProfileValidator{}
}

func (v *OpenProfileValidator) ValidateProfile(event utils.K8sEvent, ap *v1beta1.ApplicationProfileContainer, nn *v1beta1.NetworkNeighborhoodContainer) (bool, error) {
	openEvent, ok := event.(*events.OpenEvent)
	if !ok {
		return false, ErrConversionFailed
	}

	for _, open := range ap.Opens {
		if dynamicpathdetector.CompareDynamic(open.Path, openEvent.FullPath) {
			return true, nil
		}
	}

	return false, nil
}
