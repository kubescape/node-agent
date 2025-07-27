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
	RequiredEventType utils.EventType
}

func NewOpenProfileValidator(objectCache objectcache.ObjectCache) profilevalidator.ProfileValidator {
	return &OpenProfileValidator{
		RequiredEventType: utils.OpenEventType,
	}
}

func (v *OpenProfileValidator) ValidateProfile(event utils.K8sEvent, ap *v1beta1.ApplicationProfileContainer, nn *v1beta1.NetworkNeighborhoodContainer) (profilevalidator.ProfileValidationResult, error) {
	checks := profilevalidator.ProfileValidationResult{
		Checks: []profilevalidator.ProfileValidationCheck{
			{
				Name:   "open_dynamic_path",
				Result: false,
			},
			{
				Name:   "open_flags",
				Result: false,
			},
		},
	}

	openEvent, ok := event.(*events.OpenEvent)
	if !ok {
		return profilevalidator.ProfileValidationResult{}, ErrConversionFailed
	}

	for _, open := range ap.Opens {
		if dynamicpathdetector.CompareDynamic(open.Path, openEvent.FullPath) {
			checks.GetCheck("open_dynamic_path").Result = true

			if compareOpenFlags(openEvent.Flags, open.Flags) {
				checks.GetCheck("open_flags").Result = true
			}
		}
	}

	return checks, nil
}

func compareOpenFlags(eventOpenFlags []string, profileOpenFlags []string) bool {
	found := 0
	for _, eventOpenFlag := range eventOpenFlags {
		for _, profileOpenFlag := range profileOpenFlags {
			if eventOpenFlag == profileOpenFlag {
				found += 1
			}
		}
	}
	return found == len(eventOpenFlags)
}

func (v *OpenProfileValidator) GetRequiredEventType() utils.EventType {
	return v.RequiredEventType
}
