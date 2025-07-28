package validators

import (
	"slices"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type SyscallProfileValidator struct {
	RequiredEventType utils.EventType
}

func NewSyscallProfileValidator(objectCache objectcache.ObjectCache) profilevalidator.ProfileValidator {
	return &SyscallProfileValidator{
		RequiredEventType: utils.SyscallEventType,
	}
}

func (v *SyscallProfileValidator) ValidateProfile(event utils.K8sEvent, ap *v1beta1.ApplicationProfileContainer, nn *v1beta1.NetworkNeighborhoodContainer) (profilevalidator.ProfileValidationResult, error) {
	checks := profilevalidator.ProfileValidationResult{
		Checks: []profilevalidator.ProfileValidationCheck{
			{
				Name:   "syscall",
				Result: false,
			},
		},
	}

	syscallEvent, ok := event.(*types.SyscallEvent)
	if !ok {
		return profilevalidator.ProfileValidationResult{}, ErrConversionFailed
	}

	if slices.Contains(ap.Syscalls, syscallEvent.SyscallName) {
		checks.GetCheck("syscall").Result = true
	}

	return checks, nil
}

func (v *SyscallProfileValidator) GetRequiredEventType() utils.EventType {
	return v.RequiredEventType
}
