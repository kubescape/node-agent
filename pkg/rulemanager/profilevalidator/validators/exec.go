package validators

import (
	"slices"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type ExecProfileValidator struct {
	RequiredEventType utils.EventType
}

func NewExecProfileValidator(objectCache objectcache.ObjectCache) profilevalidator.ProfileValidator {
	return &ExecProfileValidator{
		RequiredEventType: utils.ExecveEventType,
	}
}

func (v *ExecProfileValidator) ValidateProfile(event utils.K8sEvent, ap *v1beta1.ApplicationProfileContainer, nn *v1beta1.NetworkNeighborhoodContainer) (profilevalidator.ProfileValidationResult, error) {
	checks := profilevalidator.ProfileValidationResult{
		Checks: []profilevalidator.ProfileValidationCheck{
			{
				Name:   "exec_path",
				Result: false,
			},
			{
				Name:   "exec_args",
				Result: false,
			},
		},
	}

	execEvent, ok := event.(*events.ExecEvent)
	if !ok {
		return checks, ErrConversionFailed
	}

	execPath := execEvent.ExePath

	for _, exec := range ap.Execs {
		if exec.Path == execPath {
			checks.GetCheck("exec_path").Result = true
			// Either compare args false or args match
			if slices.Compare(exec.Args, execEvent.Args) == 0 {
				checks.GetCheck("exec_args").Result = true
			}
		}
	}

	return checks, nil
}

func (v *ExecProfileValidator) GetRequiredEventType() utils.EventType {
	return v.RequiredEventType
}
