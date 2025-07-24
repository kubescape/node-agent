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
}

func NewExecProfileValidator(objectCache objectcache.ObjectCache) profilevalidator.ProfileValidator {
	return &ExecProfileValidator{}
}

func (v *ExecProfileValidator) ValidateProfile(event utils.K8sEvent, ap *v1beta1.ApplicationProfileContainer, nn *v1beta1.NetworkNeighborhoodContainer) (bool, error) {
	execEvent, ok := event.(*events.ExecEvent)
	if !ok {
		return false, ErrConversionFailed
	}

	execPath := execEvent.ExePath

	for _, exec := range ap.Execs {
		if exec.Path == execPath {
			// Either compare args false or args match
			if slices.Compare(exec.Args, execEvent.Args) == 0 {
				return true, nil
			}
		}
	}

	return false, nil
}
