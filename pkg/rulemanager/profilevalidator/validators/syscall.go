package validators

import (
	"slices"

	"github.com/kubescape/node-agent/pkg/objectcache"
	ruleenginetypes "github.com/kubescape/node-agent/pkg/ruleengine/types"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type SyscallProfileValidator struct {
}

func NewSyscallProfileValidator(objectCache objectcache.ObjectCache) profilevalidator.ProfileValidator {
	return &SyscallProfileValidator{}
}

func (v *SyscallProfileValidator) ValidateProfile(event utils.K8sEvent, ap *v1beta1.ApplicationProfileContainer, nn *v1beta1.NetworkNeighborhoodContainer) (bool, error) {
	syscallEvent, ok := event.(*ruleenginetypes.SyscallEvent)
	if !ok {
		return false, ErrConversionFailed
	}

	if slices.Contains(ap.Syscalls, syscallEvent.SyscallName) {
		return true, nil
	}

	return false, nil
}
