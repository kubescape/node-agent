package ruleengine

import (
	"slices"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/v1/ruleprocess"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func IsExecEventInProfile(execEvent *events.ExecEvent, objectCache objectcache.ObjectCache, compareArgs bool) (bool, error) {
	// Check if the exec is whitelisted, if so, return nil
	execPath := GetExecPathFromEvent(execEvent)

	ap, err := GetApplicationProfile(execEvent.Runtime.ContainerID, objectCache)
	if err != nil {
		return false, err
	}

	appProfileExecList, err := GetContainerFromApplicationProfile(ap, execEvent.GetContainer())
	if err != nil {
		return false, err
	}

	for _, exec := range appProfileExecList.Execs {
		if exec.Path == execPath {
			// Either compare args false or args match
			if !compareArgs || slices.Compare(exec.Args, execEvent.Args) == 0 {
				return true, nil
			}
		}
	}
	return false, nil
}

func IsAllowed(event *eventtypes.Event, objCache objectcache.ObjectCache, process string, ruleId string) (bool, error) {
	if objCache == nil {
		return false, nil
	}
	ap, err := GetApplicationProfile(event.Runtime.ContainerID, objCache)
	if err != nil {
		return false, err
	}

	appProfile, err := GetContainerFromApplicationProfile(ap, event.GetContainer())
	if err != nil {
		return false, err
	}

	// rule policy does not exists, allowed by default
	if _, ok := appProfile.PolicyByRuleId[ruleId]; !ok {
		return true, nil
	}

	if policy, ok := appProfile.PolicyByRuleId[ruleId]; ok {
		if policy.AllowedContainer || slices.Contains(policy.AllowedProcesses, process) {
			return true, nil
		}
	}

	return false, nil
}

func GetApplicationProfile(containerID string, objectCache objectcache.ObjectCache) (*v1beta1.ApplicationProfile, error) {
	ap := objectCache.ApplicationProfileCache().GetApplicationProfile(containerID)
	if ap == nil {
		return nil, ruleprocess.NoProfileAvailable
	}
	return ap, nil
}

func GetNetworkNeighborhood(containerID string, objectCache objectcache.ObjectCache) (*v1beta1.NetworkNeighborhood, error) {
	nn := objectCache.NetworkNeighborhoodCache().GetNetworkNeighborhood(containerID)
	if nn == nil {
		return nil, ruleprocess.NoProfileAvailable
	}
	return nn, nil
}
