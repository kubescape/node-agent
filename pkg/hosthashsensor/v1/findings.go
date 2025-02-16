package hosthashsensor

import (
	"github.com/armosec/armoapi-go/armotypes"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func (f FileHashResultFinding) GetAlertType() string {
	return "FileHashAccessed"
}

func (f FileHashResultFinding) GetAlertName() string {
	return "FileHashAccessed"
}

func (f FileHashResultFinding) GetBasicRuntimeAlert() armotypes.BaseRuntimeAlert {
	baseAlert := armotypes.BaseRuntimeAlert{
		AlertName:   "HashResultFinding",
		MD5Hash:     f.Hashes.md5,
		SHA1Hash:    f.Hashes.sha1,
		SHA256Hash:  f.Hashes.sha256,
		Timestamp:   f.Timestamp,
		InfectedPID: uint32(f.Pid),
		Severity:    1,
	}
	return baseAlert
}

func (f FileHashResultFinding) GetRuntimeProcessDetails() armotypes.ProcessTree {
	return armotypes.ProcessTree{
		ProcessTree: armotypes.Process{},
	}
}

func (f FileHashResultFinding) GetTriggerEvent() igtypes.Event {
	return f.Event
}

func (f FileHashResultFinding) GetMalwareRuntimeAlert() armotypes.MalwareAlert {
	return armotypes.MalwareAlert{
		MalwareFile:        f.FileDetails,
		Action:             "Accessed",
		MalwareDescription: "Host hash sensor detected a file hash",
		ProcessTree: armotypes.ProcessTree{
			ProcessTree: f.ProcessDetails,
		},
	}
}

func (f FileHashResultFinding) GetRuntimeAlertK8sDetails() armotypes.RuntimeAlertK8sDetails {
	return armotypes.RuntimeAlertK8sDetails{
		ContainerID:   f.Event.Runtime.ContainerID,
		ContainerName: f.Event.K8s.ContainerName,
		Namespace:     f.Event.GetNamespace(),
		PodName:       f.Event.K8s.PodName,
		PodNamespace:  f.Event.GetNamespace(),
		HostNetwork:   &f.Event.K8s.HostNetwork,
		Image:         f.Event.Runtime.ContainerImageName,
		ImageDigest:   f.Event.Runtime.ContainerImageDigest,
	}
}

func (f FileHashResultFinding) GetRuleAlert() *armotypes.RuleAlert {
	return &armotypes.RuleAlert{
		RuleDescription: "HashResultFinding",
	}
}
