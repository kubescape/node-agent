package hostrulemanager

import "github.com/kubescape/node-agent/pkg/utils"

type HostRuleManagerClient interface {
	RegisterPeekFunc(peek func(mntns uint64) ([]string, error))
	ReportEvent(eventType utils.EventType, event utils.K8sEvent)
}
