package hostrulemanager

import "github.com/kubescape/node-agent/pkg/utils"

type HostRuleManagerClient interface {
	ReportEvent(eventType utils.EventType, event utils.K8sEvent)
}
