package rulemanager

import (
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/utils"
)

// InitServicePeerLabelResolver registers a ServicePeerLabels hook backed by the Kubernetes client
// so that Service destination endpoints in CEL rules resolve to their backend selector labels.
func InitServicePeerLabelResolver(k8sClient k8sclient.K8sClientInterface) {
	if k8sClient == nil {
		utils.SetServicePeerLabels(nil)
		return
	}
	utils.SetServicePeerLabels(func(namespace, name string) map[string]string {
		svc, err := k8sClient.GetWorkload(namespace, "Service", name)
		if err != nil || svc == nil {
			return nil
		}
		if svc.GetName() == "kubernetes" && svc.GetNamespace() == "default" {
			return svc.GetLabels()
		}
		return svc.GetServiceSelector()
	})
}
