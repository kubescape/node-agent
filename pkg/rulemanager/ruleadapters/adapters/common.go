package adapters

import "github.com/kubescape/node-agent/pkg/utils"

func ConvertToMap(e utils.EnrichEvent) map[string]interface{} {
	result := AcquireMap()

	result["timestamp"] = e.GetTimestamp()
	result["type"] = e.GetEventType()
	//result["message"] = e.Message

	runtime := AcquireMap()
	//runtime["runtimeName"] = e.Runtime.RuntimeName
	runtime["containerId"] = e.GetContainerID()
	runtime["containerName"] = e.GetContainer()
	//runtime["containerPid"] = e.Runtime.ContainerPID
	runtime["containerImageName"] = e.GetContainerImage()
	runtime["containerImageDigest"] = e.GetContainerImageDigest()
	//runtime["containerStartedAt"] = e.Runtime.ContainerStartedAt
	result["runtime"] = runtime

	k8s := AcquireMap()
	//k8s["node"] = e.K8s.Node
	k8s["namespace"] = e.GetNamespace()
	k8s["podName"] = e.GetPod()

	//k8s["podLabels"] = e.GetPodLabels()

	k8s["containerName"] = e.GetContainer()
	k8s["hostNetwork"] = e.GetHostNetwork()

	//owner := AcquireMap()
	//owner["kind"] = e.K8s.Owner.Kind
	//owner["name"] = e.K8s.Owner.Name
	//k8s["owner"] = owner

	result["k8s"] = k8s

	return result
}
