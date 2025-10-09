package adapters

//func ConvertToMap(e *types.Event) map[string]interface{} {
//	result := AcquireMap()
//
//	result["timestamp"] = e.Timestamp
//	result["type"] = e.Type
//	result["message"] = e.Message
//
//	runtime := AcquireMap()
//	runtime["runtimeName"] = e.Runtime.RuntimeName
//	runtime["containerId"] = e.Runtime.ContainerID
//	runtime["containerName"] = e.Runtime.ContainerName
//	runtime["containerPid"] = e.Runtime.ContainerPID
//	runtime["containerImageName"] = e.Runtime.ContainerImageName
//	runtime["containerImageDigest"] = e.Runtime.ContainerImageDigest
//	runtime["containerStartedAt"] = e.Runtime.ContainerStartedAt
//	result["runtime"] = runtime
//
//	k8s := AcquireMap()
//	k8s["node"] = e.K8s.Node
//	k8s["namespace"] = e.K8s.Namespace
//	k8s["podName"] = e.K8s.PodName
//	k8s["podLabels"] = e.K8s.PodLabels
//	k8s["containerName"] = e.K8s.ContainerName
//	k8s["hostNetwork"] = e.K8s.HostNetwork
//
//	owner := AcquireMap()
//	owner["kind"] = e.K8s.Owner.Kind
//	owner["name"] = e.K8s.Owner.Name
//	k8s["owner"] = owner
//
//	result["k8s"] = k8s
//
//	return result
//}
