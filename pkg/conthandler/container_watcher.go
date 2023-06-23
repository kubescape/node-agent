package conthandler

import (
	"fmt"

	"node-agent/pkg/config"
	conthandlerV1 "node-agent/pkg/conthandler/v1"

	"github.com/armosec/utils-k8s-go/wlid"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/k8s-interface/instanceidhandler"
	instanceidhandlerV1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"k8s.io/client-go/rest"
)

type ContainerClientK8SAPIServer struct {
	k8sClient *k8sinterface.KubernetesApi
}

var _ ContainerClient = (*ContainerClientK8SAPIServer)(nil)

type ContainerWatcher struct {
	ContainerClient ContainerClient
	nodeName        string
}

var _ ContainerWatcherClient = (*ContainerWatcher)(nil)

func CreateContainerClientK8SAPIServer() (ContainerClient, error) {
	return &ContainerClientK8SAPIServer{
		k8sClient: k8sinterface.NewKubernetesApi(),
	}, nil
}

func CreateContainerWatcher(client ContainerClient) (*ContainerWatcher, error) {
	nodeName, err := getNodeName()
	if err != nil {
		return nil, err
	}

	return &ContainerWatcher{
		ContainerClient: client,
		nodeName:        nodeName,
	}, nil
}

func getNodeName() (string, error) {
	return config.GetConfigurationConfigContext().GetNodeName(), nil
}

func (client *ContainerClientK8SAPIServer) GetK8sConfig() *rest.Config {
	return client.k8sClient.K8SConfig
}

func (client *ContainerClientK8SAPIServer) CalculateWorkloadParentRecursive(workload any) (string, string, error) {
	w := workload.(*workloadinterface.Workload)
	return client.k8sClient.CalculateWorkloadParentRecursive(w)
}

func (client *ContainerClientK8SAPIServer) GetWorkload(namespace, kind, name string) (any, error) {
	return client.k8sClient.GetWorkload(namespace, kind, name)
}

func (client *ContainerClientK8SAPIServer) GenerateWLID(workload any, clusterName string) string {
	w := workload.(*workloadinterface.Workload)
	return w.GenerateWlid(clusterName)
}

func getInstanceID(instanceIDs []instanceidhandler.IInstanceID, name string) instanceidhandler.IInstanceID {
	foundIndex := 0
	for i := range instanceIDs {
		if instanceIDs[i].GetContainerName() == name {
			foundIndex = i
		}
	}
	return instanceIDs[foundIndex]
}

func (containerWatcher *ContainerWatcher) GetContainerClient() ContainerClient {
	return containerWatcher.ContainerClient
}

func (containerWatcher *ContainerWatcher) GetNodeName() string {
	return containerWatcher.nodeName
}

func (containerWatcher *ContainerWatcher) ParsePodData(pod *workloadinterface.Workload, container *containercollection.Container) (*conthandlerV1.ContainerEventData, error) {
	kind, name, err := containerWatcher.GetContainerClient().CalculateWorkloadParentRecursive(pod)
	if err != nil {
		return nil, fmt.Errorf("fail to get workload owner parent %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	parentWorkload, err := containerWatcher.GetContainerClient().GetWorkload(pod.GetNamespace(), kind, name)
	if err != nil {
		return nil, fmt.Errorf("fail to get parent workload %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	parentWlid := containerWatcher.GetContainerClient().GenerateWLID(parentWorkload, config.GetConfigurationConfigContext().GetClusterName())
	err = wlid.IsWlidValid(parentWlid)
	if err != nil {
		return nil, fmt.Errorf("WLID of parent workload is not in the right %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}

	containers, err := pod.GetContainers()
	if err != nil {
		return nil, fmt.Errorf("fail to get containers for pod %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	imageTag := ""
	for i := range containers {
		if containers[i].Name == container.Name {
			imageTag = containers[i].Image
		}
	}

	instanceIDs, err := instanceidhandlerV1.GenerateInstanceID(pod)
	if err != nil {
		return nil, fmt.Errorf("fail to create InstanceID to pod %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	instanceID := getInstanceID(instanceIDs, container.Name)

	k8sContainerID := createK8sContainerID(pod.GetNamespace(), pod.GetName(), container.Name)
	return conthandlerV1.CreateNewContainerEvent(imageTag, container, k8sContainerID, parentWlid, instanceID), nil
}
