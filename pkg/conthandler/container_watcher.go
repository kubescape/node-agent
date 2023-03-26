package conthandler

import (
	gcontext "context"
	"encoding/json"
	"fmt"

	"sniffer/pkg/config"
	conthandlerV1 "sniffer/pkg/conthandler/v1"

	"sniffer/pkg/context"

	wlid "github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	instanceidhandler "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	k8sinterface "github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	core "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

type ContainerClientK8SAPIServer struct {
	k8sClient *k8sinterface.KubernetesApi
}

type ContainerWatcher struct {
	ContainerClient ContainerClient
	nodeName        string
}

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

func (client *ContainerClientK8SAPIServer) GetWatcher() (watch.Interface, error) {
	globalHTTPContext := gcontext.Background()
	return client.k8sClient.KubernetesClient.CoreV1().Pods("").Watch(globalHTTPContext, v1.ListOptions{})
}

func (client *ContainerClientK8SAPIServer) GetApiVersion(workload any) string {
	w := workload.(*workloadinterface.Workload)
	return w.GetApiVersion()
}

func (client *ContainerClientK8SAPIServer) GetResourceVersion(workload any) string {
	w := workload.(*workloadinterface.Workload)
	return w.GetResourceVersion()
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

func getInstanceID(instanceIDs []instanceidhandler.InstanceID, name string) instanceidhandler.InstanceID {
	foundIndex := 0
	for i := range instanceIDs {
		if instanceIDs[i].GetContainerName() == name {
			foundIndex = i
		}
	}
	return instanceIDs[foundIndex]
}

func (containerWatcher *ContainerWatcher) parsePodData(pod *core.Pod, containerIndex int) (*conthandlerV1.ContainerEventData, error) {
	pod.TypeMeta.Kind = "Pod"
	podBytes, err := json.Marshal(pod)
	if err != nil {
		return nil, fmt.Errorf("fail to unmarshal pod %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	workload, err := workloadinterface.NewWorkload(podBytes)
	if err != nil {
		return nil, fmt.Errorf("fail to create workload ID to pod %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	kind, name, err := containerWatcher.ContainerClient.CalculateWorkloadParentRecursive(workload)
	if err != nil {
		return nil, fmt.Errorf("fail to get workload owner parent %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	parentWorkload, err := containerWatcher.ContainerClient.GetWorkload(pod.GetNamespace(), kind, name)
	if err != nil {
		return nil, fmt.Errorf("fail to get parent workload %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	parentWlid := containerWatcher.ContainerClient.GenerateWLID(parentWorkload, config.GetConfigurationConfigContext().GetClusterName())
	err = wlid.IsWlidValid(parentWlid)
	if err != nil {
		return nil, fmt.Errorf("WLID of parent workload is not in the right %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}

	instanceIDs, err := instanceidhandler.GenerateInstanceID(workload)
	if err != nil {
		return nil, fmt.Errorf("fail to create InstanceID to pod %s in namespace %s with error: %v", pod.GetName(), pod.GetNamespace(), err)
	}
	instanceID := getInstanceID(instanceIDs, pod.Status.ContainerStatuses[containerIndex].Name)
	return conthandlerV1.CreateNewContainerEvent(pod.Status.ContainerStatuses[containerIndex].ImageID, pod.Status.ContainerStatuses[containerIndex].ContainerID, pod.GetName(), parentWlid, instanceID, conthandlerV1.ContainerRunning), nil
}

func (containerWatcher *ContainerWatcher) StartWatchedOnContainers(containerEventChannel chan conthandlerV1.ContainerEventData) error {
	logger.L().Info("Ready to watch over node", helpers.String("node name", containerWatcher.nodeName))
	for {
		watcher, err := containerWatcher.ContainerClient.GetWatcher()
		if err != nil {
			logger.L().Ctx(context.GetBackgroundContext()).Error("GetWatcher err", helpers.Error(err))
			continue
		}
		for {
			event, chanActive := <-watcher.ResultChan()
			if !chanActive {
				watcher.Stop()
				break
			}
			if event.Type == watch.Error {
				watcher.Stop()
				break
			}

			pod, ok := event.Object.(*core.Pod)
			if !ok {
				continue
			}

			switch event.Type {
			case watch.Modified:
				for i := range pod.Status.ContainerStatuses {
					if pod.Status.ContainerStatuses[i].Started != nil && *pod.Status.ContainerStatuses[i].Started {
						logger.L().Debug("container has started", helpers.String("namespace", pod.GetNamespace()), helpers.String("Pod name", pod.GetName()), helpers.String("ContainerID", pod.Status.ContainerStatuses[i].ContainerID), helpers.String("Container name", pod.Status.ContainerStatuses[i].Name))
						if pod.GetNamespace() == config.GetConfigurationConfigContext().GetNamespace() && pod.GetName() == config.GetConfigurationConfigContext().GetContainerName() {
							continue
						}
						containerEventData, err := containerWatcher.parsePodData(pod, i)
						if err != nil {
							logger.L().Ctx(context.GetBackgroundContext()).Error("failed to parse container data", helpers.String("namespace", pod.GetNamespace()), helpers.String("Pod name", pod.GetName()), helpers.String("ContainerID", pod.Status.ContainerStatuses[i].ContainerID), helpers.String("Container name", pod.Status.ContainerStatuses[i].Name), helpers.Error(err))
							continue
						}
						containerEventChannel <- *containerEventData
					} else if pod.Status.ContainerStatuses[i].State.Terminated != nil {
						logger.L().Debug("container has Terminated", helpers.String("namespace", pod.GetNamespace()), helpers.String("Pod name", pod.GetName()), helpers.String("ContainerID", pod.Status.ContainerStatuses[i].ContainerID), helpers.String("Container name", pod.Status.ContainerStatuses[i].Name))
						containerEventData := conthandlerV1.CreateNewContainerEvent("", pod.Status.ContainerStatuses[i].ContainerID, "", "", instanceidhandler.InstanceID{}, conthandlerV1.ContainerDeleted)
						containerEventChannel <- *containerEventData
					}
				}
			}
		}
	}

}
