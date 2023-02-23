package conthandler

import (
	"context"
	"encoding/json"

	"sniffer/pkg/config"
	conthandlerV1 "sniffer/pkg/conthandler/v1"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
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
	globalHTTPContext := context.Background()
	return client.k8sClient.KubernetesClient.CoreV1().Pods("").Watch(globalHTTPContext, v1.ListOptions{})
}

func (containerWatcher *ContainerWatcher) StartWatchedOnContainers(containerEventChannel chan conthandlerV1.ContainerEventData) error {
	logger.L().Info("", helpers.String("sniffer is ready to watch over node %s", containerWatcher.nodeName))

	for {
		watcher, err := containerWatcher.ContainerClient.GetWatcher()
		if err != nil {
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
						podBytes, err := json.Marshal(pod)
						if err != nil {
							logger.L().Error("fail to unmarshal pod ", []helpers.IDetails{helpers.String("%s", pod.GetName()), helpers.String(" in namespace %s with error: ", pod.GetNamespace()), helpers.Error(err)}...)
							continue
						}
						workload, err := workloadinterface.NewWorkload(podBytes)
						if err != nil {
							logger.L().Error("fail to create workload ID to pod ", []helpers.IDetails{helpers.String("%s", pod.GetName()), helpers.String(" in namespace %s", pod.GetNamespace())}...)
							continue
						}
						wlid := workload.GenerateWlid(config.GetConfigurationConfigContext().GetClusterName())
						instanceID := conthandlerV1.CreateInstanceID(workload, wlid, pod.Status.ContainerStatuses[i].Name)
						containerEventData := conthandlerV1.CreateNewContainerEvent(pod.Status.ContainerStatuses[i].ImageID, pod.Status.ContainerStatuses[i].ContainerID, pod.GetName(), wlid, instanceID, conthandlerV1.CONTAINER_RUNNING)
						containerEventChannel <- *containerEventData
					}
				}
			}
		}
	}

}
