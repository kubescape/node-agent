package conthandler

import (
	"context"
	"encoding/json"

	"sniffer/pkg/config"
	conthandlerV1 "sniffer/pkg/conthandler/v1"

	wlid "github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
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
	globalHTTPContext := context.Background()
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
						pod.TypeMeta.Kind = "Pod"
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
						kind, name, err := containerWatcher.ContainerClient.CalculateWorkloadParentRecursive(workload)
						if err != nil {
							logger.L().Error("fail to get workload owner parent", []helpers.IDetails{helpers.String("%s", pod.GetName()), helpers.String(" in namespace %s", pod.GetNamespace())}...)
							continue
						}
						parentWorkload, err := containerWatcher.ContainerClient.GetWorkload(pod.GetNamespace(), kind, name)
						if err != nil {
							logger.L().Error("fail to get parent workload", []helpers.IDetails{helpers.String("%s", pod.GetName()), helpers.String(" in namespace %s", pod.GetNamespace())}...)
							continue
						}
						parentWlid := containerWatcher.ContainerClient.GenerateWLID(parentWorkload, config.GetConfigurationConfigContext().GetClusterName())
						err = wlid.IsWlidValid(parentWlid)
						if err != nil {
							logger.L().Error("WLID of parent workload is not in the right form", []helpers.IDetails{helpers.String("", pod.GetName()), helpers.String(" in namespace ", pod.GetNamespace()), helpers.Error(err)}...)
							continue
						}

						instanceID, err := conthandlerV1.CreateInstanceID(containerWatcher.ContainerClient.GetApiVersion(parentWorkload), containerWatcher.ContainerClient.GetResourceVersion(parentWorkload), parentWlid, pod.Status.ContainerStatuses[i].Name)
						if err != nil {
							logger.L().Error("fail to create InstanceID to pod ", []helpers.IDetails{helpers.String("%s", pod.GetName()), helpers.String(" in namespace %s with err ", pod.GetNamespace()), helpers.Error(err)}...)
							continue
						}
						containerEventData := conthandlerV1.CreateNewContainerEvent(pod.Status.ContainerStatuses[i].ImageID, pod.Status.ContainerStatuses[i].ContainerID, pod.GetName(), parentWlid, instanceID, conthandlerV1.ContainerRunning)
						containerEventChannel <- *containerEventData
					}
				}
			}
		}
	}

}
