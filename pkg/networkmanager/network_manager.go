package networkmanager

import (
	"context"
	"fmt"
	"node-agent/pkg/config"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/storage"

	"github.com/armosec/utils-k8s-go/wlid"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
)

type NetworkManager struct {
	cfg                      config.Config
	ctx                      context.Context
	k8sClient                k8sclient.K8sClientInterface
	storageClient            storage.StorageClient
	containerAndPodToWLIDMap map[string]string
	clusterName              string
}

func CreateNetworkManager(ctx context.Context, cfg config.Config, k8sClient k8sclient.K8sClientInterface, storageClient storage.StorageClient, clusterName string) (*NetworkManager, error) {
	return &NetworkManager{
		cfg:                      cfg,
		ctx:                      ctx,
		k8sClient:                k8sClient,
		storageClient:            storageClient,
		containerAndPodToWLIDMap: make(map[string]string),
		clusterName:              clusterName,
	}, nil
}

func (am *NetworkManager) ContainerCallback(notif containercollection.PubSubEvent) {
	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		am.handleContainerStarted(notif.Container)

	case containercollection.EventTypeRemoveContainer:
	}
}

func (am *NetworkManager) handleContainerStarted(container *containercollection.Container) {
	// retrieve parent WL
	parentWL, err := am.getParentWorkloadFromContainer(container)
	if err != nil {
		fmt.Println(err.Error())
	}

	// TODO: check if it has network neighbor on storage

	// If yes, update labels

	// If not, create CRD
	networkNeighbors := &NetworkNeighbors{
		Kind: "NetworkNeighbors",
		Metadata: Metadata{
			Name:      fmt.Sprintf("%s-%s", parentWL.GetKind(), parentWL.GetName()),
			Kind:      parentWL.GetKind(),
			Namespace: parentWL.GetNamespace(),
			// add workload labels
		},
		Spec: Spec{
			// add match labels
			Labels: parentWL.GetInnerLabels(),
		},
	}
	am.publishNetworkNeighbors(networkNeighbors)

	// save container + pod to wlid map
	am.containerAndPodToWLIDMap[container.Runtime.ContainerID+container.K8s.PodName] = parentWL.GenerateWlid(am.clusterName)

}

func (am *NetworkManager) publishNetworkNeighbors(networkNeighbor *NetworkNeighbors) {
	// publish to storage
}

func (am *NetworkManager) getParentWorkloadFromContainer(container *containercollection.Container) (k8sinterface.IWorkload, error) {
	wl, err := am.k8sClient.GetWorkload(container.K8s.Namespace, "Pod", container.K8s.PodName)
	if err != nil {
		return nil, err
	}
	pod := wl.(*workloadinterface.Workload)
	// find parentWlid
	kind, name, err := am.k8sClient.CalculateWorkloadParentRecursive(pod)
	if err != nil {
		return nil, err
	}
	parentWorkload, err := am.k8sClient.GetWorkload(pod.GetNamespace(), kind, name)
	if err != nil {
		return nil, err
	}
	w := parentWorkload.(*workloadinterface.Workload)
	parentWlid := w.GenerateWlid(am.clusterName)
	err = wlid.IsWlidValid(parentWlid)
	if err != nil {
		return nil, err
	}
	return parentWorkload, nil
}

func (am *NetworkManager) handleContainerStopped(container *containercollection.Container) {
	// clean map
}
