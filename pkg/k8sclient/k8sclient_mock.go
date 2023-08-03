package k8sclient

import (
	"node-agent/pkg/storage"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
)

type K8sClientMock struct{}

var _ K8sClientInterface = (*K8sClientMock)(nil)

func (k K8sClientMock) GetWorkload(namespace, _, name string) (k8sinterface.IWorkload, error) {
	return workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": namespace,
		},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "cont",
					"image": "nginx",
				},
			},
		},
		"status": map[string]interface{}{
			"containerStatuses": []interface{}{
				map[string]interface{}{
					"name":    "cont",
					"imageID": storage.NginxImageID,
				},
			},
		},
	}), nil
}

func (k K8sClientMock) CalculateWorkloadParentRecursive(workload k8sinterface.IWorkload) (string, string, error) {
	return workload.GetKind(), workload.GetName(), nil
}
