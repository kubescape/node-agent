package k8sclient

import (
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
					"imageID": "nginx@sha256:6a59f1cbb8d28ac484176d52c473494859a512ddba3ea62a547258cf16c9b3ae",
				},
			},
		},
	}), nil
}

func (k K8sClientMock) CalculateWorkloadParentRecursive(workload k8sinterface.IWorkload) (string, string, error) {
	return workload.GetKind(), workload.GetName(), nil
}
