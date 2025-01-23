package k8sclient

import (
	"github.com/kubescape/node-agent/pkg/storage"

	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

type K8sClientMock struct {
	objects []runtime.Object
}

var _ K8sClientInterface = (*K8sClientMock)(nil)

func (k *K8sClientMock) GetWorkload(namespace, _, name string) (k8sinterface.IWorkload, error) {
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
					"name":  "log",
					"image": "fluentbit",
				},
				map[string]interface{}{
					"name":  "cont",
					"image": "nginx",
				},
			},
		},
		"status": map[string]interface{}{
			"containerStatuses": []interface{}{
				map[string]interface{}{
					"name":    "log",
					"imageID": storage.FluentBitImageID,
				},
				map[string]interface{}{
					"name":    "cont",
					"imageID": storage.NginxImageID,
				},
			},
		},
	}), nil
}

func (k *K8sClientMock) CalculateWorkloadParentRecursive(workload k8sinterface.IWorkload) (string, string, error) {
	return workload.GetKind(), workload.GetName(), nil
}
func (k *K8sClientMock) GetKubernetesClient() kubernetes.Interface {
	return k8sfake.NewSimpleClientset(k.objects...)
}
func (k *K8sClientMock) GetDynamicClient() dynamic.Interface {
	return dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), k.objects...)
}
