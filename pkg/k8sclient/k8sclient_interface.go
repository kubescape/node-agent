package k8sclient

import (
	"github.com/kubescape/k8s-interface/k8sinterface"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

type K8sClientInterface interface {
	GetWorkload(namespace, kind, name string) (k8sinterface.IWorkload, error)
	CalculateWorkloadParentRecursive(workload k8sinterface.IWorkload) (string, string, error)
	GetKubernetesClient() kubernetes.Interface
	GetDynamicClient() dynamic.Interface
}
