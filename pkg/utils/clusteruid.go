package utils

import (
	"context"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// GetClusterUID retrieves the UID of the kube-system namespace to use as a stable cluster identifier.
// If the namespace cannot be accessed (e.g., due to RBAC restrictions), it returns an empty string and logs a warning.
func GetClusterUID(k8sClient kubernetes.Interface) string {
	   ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
       defer cancel()
	namespace, err := k8sClient.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to get kube-system namespace for ClusterUID", helpers.Error(err))
		return ""
	}
	
	clusterUID := string(namespace.UID)
	logger.L().Ctx(ctx).Info("successfully retrieved ClusterUID", helpers.String("clusterUID", clusterUID))
	return clusterUID
}
