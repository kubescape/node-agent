package storage

import (
	"context"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (sc *Storage) GetNetworkNeighborhood(namespace, name string) (*v1beta1.NetworkNeighborhood, error) {
	return sc.storageClient.NetworkNeighborhoods(namespace).Get(context.Background(), name, metav1.GetOptions{})
}

func (sc *Storage) ListNetworkNeighborhoods(namespace string) (*v1beta1.NetworkNeighborhoodList, error) {
	return sc.storageClient.NetworkNeighborhoods(namespace).List(context.Background(), metav1.ListOptions{})
}
