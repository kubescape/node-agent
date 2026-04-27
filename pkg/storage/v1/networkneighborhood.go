package storage

import (
	"context"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (sc *Storage) GetNetworkNeighborhood(ctx context.Context, namespace, name string) (*v1beta1.NetworkNeighborhood, error) {
	return sc.storageClient.NetworkNeighborhoods(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (sc *Storage) ListNetworkNeighborhoods(ctx context.Context, namespace string, limit int64, cont string) (*v1beta1.NetworkNeighborhoodList, error) {
	return sc.storageClient.NetworkNeighborhoods(namespace).List(ctx, metav1.ListOptions{
		Limit:    limit,
		Continue: cont,
	})
}
