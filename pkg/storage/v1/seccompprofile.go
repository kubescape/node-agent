package storage

import (
	"context"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

// StorageSeccompProfileClient implements SeccompProfileClient using the aggregated API storage backend
type StorageSeccompProfileClient struct {
	storageClient spdxv1beta1.SpdxV1beta1Interface
}

// NewStorageSeccompProfileClient creates a new storage-backed SeccompProfile client
func NewStorageSeccompProfileClient(storageClient spdxv1beta1.SpdxV1beta1Interface) *StorageSeccompProfileClient {
	return &StorageSeccompProfileClient{
		storageClient: storageClient,
	}
}

func (c *StorageSeccompProfileClient) WatchSeccompProfiles(namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	opts.ResourceVersion = softwarecomposition.ResourceVersionFullSpec
	return c.storageClient.SeccompProfiles(namespace).Watch(context.Background(), opts)
}

func (c *StorageSeccompProfileClient) ListSeccompProfiles(namespace string, opts metav1.ListOptions) (*v1beta1.SeccompProfileList, error) {
	opts.ResourceVersion = softwarecomposition.ResourceVersionFullSpec
	return c.storageClient.SeccompProfiles(namespace).List(context.Background(), opts)
}

func (c *StorageSeccompProfileClient) GetSeccompProfile(namespace, name string) (*v1beta1.SeccompProfile, error) {
	return c.storageClient.SeccompProfiles(namespace).Get(context.Background(), name, metav1.GetOptions{
		ResourceVersion: softwarecomposition.ResourceVersionFullSpec,
	})
}

