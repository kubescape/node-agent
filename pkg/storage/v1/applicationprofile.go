package storage

import (
	"context"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (sc *Storage) GetApplicationProfile(ctx context.Context, namespace, name string) (*v1beta1.ApplicationProfile, error) {
	return sc.storageClient.ApplicationProfiles(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (sc *Storage) ListApplicationProfiles(ctx context.Context, namespace string, limit int64, cont string) (*v1beta1.ApplicationProfileList, error) {
	return sc.storageClient.ApplicationProfiles(namespace).List(ctx, metav1.ListOptions{
		Limit:    limit,
		Continue: cont,
	})
}
