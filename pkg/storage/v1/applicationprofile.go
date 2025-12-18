package storage

import (
	"context"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (sc *Storage) GetApplicationProfile(namespace, name string) (*v1beta1.ApplicationProfile, error) {
	return sc.storageClient.ApplicationProfiles(namespace).Get(context.Background(), name, metav1.GetOptions{})
}

func (sc *Storage) ListApplicationProfiles(namespace string, limit int64, cont string) (*v1beta1.ApplicationProfileList, error) {
	return sc.storageClient.ApplicationProfiles(namespace).List(context.Background(), metav1.ListOptions{
		Limit:    limit,
		Continue: cont,
	})
}
