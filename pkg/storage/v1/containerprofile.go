package storage

import (
	"context"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (sc *Storage) GetContainerProfile(ctx context.Context, namespace, name string) (*v1beta1.ContainerProfile, error) {
	return sc.storageClient.ContainerProfiles(namespace).Get(ctx, name, metav1.GetOptions{})
}

// CreateContainerProfileDirect directly creates the profile without queuing.
// This implements the ProfileCreator interface.
func (sc *Storage) CreateContainerProfileDirect(profile *v1beta1.ContainerProfile) error {
	// Apply name modifications if needed (keeping your existing logic)
	// sc.modifyNameP(&profile.Name)
	// defer sc.revertNameP(&profile.Name)

	// Unset resourceVersion
	profile.ResourceVersion = ""

	_, err := sc.storageClient.ContainerProfiles(profile.Namespace).Create(context.Background(), profile, metav1.CreateOptions{})
	return err
}
