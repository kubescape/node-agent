package storage

import (
	"context"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (sc Storage) CreateContainerProfile(profile *v1beta1.ContainerProfile, namespace string) error {
	// TODO: Check if we need the modfiyNameP and revertNameP functions for container profiles.
	// sc.modifyNameP(&profile.Name)
	// defer sc.revertNameP(&profile.Name)

	// Unset resourceVersion
	profile.ResourceVersion = ""
	// TODO: Implement a queue that will save on the disk and retry later if the API server is not available.
	_, err := sc.StorageClient.ContainerProfiles(namespace).Create(context.Background(), profile, v1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}
