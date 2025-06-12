package storage

import (
	"context"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CreateContainerProfile queues a container profile for creation with persistent storage
func (sc *Storage) CreateContainerProfile(profile *v1beta1.ContainerProfile, namespace string) error {
	// Apply name modifications if needed (keeping your existing logic)
	// sc.modifyNameP(&profile.Name)
	// defer sc.revertNameP(&profile.Name)

	// Unset resourceVersion
	profile.ResourceVersion = ""

	// Set namespace in profile metadata if not already set
	if profile.Namespace == "" {
		profile.Namespace = namespace
	}

	// First try to create the profile directly
	if err := sc.CreateContainerProfileDirect(profile); err == nil {
		logger.L().Debug("container profile created directly", helpers.String("name", profile.Name), helpers.String("namespace", profile.Namespace))
		return nil
	} else {
		logger.L().Debug("failed to create container profile directly, queuing for later", helpers.String("name", profile.Name), helpers.String("namespace", profile.Namespace), helpers.Error(err))
	}

	// Try to enqueue the profile
	if err := sc.queueData.Enqueue(profile); err != nil {
		logger.L().Error("failed to enqueue container profile for creation",
			helpers.String("name", profile.Name),
			helpers.String("namespace", profile.Namespace),
			helpers.Error(err))
		return err
	}

	return nil
}

// CreateContainerProfileDirect directly creates the profile without queuing
// This implements the ProfileCreator interface
func (sc *Storage) CreateContainerProfileDirect(profile *v1beta1.ContainerProfile) error {
	_, err := sc.StorageClient.ContainerProfiles(profile.Namespace).Create(context.Background(), profile, metav1.CreateOptions{})
	return err
}
