package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/kubescape/go-logger"
	loggerhelpers "github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func (sc Storage) GetApplicationProfile(namespace, name string) (*v1beta1.ApplicationProfile, error) {
	ap, err := sc.StorageClient.ApplicationProfiles(namespace).Get(context.Background(), sc.modifyName(name), v1.GetOptions{})
	if ap != nil {
		sc.revertNameP(&ap.Name)
	}
	return ap, err
}

func (sc Storage) CreateApplicationProfile(profile *v1beta1.ApplicationProfile, namespace string) error {
	sc.modifyNameP(&profile.Name)
	defer sc.revertNameP(&profile.Name)

	// unset resourceVersion
	profile.ResourceVersion = ""
	_, err := sc.StorageClient.ApplicationProfiles(namespace).Create(context.Background(), profile, v1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (sc Storage) PatchApplicationProfile(name, namespace string, operations []utils.PatchOperation, watchedContainer *utils.WatchedContainerData) error {
	logger.L().Debug("Storage - patching application profile",
		loggerhelpers.String("name", name),
		loggerhelpers.String("namespace", namespace),
		loggerhelpers.Int("operations", len(operations)),
		loggerhelpers.String("status", string(watchedContainer.GetStatus())),
		loggerhelpers.String("completion status", string(watchedContainer.GetCompletionStatus())))
	// split operations into max JSON operations batches
	for _, chunk := range utils.ChunkBy(operations, sc.maxJsonPatchOperations) {
		if err := sc.patchApplicationProfile(name, namespace, chunk, watchedContainer); err != nil {
			return err
		}
	}
	return nil
}

func (sc Storage) patchApplicationProfile(name, namespace string, operations []utils.PatchOperation, watchedContainer *utils.WatchedContainerData) error {
	patch, err := json.Marshal(operations)
	if err != nil {
		return fmt.Errorf("marshal patch: %w", err)
	}

	backOff := backoff.NewExponentialBackOff()
	backOff.MaxInterval = 10 * time.Second
	profile, err := backoff.Retry(context.Background(), func() (*v1beta1.ApplicationProfile, error) {
		profile, err := sc.StorageClient.ApplicationProfiles(namespace).Patch(context.Background(), sc.modifyName(name), types.JSONPatchType, patch, v1.PatchOptions{})
		switch {
		case apierrors.IsTimeout(err), apierrors.IsServerTimeout(err), apierrors.IsTooManyRequests(err):
			return nil, apierrors.NewTimeoutError("backoff timeout", 0)
		case err != nil:
			return nil, backoff.Permanent(err)
		default:
			return profile, nil
		}
	}, backoff.WithBackOff(backOff), backoff.WithMaxElapsedTime(sc.maxElapsedTime))
	if err != nil {
		return fmt.Errorf("patch application profile: %w", err)
	}

	// check if returned profile is full
	if status, ok := profile.Annotations[helpers.StatusMetadataKey]; ok && status == helpers.TooLarge {
		watchedContainer.SyncChannel <- utils.TooLargeObjectError
		return nil
	}

	// check if returned profile is completed
	if IsComplete(profile.Annotations, watchedContainer.GetCompletionStatus()) {
		logger.L().Debug("ApplicationProfile - profile already completed",
			loggerhelpers.String("name", name),
			loggerhelpers.String("namespace", namespace),
			loggerhelpers.String("watchedContainer", watchedContainer.ContainerID),
			loggerhelpers.String("completion", string(watchedContainer.GetCompletionStatus())),
			loggerhelpers.String("status", string(watchedContainer.GetStatus())))
		watchedContainer.SyncChannel <- utils.ObjectCompleted
		return nil
	}

	// retrigger the patch if the storage profile is complete and the locally stored profile is partial
	if IsSeenFromStart(profile.Annotations, watchedContainer) {
		watchedContainer.SetCompletionStatus(utils.WatchedContainerCompletionStatusFull)
		logger.L().Debug("ApplicationProfile - retriggering patch because profile is complete from start",
			loggerhelpers.String("name", name),
			loggerhelpers.String("namespace", namespace),
			loggerhelpers.String("watchedContainer", watchedContainer.ContainerID),
			loggerhelpers.String("completion", helpers.Complete),
			loggerhelpers.String("status", string(watchedContainer.GetStatus())))
		sc.patchApplicationProfile(name, namespace, operations, watchedContainer)
	}

	return nil
}
