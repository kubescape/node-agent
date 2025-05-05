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

func (sc Storage) GetNetworkNeighborhood(namespace, name string) (*v1beta1.NetworkNeighborhood, error) {
	nn, err := sc.StorageClient.NetworkNeighborhoods(namespace).Get(context.Background(), sc.modifyName(name), v1.GetOptions{})
	if nn != nil {
		sc.revertNameP(&nn.Name)
	}
	return nn, err
}

func (sc Storage) CreateNetworkNeighborhood(neighborhood *v1beta1.NetworkNeighborhood, namespace string) error {
	sc.modifyNameP(&neighborhood.Name)
	defer sc.revertNameP(&neighborhood.Name)

	// unset resourceVersion
	neighborhood.ResourceVersion = ""
	_, err := sc.StorageClient.NetworkNeighborhoods(namespace).Create(context.Background(), neighborhood, v1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (sc Storage) PatchNetworkNeighborhood(name, namespace string, operations []utils.PatchOperation, watchedContainer *utils.WatchedContainerData) error {
	logger.L().Debug("Storage - patching network neighborhood", loggerhelpers.String("name", name), loggerhelpers.String("namespace", namespace), loggerhelpers.Int("operations", len(operations)))
	// split operations into max JSON operations batches
	for _, chunk := range utils.ChunkBy(operations, sc.maxJsonPatchOperations) {
		if err := sc.patchNetworkNeighborhood(name, namespace, chunk, watchedContainer); err != nil {
			return err
		}
	}
	return nil
}

func (sc Storage) patchNetworkNeighborhood(name, namespace string, operations []utils.PatchOperation, watchedContainer *utils.WatchedContainerData) error {
	patch, err := json.Marshal(operations)
	if err != nil {
		return fmt.Errorf("marshal patch: %w", err)
	}

	backOff := backoff.NewExponentialBackOff()
	backOff.MaxInterval = 10 * time.Second
	neighborhood, err := backoff.Retry(context.Background(), func() (*v1beta1.NetworkNeighborhood, error) {
		neighborhood, err := sc.StorageClient.NetworkNeighborhoods(namespace).Patch(context.Background(), sc.modifyName(name), types.JSONPatchType, patch, v1.PatchOptions{})
		switch {
		case apierrors.IsTimeout(err), apierrors.IsServerTimeout(err), apierrors.IsTooManyRequests(err):
			return nil, apierrors.NewTimeoutError("backoff timeout", 0)
		case err != nil:
			return nil, backoff.Permanent(err)
		default:
			return neighborhood, nil
		}
	}, backoff.WithBackOff(backOff), backoff.WithMaxElapsedTime(sc.maxElapsedTime))
	if err != nil {
		return fmt.Errorf("patch network neighborhood: %w", err)
	}
	// check if returned neighborhood is full
	if status, ok := neighborhood.Annotations[helpers.StatusMetadataKey]; ok && status == helpers.TooLarge {
		watchedContainer.SyncChannel <- utils.TooLargeObjectError
		return nil
	}

	// check if returned neighborhood is completed
	if s, ok := neighborhood.Annotations[helpers.StatusMetadataKey]; ok && s == helpers.Complete {
		watchedContainer.SyncChannel <- utils.ObjectCompleted
		return nil
	}

	// retrigger the patch if the storage profile is complete and the locally stored profile is partial
	if completion, ok := neighborhood.Annotations[helpers.CompletionMetadataKey]; ok && completion == helpers.Complete &&
		watchedContainer.GetCompletionStatus() == helpers.Partial {
		watchedContainer.SetCompletionStatus(utils.WatchedContainerCompletionStatusFull)
		logger.L().Debug("Storage - retriggering patch",
			loggerhelpers.String("name", name),
			loggerhelpers.String("namespace", namespace),
			loggerhelpers.String("watchedContainer", watchedContainer.ContainerID),
			loggerhelpers.String("completion", helpers.Complete))
		sc.patchNetworkNeighborhood(name, namespace, operations, watchedContainer)
	}

	return nil
}
