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
	"github.com/kubescape/storage/pkg/apis/softwarecomposition"
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
		switch err := sc.patchNetworkNeighborhood(name, namespace, chunk, watchedContainer); err {
		case nil:
			// next chunk
			continue
		case utils.ObjectCompleted, utils.TooLargeObjectError:
			// no need to continue patching
			return nil
		default:
			// abort patching
			return err
		}
	}
	return nil
}

func (sc Storage) patchNetworkNeighborhood(name, namespace string, operations []utils.PatchOperation, watchedContainer *utils.WatchedContainerData) error {
	// check if an existing network neighborhood exists and it's completed
	backOff := backoff.NewExponentialBackOff()
	backOff.MaxInterval = 10 * time.Second
	existingNeighborhood, err := backoff.Retry(context.Background(), func() (*v1beta1.NetworkNeighborhood, error) {
		neighborhood, err := sc.StorageClient.NetworkNeighborhoods(namespace).Get(context.Background(), sc.modifyName(name), v1.GetOptions{ResourceVersion: softwarecomposition.ResourceVersionMetadata})
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
		return fmt.Errorf("get network neighborhood: %w", err)
	}
	if existingNeighborhood != nil {
		// check if returned profile is full
		if status, ok := existingNeighborhood.Annotations[helpers.StatusMetadataKey]; ok && status == helpers.TooLarge {
			watchedContainer.SyncChannel <- utils.TooLargeObjectError
			return utils.TooLargeObjectError
		}
		// check if returned profile is completed
		if IsComplete(existingNeighborhood.Annotations, watchedContainer.GetCompletionStatus()) {
			watchedContainer.SyncChannel <- utils.ObjectCompleted
			return utils.ObjectCompleted
		}
	}

	patch, err := json.Marshal(operations)
	if err != nil {
		return fmt.Errorf("marshal patch: %w", err)
	}

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
		return utils.TooLargeObjectError
	}

	// check if returned neighborhood is completed
	if IsComplete(neighborhood.Annotations, watchedContainer.GetCompletionStatus()) {
		watchedContainer.SyncChannel <- utils.ObjectCompleted
		return utils.ObjectCompleted
	}

	// retrigger the patch if the storage profile is complete and the locally stored profile is partial
	if IsSeenFromStart(neighborhood.Annotations, watchedContainer) {
		watchedContainer.SetCompletionStatus(utils.WatchedContainerCompletionStatusFull)
		logger.L().Debug("Storage - retriggering network neighborhood patch",
			loggerhelpers.String("name", name),
			loggerhelpers.String("namespace", namespace),
			loggerhelpers.String("watchedContainer", watchedContainer.ContainerID),
			loggerhelpers.String("completion", helpers.Full))
		return sc.patchNetworkNeighborhood(name, namespace, operations, watchedContainer)
	}

	return nil
}
