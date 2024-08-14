package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/kubescape/node-agent/pkg/utils"

	"github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
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

func (sc Storage) PatchNetworkNeighborhood(name, namespace string, operations []utils.PatchOperation, channel chan error) error {
	// split operations into max JSON operations batches
	for _, chunk := range utils.ChunkBy(operations, sc.maxJsonPatchOperations) {
		if err := sc.patchNetworkNeighborhood(name, namespace, chunk, channel); err != nil {
			return err
		}
	}
	return nil
}

func (sc Storage) patchNetworkNeighborhood(name, namespace string, operations []utils.PatchOperation, channel chan error) error {
	patch, err := json.Marshal(operations)
	if err != nil {
		return fmt.Errorf("marshal patch: %w", err)
	}
	neighborhood, err := sc.StorageClient.NetworkNeighborhoods(namespace).Patch(context.Background(), sc.modifyName(name), types.JSONPatchType, patch, v1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("patch application neighborhood: %w", err)
	}
	// check if returned neighborhood is full
	if status, ok := neighborhood.Annotations[helpers.StatusMetadataKey]; ok && status == helpers.TooLarge {
		if channel != nil {
			channel <- utils.TooLargeObjectError
		}
		return nil
	}
	// check if returned profile is completed
	if c, ok := neighborhood.Annotations[helpers.CompletionMetadataKey]; ok {
		if s, ok := neighborhood.Annotations[helpers.StatusMetadataKey]; ok && s == helpers.Complete && c == helpers.Completed {
			if channel != nil {
				channel <- utils.ObjectCompleted
			}
			return nil
		}
	}

	// check if returned neighborhood is too big
	if s, ok := neighborhood.Annotations[helpers.ResourceSizeMetadataKey]; ok {
		size, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("parse size: %w", err)
		}
		if size > sc.maxNetworkNeighborhoodSize {
			// add annotation to indicate that the neighborhood is full
			annotationOperations := []utils.PatchOperation{
				{
					Op:    "replace",
					Path:  "/metadata/annotations/" + utils.EscapeJSONPointerElement(helpers.StatusMetadataKey),
					Value: helpers.TooLarge,
				},
			}
			annotationsPatch, err := json.Marshal(annotationOperations)
			if err != nil {
				return fmt.Errorf("create patch for annotations: %w", err)
			}
			_, err = sc.StorageClient.NetworkNeighborhoods(namespace).Patch(context.Background(), sc.modifyName(name), types.JSONPatchType, annotationsPatch, v1.PatchOptions{})
			if err != nil {
				return fmt.Errorf("patch application neighborhood annotations: %w", err)
			}
			if channel != nil {
				channel <- utils.TooLargeObjectError
			}
		}
	}
	return nil
}
