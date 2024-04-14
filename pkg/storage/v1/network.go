package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"node-agent/pkg/utils"
	"strconv"
)

func (sc Storage) GetNetworkNeighborhood(namespace, name string) (*v1beta1.NetworkNeighborhood, error) {
	return sc.StorageClient.NetworkNeighborhoods(namespace).Get(context.Background(), name, v1.GetOptions{})
}

func (sc Storage) CreateNetworkNeighborhood(neighborhood *v1beta1.NetworkNeighborhood, namespace string) error {
	// unset resourceVersion
	neighborhood.ResourceVersion = ""
	_, err := sc.StorageClient.NetworkNeighborhoods(namespace).Create(context.Background(), neighborhood, v1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (sc Storage) PatchNetworkNeighborhood(name, namespace string, patch []byte, channel chan error) error {
	neighborhood, err := sc.StorageClient.NetworkNeighborhoods(namespace).Patch(context.Background(), name, types.JSONPatchType, patch, v1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("patch application neighborhood: %w", err)
	}
	// check if returned neighborhood is full
	if s, ok := neighborhood.Annotations[helpers.StatusMetadataKey]; ok {
		if s == helpers.TooLarge {
			if channel != nil {
				channel <- utils.TooLargeObjectError
			}
		}
		return nil
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
			_, err = sc.StorageClient.NetworkNeighborhoods(namespace).Patch(context.Background(), name, types.JSONPatchType, annotationsPatch, v1.PatchOptions{})
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
