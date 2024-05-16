package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"node-agent/pkg/utils"
	"strconv"

	"github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
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

func (sc Storage) PatchApplicationProfile(name, namespace string, patch []byte, channel chan error) error {
	profile, err := sc.StorageClient.ApplicationProfiles(namespace).Patch(context.Background(), sc.modifyName(name), types.JSONPatchType, patch, v1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("patch application profile: %w", err)
	}
	// check if returned profile is full
	if s, ok := profile.Annotations[helpers.StatusMetadataKey]; ok {
		if s == helpers.TooLarge {
			if channel != nil {
				channel <- utils.TooLargeObjectError
			}
		}
		return nil
	}
	// check if returned profile is completed
	if c, ok := profile.Annotations[helpers.CompletionMetadataKey]; ok {
		if s, ok := profile.Annotations[helpers.StatusMetadataKey]; ok {
			if s == helpers.Complete && c == helpers.Completed {
				if channel != nil {
					channel <- utils.ObjectCompleted
				}
			}
		}
		return nil
	}
	// check if returned profile is too big
	if s, ok := profile.Annotations[helpers.ResourceSizeMetadataKey]; ok {
		size, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("parse size: %w", err)
		}
		if size > sc.maxApplicationProfileSize {
			// add annotation to indicate that the profile is full
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
			_, err = sc.StorageClient.ApplicationProfiles(namespace).Patch(context.Background(), sc.modifyName(name), types.JSONPatchType, annotationsPatch, v1.PatchOptions{})
			if err != nil {
				return fmt.Errorf("patch application profile annotations: %w", err)
			}
			if channel != nil {
				channel <- utils.TooLargeObjectError
			}
		}
	}
	return nil
}
