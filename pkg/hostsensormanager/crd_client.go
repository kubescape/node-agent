package hostsensormanager

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// CRDClient handles Kubernetes CRD operations
type CRDClient struct {
	dynamicClient dynamic.Interface
	nodeName      string
}

// NewCRDClient creates a new CRD client
func NewCRDClient(nodeName string) (*CRDClient, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	return &CRDClient{
		dynamicClient: dynamicClient,
		nodeName:      nodeName,
	}, nil
}

// CreateOrUpdateOsReleaseFile creates or updates an OsReleaseFile CRD
func (c *CRDClient) CreateOrUpdateOsReleaseFile(ctx context.Context, spec *OsReleaseFileSpec) error {
	gvr := schema.GroupVersionResource{
		Group:    HostDataGroup,
		Version:  HostDataVersion,
		Resource: "osreleasefiles",
	}

	// Create the CRD object
	osReleaseFile := &OsReleaseFile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: fmt.Sprintf("%s/%s", HostDataGroup, HostDataVersion),
			Kind:       "OsReleaseFile",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: c.nodeName,
		},
		Spec: *spec,
		Status: OsReleaseFileStatus{
			LastSensed: metav1.Now(),
		},
	}

	// Convert to unstructured
	unstructuredObj, err := toUnstructured(osReleaseFile)
	if err != nil {
		return fmt.Errorf("failed to convert to unstructured: %w", err)
	}

	// Try to get existing resource
	existing, err := c.dynamicClient.Resource(gvr).Get(ctx, c.nodeName, metav1.GetOptions{})
	if err != nil {
		// Resource doesn't exist, create it
		logger.L().Debug("creating new OsReleaseFile CRD", helpers.String("nodeName", c.nodeName))
		_, err = c.dynamicClient.Resource(gvr).Create(ctx, unstructuredObj, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create OsReleaseFile CRD: %w", err)
		}
		logger.L().Info("created OsReleaseFile CRD", helpers.String("nodeName", c.nodeName))
		return nil
	}

	// Resource exists, update it using patch
	logger.L().Debug("updating existing OsReleaseFile CRD", helpers.String("nodeName", c.nodeName))

	// Preserve the resource version
	unstructuredObj.SetResourceVersion(existing.GetResourceVersion())

	// Create patch data
	patchData, err := json.Marshal(map[string]interface{}{
		"spec": spec,
		"status": OsReleaseFileStatus{
			LastSensed: metav1.Now(),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal patch data: %w", err)
	}

	_, err = c.dynamicClient.Resource(gvr).Patch(ctx, c.nodeName, types.MergePatchType, patchData, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("failed to patch OsReleaseFile CRD: %w", err)
	}

	logger.L().Debug("updated OsReleaseFile CRD", helpers.String("nodeName", c.nodeName))
	return nil
}

// UpdateStatus updates the status of an OsReleaseFile CRD with an error
func (c *CRDClient) UpdateStatus(ctx context.Context, errorMsg string) error {
	gvr := schema.GroupVersionResource{
		Group:    HostDataGroup,
		Version:  HostDataVersion,
		Resource: "osreleasefiles",
	}

	patchData, err := json.Marshal(map[string]interface{}{
		"status": OsReleaseFileStatus{
			LastSensed: metav1.Now(),
			Error:      errorMsg,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal patch data: %w", err)
	}

	_, err = c.dynamicClient.Resource(gvr).Patch(ctx, c.nodeName, types.MergePatchType, patchData, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	return nil
}

// toUnstructured converts a typed object to unstructured
func toUnstructured(obj interface{}) (*unstructured.Unstructured, error) {
	data, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	var unstructuredObj unstructured.Unstructured
	err = json.Unmarshal(data, &unstructuredObj.Object)
	if err != nil {
		return nil, err
	}

	return &unstructuredObj, nil
}
