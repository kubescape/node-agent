package hostsensormanager

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

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

// CreateOrUpdateHostData creates or updates a host data CRD
func (c *CRDClient) CreateOrUpdateHostData(ctx context.Context, resource string, kind string, spec interface{}) error {
	gvr := schema.GroupVersionResource{
		Group:    HostDataGroup,
		Version:  HostDataVersion,
		Resource: resource,
	}

	// Create the unstructured object
	unstructuredObj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": fmt.Sprintf("%s/%s", HostDataGroup, HostDataVersion),
			"kind":       kind,
			"metadata": map[string]interface{}{
				"name": c.nodeName,
			},
			"spec": spec,
			"status": map[string]interface{}{
				"lastSensed": metav1.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	// Try to get existing resource
	_, err := c.dynamicClient.Resource(gvr).Get(ctx, c.nodeName, metav1.GetOptions{})
	if err != nil {
		// Resource doesn't exist, create it
		logger.L().Debug("creating new host data CRD",
			helpers.String("kind", kind),
			helpers.String("nodeName", c.nodeName))
		_, err = c.dynamicClient.Resource(gvr).Create(ctx, unstructuredObj, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create %s CRD: %w", kind, err)
		}
		logger.L().Info("created host data CRD",
			helpers.String("kind", kind),
			helpers.String("nodeName", c.nodeName))
		return nil
	}

	// Resource exists, update it using patch
	logger.L().Debug("updating existing host data CRD",
		helpers.String("kind", kind),
		helpers.String("nodeName", c.nodeName))

	// Create patch data
	patchData, err := json.Marshal(map[string]interface{}{
		"spec": spec,
		"status": Status{
			LastSensed: metav1.Now(),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal patch data: %w", err)
	}

	_, err = c.dynamicClient.Resource(gvr).Patch(ctx, c.nodeName, types.MergePatchType, patchData, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("failed to patch %s CRD: %w", kind, err)
	}

	logger.L().Debug("updated host data CRD",
		helpers.String("kind", kind),
		helpers.String("nodeName", c.nodeName))
	return nil
}

// UpdateStatus updates the status of a host data CRD with an error
func (c *CRDClient) UpdateStatus(ctx context.Context, resource string, errorMsg string) error {
	gvr := schema.GroupVersionResource{
		Group:    HostDataGroup,
		Version:  HostDataVersion,
		Resource: resource,
	}

	patchData, err := json.Marshal(map[string]interface{}{
		"status": Status{
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
