package cloudmetadata

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	k8sInterfaceCloudMetadata "github.com/kubescape/k8s-interface/cloudmetadata"
	"github.com/kubescape/k8s-interface/k8sinterface"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	azureApiVersion = "2021-12-13"
	metadataTimeout = 2 * time.Second
)

// GetCloudMetadata retrieves cloud metadata for a given node
func GetCloudMetadata(ctx context.Context, client *k8sinterface.KubernetesApi, nodeName string) (*apitypes.CloudMetadata, error) {
	node, err := client.GetKubernetesClient().CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get node %s: %v", nodeName, err)
	}

	cMetadata, err := k8sInterfaceCloudMetadata.GetCloudMetadata(ctx, node, nodeName)
	if err != nil {
		return nil, err
	}

	// special case for AWS, if the account ID is not found in the node metadata, we need to get it from ConfigMap
	enrichCloudMetadataForAWS(ctx, client, cMetadata)
	return cMetadata, nil
}

func enrichCloudMetadataForAWS(ctx context.Context, client *k8sinterface.KubernetesApi, cMetadata *apitypes.CloudMetadata) {
	if cMetadata == nil || cMetadata.Provider != k8sInterfaceCloudMetadata.ProviderAWS || cMetadata.AccountID != "" {
		return
	}

	cm, err := client.GetKubernetesClient().CoreV1().ConfigMaps("kube-system").Get(ctx, "aws-auth", metav1.GetOptions{})
	if err != nil {
		logger.L().Warning("failed to get aws-auth ConfigMap", helpers.Error(err))
		return
	}

	err = k8sInterfaceCloudMetadata.EnrichCloudMetadataFromAWSAuthConfigMap(cMetadata, cm)
	if err != nil {
		logger.L().Warning("failed to enrich cloud metadata from aws-auth ConfigMap", helpers.Error(err))
	}

	logger.L().Debug("enriched cloud metadata from aws-auth ConfigMap")
}

// GetCloudMetadataWithIMDS retrieves cloud metadata for a given node using IMDS
func GetCloudMetadataWithIMDS(ctx context.Context) (*apitypes.CloudMetadata, error) {
	cMetadataClient := k8sInterfaceCloudMetadata.NewMetadataClient(true)

	cMetadata, err := cMetadataClient.GetMetadata(ctx)
	if err == nil {
		return cMetadata, nil
	}

	logger.L().Info("failed to get cloud metadata from IMDS, trying fallbacks", helpers.Error(err))

	// Fallback strategy: try different providers
	fallbacks := []struct {
		name  string
		fetch func(context.Context) (*apitypes.CloudMetadata, error)
	}{
		{name: "DigitalOcean", fetch: fetchDigitalOceanMetadata},
		{name: "GCP", fetch: fetchGCPMetadata},
		{name: "Azure", fetch: fetchAzureMetadata},
	}

	for _, fb := range fallbacks {
		if meta, ferr := fb.fetch(ctx); ferr == nil && meta != nil {
			logger.L().Info(fmt.Sprintf("retrieved cloud metadata from %s metadata service", fb.name))
			return meta, nil
		}
	}

	// Wrap the underlying error with additional context so logs make it clearer why metadata is missing.
	return nil, fmt.Errorf("failed to get cloud metadata from IMDS or fallbacks: %w", err)
}

// fetchHTTPMetadata helper to fetch metadata from a URL with optional headers
func fetchHTTPMetadata(ctx context.Context, url string, headers map[string]string) (string, error) {
	client := &http.Client{
		Timeout: metadataTimeout,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata endpoint %s returned status: %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

func getLastPathPart(val string) string {
	if val == "" {
		return ""
	}
	parts := strings.Split(val, "/")
	return parts[len(parts)-1]
}

// fetchDigitalOceanMetadata attempts to fetch basic metadata from DigitalOcean's metadata service.
func fetchDigitalOceanMetadata(ctx context.Context) (*apitypes.CloudMetadata, error) {
	base := "http://169.254.169.254/metadata/v1/"

	// Probe root to see whether the metadata endpoint responds and contains expected entries.
	body, err := fetchHTTPMetadata(ctx, base, nil)
	if err != nil {
		return nil, err
	}

	// Basic heuristic: the DO metadata root typically lists resources like 'id', 'hostname', 'region' etc.
	if !strings.Contains(body, "id") && !strings.Contains(body, "region") && !strings.Contains(body, "hostname") {
		return nil, fmt.Errorf("digitalocean metadata root missing expected entries")
	}

	get := func(path string) string {
		val, _ := fetchHTTPMetadata(ctx, base+path, nil)
		return val
	}

	id := get("id")
	if id == "" {
		id = get("droplet_id")
	}
	instanceType := get("size")
	if instanceType == "" {
		instanceType = get("type")
	}

	meta := &apitypes.CloudMetadata{
		Provider:     "digitalocean",
		InstanceID:   id,
		InstanceType: instanceType,
		Region:       get("region"),
		PrivateIP:    get("interfaces/private/0/ipv4/address"),
		PublicIP:     get("interfaces/public/0/ipv4/address"),
		Hostname:     get("hostname"),
	}

	// if nothing useful was obtained, return an error so callers can continue trying other fallbacks
	if meta.InstanceID == "" && meta.Hostname == "" && meta.Region == "" && meta.PrivateIP == "" && meta.PublicIP == "" && meta.InstanceType == "" {
		return nil, fmt.Errorf("digitalocean metadata endpoints returned no data")
	}

	return meta, nil
}

// fetchGCPMetadata attempts to fetch basic metadata from GCP's metadata service.
func fetchGCPMetadata(ctx context.Context) (*apitypes.CloudMetadata, error) {
	base := "http://metadata.google.internal/computeMetadata/v1/"
	headers := map[string]string{"Metadata-Flavor": "Google"}

	get := func(path string) string {
		val, _ := fetchHTTPMetadata(ctx, base+path, headers)
		return val
	}

	machineType := get("instance/machine-type")
	if machineType == "" {
		return nil, fmt.Errorf("not a GCP instance")
	}

	return &apitypes.CloudMetadata{
		Provider:     "gcp",
		AccountID:    get("project/project-id"),
		InstanceID:   get("instance/id"),
		InstanceType: getLastPathPart(machineType),
		Zone:         getLastPathPart(get("instance/zone")),
		Hostname:     get("instance/hostname"),
	}, nil
}

// fetchAzureMetadata attempts to fetch basic metadata from Azure's metadata service.
func fetchAzureMetadata(ctx context.Context) (*apitypes.CloudMetadata, error) {
	base := "http://169.254.169.254/metadata/instance/compute/"
	headers := map[string]string{"Metadata": "true"}
	params := "?api-version=" + azureApiVersion + "&format=text"

	get := func(path string) string {
		val, _ := fetchHTTPMetadata(ctx, base+path+params, headers)
		return val
	}

	vmSize := get("vmSize")
	if vmSize == "" {
		return nil, fmt.Errorf("not an Azure instance")
	}

	return &apitypes.CloudMetadata{
		Provider:     "azure",
		AccountID:    get("subscriptionId"),
		InstanceID:   get("vmId"),
		InstanceType: vmSize,
		Region:       get("location"),
		Zone:         get("zone"),
		Hostname:     get("name"),
	}, nil
}
