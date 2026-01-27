package cloudmetadata

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	k8sInterfaceCloudMetadata "github.com/kubescape/k8s-interface/cloudmetadata"
	"github.com/kubescape/k8s-interface/k8sinterface"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	azureApiVersion = "2021-12-13"
	metadataTimeout = 2 * time.Second
)

// GetCloudMetadata retrieves cloud metadata for a given node
func GetCloudMetadata(ctx context.Context, client *k8sinterface.KubernetesApi, nodeName string) (*armotypes.CloudMetadata, error) {
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
	// special case for Azure, enrich ResourceGroup from node providerID
	enrichCloudMetadataForAzure(node, cMetadata)
	return cMetadata, nil
}

func enrichCloudMetadataForAWS(ctx context.Context, client *k8sinterface.KubernetesApi, cMetadata *armotypes.CloudMetadata) {
	if cMetadata == nil || cMetadata.Provider != armotypes.ProviderAws || cMetadata.AccountID != "" {
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

func enrichCloudMetadataForAzure(node *corev1.Node, cMetadata *armotypes.CloudMetadata) {
	if cMetadata == nil || cMetadata.Provider != armotypes.ProviderAzure || cMetadata.ResourceGroup != "" {
		return
	}

	// Parse ResourceGroup from node's providerID
	// Format: azure:///subscriptions/{sub}/resourceGroups/{rg}/providers/...
	providerID := node.Spec.ProviderID
	if rg := parseAzureResourceGroup(providerID); rg != "" {
		cMetadata.ResourceGroup = rg
		logger.L().Debug("enriched cloud metadata with Azure ResourceGroup from node providerID", helpers.String("resourceGroup", rg))
	}
}

func parseAzureResourceGroup(providerID string) string {
	// providerID format: azure:///subscriptions/.../resourceGroups/{resourceGroup}/providers/...
	const marker = "/resourceGroups/"
	idx := strings.Index(strings.ToLower(providerID), strings.ToLower(marker))
	if idx == -1 {
		return ""
	}
	start := idx + len(marker)
	rest := providerID[start:]
	end := strings.Index(rest, "/")
	if end == -1 {
		return rest
	}
	return rest[:end]
}

// GetCloudMetadataWithIMDS retrieves cloud metadata for a given node using IMDS
func GetCloudMetadataWithIMDS(ctx context.Context) (*armotypes.CloudMetadata, error) {
	cMetadataClient := k8sInterfaceCloudMetadata.NewMetadataClient(true)

	cMetadata, err := cMetadataClient.GetMetadata(ctx)
	if err == nil {
		return cMetadata, nil
	}

	logger.L().Info("failed to get cloud metadata from IMDS, trying fallbacks", helpers.Error(err))

	// Fallback strategy: try different providers
	fallbacks := []struct {
		name  string
		fetch func(context.Context) (*armotypes.CloudMetadata, error)
	}{
		{name: string(armotypes.ProviderDigitalOcean), fetch: fetchDigitalOceanMetadata},
		{name: string(armotypes.ProviderGcp), fetch: fetchGCPMetadata},
		{name: string(armotypes.ProviderAzure), fetch: fetchAzureMetadata},
		{name: string(armotypes.ProviderAlibaba), fetch: fetchAlibabaMetadata},
		{name: string(armotypes.ProviderOracle), fetch: fetchOracleMetadata},
		{name: string(armotypes.ProviderOpenStack), fetch: fetchOpenStackMetadata},
		{name: string(armotypes.ProviderHetzner), fetch: fetchHetznerMetadata},
		{name: string(armotypes.ProviderLinode), fetch: fetchLinodeMetadata},
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
func fetchDigitalOceanMetadata(ctx context.Context) (*armotypes.CloudMetadata, error) {
	base := "http://169.254.169.254/metadata/v1/"

	// Probe root to see whether the metadata endpoint responds and contains expected entries.
	body, err := fetchHTTPMetadata(ctx, base, nil)
	if err != nil {
		return nil, err
	}

	// Basic heuristic: the DO metadata root typically lists resources like 'id', 'region' and 'hostname'.
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

	meta := &armotypes.CloudMetadata{
		Provider:     armotypes.ProviderDigitalOcean,
		HostType:     armotypes.HostTypeDroplet,
		InstanceID:   id,
		InstanceType: instanceType,
		Region:       get("region"),
		PrivateIP:    get("interfaces/private/0/ipv4/address"),
		PublicIP:     get("interfaces/public/0/ipv4/address"),
		Hostname:     get("hostname"),
	}

	// Detect DOKS
	if tags := get("tags"); tags != "" && strings.Contains(tags, "k8s") {
		meta.HostType = armotypes.HostTypeDoks
	}

	// if nothing useful was obtained, return an error so callers can continue trying other fallbacks
	if meta.InstanceID == "" && meta.Hostname == "" && meta.Region == "" && meta.PrivateIP == "" && meta.PublicIP == "" && meta.InstanceType == "" {
		return nil, fmt.Errorf("digitalocean metadata endpoints returned no data")
	}

	return meta, nil
}

// fetchGCPMetadata attempts to fetch basic metadata from GCP's metadata service.
func fetchGCPMetadata(ctx context.Context) (*armotypes.CloudMetadata, error) {
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

	meta := &armotypes.CloudMetadata{
		Provider:     armotypes.ProviderGcp,
		HostType:     armotypes.HostTypeGce,
		AccountID:    get("project/project-id"),
		InstanceID:   get("instance/id"),
		InstanceType: getLastPathPart(machineType),
		Zone:         getLastPathPart(get("instance/zone")),
		Hostname:     get("instance/hostname"),
		PrivateIP:    get("instance/network-interfaces/0/ip"),
		PublicIP:     get("instance/network-interfaces/0/access-configs/0/external-ip"),
	}

	// Detect GKE
	if clusterName := get("instance/attributes/cluster-name"); clusterName != "" {
		meta.HostType = armotypes.HostTypeGke
	}

	return meta, nil
}

// fetchAzureMetadata attempts to fetch basic metadata from Azure's metadata service.
func fetchAzureMetadata(ctx context.Context) (*armotypes.CloudMetadata, error) {
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

	meta := &armotypes.CloudMetadata{
		Provider:      armotypes.ProviderAzure,
		HostType:      armotypes.HostTypeAzureVm,
		AccountID:     get("subscriptionId"),
		InstanceID:    get("vmId"),
		InstanceType:  vmSize,
		Region:        get("location"),
		Zone:          get("zone"),
		Hostname:      get("name"),
		ResourceGroup: get("resourceGroupName"),
	}

	// Detect AKS (heuristic: check for resource group or vmss tags common in AKS)
	if strings.Contains(strings.ToLower(meta.ResourceGroup), "aks") {
		meta.HostType = armotypes.HostTypeAks
	}

	// Try to get IP info
	networkBase := "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/"
	if ip, err := fetchHTTPMetadata(ctx, networkBase+"privateIpAddress"+params, headers); err == nil {
		meta.PrivateIP = ip
	}
	if ip, err := fetchHTTPMetadata(ctx, networkBase+"publicIpAddress"+params, headers); err == nil {
		meta.PublicIP = ip
	}

	return meta, nil
}

// fetchAlibabaMetadata attempts to fetch basic metadata from Alibaba Cloud's metadata service.
func fetchAlibabaMetadata(ctx context.Context) (*armotypes.CloudMetadata, error) {
	base := "http://100.100.100.200/latest/meta-data/"
	get := func(path string) string {
		val, _ := fetchHTTPMetadata(ctx, base+path, nil)
		return val
	}

	instanceID := get("instance-id")
	if instanceID == "" {
		return nil, fmt.Errorf("not an Alibaba Cloud instance")
	}

	return &armotypes.CloudMetadata{
		Provider:     armotypes.ProviderAlibaba,
		HostType:     armotypes.HostTypeOther,
		InstanceID:   instanceID,
		InstanceType: get("instance/instance-type"),
		Region:       get("region-id"),
		Zone:         get("zone-id"),
		PrivateIP:    get("private-ipv4"),
		PublicIP:     get("public-ipv4"),
		Hostname:     get("hostname"),
	}, nil
}

// fetchOracleMetadata attempts to fetch basic metadata from Oracle Cloud's metadata service.
func fetchOracleMetadata(ctx context.Context) (*armotypes.CloudMetadata, error) {
	base := "http://169.254.169.254/opc/v1/instance/"
	get := func(path string) string {
		val, _ := fetchHTTPMetadata(ctx, base+path, nil)
		return val
	}

	id := get("id")
	if id == "" {
		return nil, fmt.Errorf("not an Oracle Cloud instance")
	}

	return &armotypes.CloudMetadata{
		Provider:     armotypes.ProviderOracle,
		HostType:     armotypes.HostTypeOther,
		InstanceID:   id,
		InstanceType: get("shape"),
		Region:       get("region"),
		Zone:         get("availabilityDomain"),
		Hostname:     get("displayName"),
	}, nil
}

// fetchOpenStackMetadata attempts to fetch basic metadata from OpenStack's metadata service.
func fetchOpenStackMetadata(ctx context.Context) (*armotypes.CloudMetadata, error) {
	// OpenStack metadata is typically a JSON, but we can probe the root first.
	_, err := fetchHTTPMetadata(ctx, "http://169.254.169.254/openstack", nil)
	if err != nil {
		return nil, err
	}

	// Just return provider for now to signify detection
	return &armotypes.CloudMetadata{
		Provider: armotypes.ProviderOpenStack,
		HostType: armotypes.HostTypeOther,
	}, nil
}

// fetchHetznerMetadata attempts to fetch basic metadata from Hetzner Cloud's metadata service.
func fetchHetznerMetadata(ctx context.Context) (*armotypes.CloudMetadata, error) {
	base := "http://169.254.169.254/hetzner/v1/metadata"
	_, err := fetchHTTPMetadata(ctx, base, nil)
	if err != nil {
		return nil, err
	}

	get := func(path string) string {
		val, _ := fetchHTTPMetadata(ctx, base+"/"+path, nil)
		return val
	}

	id := get("instance-id")
	if id == "" {
		return nil, fmt.Errorf("not a Hetzner Cloud instance")
	}

	return &armotypes.CloudMetadata{
		Provider:     armotypes.ProviderHetzner,
		HostType:     armotypes.HostTypeOther,
		InstanceID:   id,
		InstanceType: get("instance-type"),
		Region:       get("region"),
		Zone:         get("availability-zone"),
		PublicIP:     get("public-ipv4"),
		Hostname:     get("hostname"),
	}, nil
}

// fetchLinodeMetadata attempts to fetch basic metadata from Linode's metadata service.
func fetchLinodeMetadata(ctx context.Context) (*armotypes.CloudMetadata, error) {
	base := "http://169.254.169.254/v1/metadata"
	// Linode returns a JSON usually, but let's check for response
	_, err := fetchHTTPMetadata(ctx, base, nil)
	if err != nil {
		return nil, err
	}

	return &armotypes.CloudMetadata{
		Provider: armotypes.ProviderLinode,
		HostType: armotypes.HostTypeOther,
	}, nil
}
