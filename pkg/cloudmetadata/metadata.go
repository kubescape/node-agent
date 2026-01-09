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
	if err != nil {
		// Try DigitalOcean metadata endpoints as a fallback (e.g., droplets) if IMDS didn't work.
		if doMeta, derr := fetchDigitalOceanMetadata(ctx); derr == nil && doMeta != nil {
			logger.L().Info("retrieved cloud metadata from DigitalOcean metadata service as fallback")
			return doMeta, nil
		}
		// Wrap the underlying error with additional context so logs make it clearer why metadata is missing.
		// This helps surface issues like IMDS token endpoint failures (e.g. IMDSv2 token 404), unreachable metadata endpoints,
		// or provider-specific metadata problems.
		return nil, fmt.Errorf("failed to get cloud metadata from IMDS: %w", err)
	}

	return cMetadata, nil
}

// fetchDigitalOceanMetadata attempts to fetch basic metadata from DigitalOcean's metadata service.
//
// It probes the metadata root and queries a few commonly available endpoints.
// It returns a non-nil error if it does not look like DigitalOcean's metadata service or no useful values were found.
func fetchDigitalOceanMetadata(ctx context.Context) (*apitypes.CloudMetadata, error) {
	client := &http.Client{
		Timeout: 2 * time.Second,
	}
	base := "http://169.254.169.254/metadata/v1/"

	// Probe root to see whether the metadata endpoint responds and contains expected entries.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("digitalocean metadata root returned status: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	bstr := string(body)
	// Basic heuristic: the DO metadata root typically lists resources like 'id', 'hostname', 'region' etc.
	if !strings.Contains(bstr, "id") && !strings.Contains(bstr, "region") && !strings.Contains(bstr, "hostname") {
		return nil, fmt.Errorf("digitalocean metadata root missing expected entries")
	}

	// helper to fetch a single textual endpoint and return trimmed result or empty string
	get := func(path string) string {
		url := base + path
		r, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp2, err2 := client.Do(r)
		if err2 != nil || resp2.StatusCode != 200 {
			if resp2 != nil {
				resp2.Body.Close()
			}
			return ""
		}
		defer resp2.Body.Close()
		b, _ := io.ReadAll(resp2.Body)
		return strings.TrimSpace(string(b))
	}

	id := get("id")
	if id == "" {
		id = get("droplet_id")
	}
	hostname := get("hostname")
	region := get("region")
	instanceType := get("size")
	if instanceType == "" {
		instanceType = get("type")
	}
	privateIP := get("interfaces/private/0/ipv4/address")
	publicIP := get("interfaces/public/0/ipv4/address")

	// if nothing useful was obtained, return an error so callers can continue trying other fallbacks
	if id == "" && hostname == "" && region == "" && privateIP == "" && publicIP == "" && instanceType == "" {
		return nil, fmt.Errorf("digitalocean metadata endpoints returned no data")
	}

	return &apitypes.CloudMetadata{
		Provider:     "digitalocean",
		InstanceID:   id,
		InstanceType: instanceType,
		Region:       region,
		PrivateIP:    privateIP,
		PublicIP:     publicIP,
		Hostname:     hostname,
	}, nil
}
