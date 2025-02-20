package cloudmetadata

import (
	"context"
	"fmt"

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
		return nil, err
	}

	return cMetadata, nil
}
