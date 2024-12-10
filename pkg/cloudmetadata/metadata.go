package cloudmetadata

import (
	"context"
	"fmt"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/kubescape/k8s-interface/k8sinterface"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ProviderAWS          = "aws"
	ProviderGCP          = "gcp"
	ProviderAzure        = "azure"
	ProviderDigitalOcean = "digitalocean"
	ProviderOpenStack    = "openstack"
	ProviderVMware       = "vmware"
	ProviderAlibaba      = "alibaba"
	ProviderIBM          = "ibm"
	ProviderOracle       = "oracle"
	ProviderLinode       = "linode"
	ProviderScaleway     = "scaleway"
	ProviderVultr        = "vultr"
	ProviderHetzner      = "hetzner"
	ProviderEquinixMetal = "equinixmetal" // formerly Packet
	ProviderExoscale     = "exoscale"
	ProviderUnknown      = "unknown"
)

// Getapitypes.CloudMetadata retrieves cloud metadata for a given node
func GetCloudMetadata(ctx context.Context, client *k8sinterface.KubernetesApi, nodeName string) (*apitypes.CloudMetadata, error) {
	node, err := client.GetKubernetesClient().CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get node %s: %v", nodeName, err)
	}

	metadata := &apitypes.CloudMetadata{
		Hostname: node.Name,
	}

	// Determine provider and extract metadata
	providerID := node.Spec.ProviderID
	switch {
	case strings.HasPrefix(providerID, "aws://"):
		metadata.Provider = ProviderAWS
		metadata = extractAWSMetadata(node, metadata)
	case strings.HasPrefix(providerID, "gce://"):
		metadata.Provider = ProviderGCP
		metadata = extractGCPMetadata(node, metadata)
	case strings.HasPrefix(providerID, "azure://"):
		metadata.Provider = ProviderAzure
		metadata = extractAzureMetadata(node, metadata)
	case strings.HasPrefix(providerID, "digitalocean://"):
		metadata.Provider = ProviderDigitalOcean
		metadata = extractDigitalOceanMetadata(node, metadata)
	case strings.HasPrefix(providerID, "openstack://"):
		metadata.Provider = ProviderOpenStack
		metadata = extractOpenstackMetadata(node, metadata)
	case strings.HasPrefix(providerID, "vsphere://"):
		metadata.Provider = ProviderVMware
		metadata = extractVMwareMetadata(node, metadata)
	case strings.HasPrefix(providerID, "alicloud://"):
		metadata.Provider = ProviderAlibaba
		metadata = extractAlibabaMetadata(node, metadata)
	case strings.HasPrefix(providerID, "ibm://"):
		metadata.Provider = ProviderIBM
		metadata = extractIBMMetadata(node, metadata)
	case strings.HasPrefix(providerID, "oci://"):
		metadata.Provider = ProviderOracle
		metadata = extractOracleMetadata(node, metadata)
	case strings.HasPrefix(providerID, "linode://"):
		metadata.Provider = ProviderLinode
		metadata = extractLinodeMetadata(node, metadata)
	case strings.HasPrefix(providerID, "scaleway://"):
		metadata.Provider = ProviderScaleway
		metadata = extractScalewayMetadata(node, metadata)
	case strings.HasPrefix(providerID, "vultr://"):
		metadata.Provider = ProviderVultr
		metadata = extractVultrMetadata(node, metadata)
	case strings.HasPrefix(providerID, "hcloud://"):
		metadata.Provider = ProviderHetzner
		metadata = extractHetznerMetadata(node, metadata)
	case strings.HasPrefix(providerID, "equinixmetal://"):
		metadata.Provider = ProviderEquinixMetal
		metadata = extractEquinixMetalMetadata(node, metadata)
	case strings.HasPrefix(providerID, "exoscale://"):
		metadata.Provider = ProviderExoscale
		metadata = extractExoscaleMetadata(node, metadata)
	default:
		metadata.Provider = ProviderUnknown
		return nil, fmt.Errorf("unknown cloud provider for node %s: %s", nodeName, providerID)
	}

	// Extract common metadata from node status
	for _, addr := range node.Status.Addresses {
		switch addr.Type {
		case "InternalIP":
			metadata.PrivateIP = addr.Address
		case "ExternalIP":
			metadata.PublicIP = addr.Address
		case "Hostname":
			metadata.Hostname = addr.Address
		}
	}

	return metadata, nil
}

func extractAWSMetadata(node *corev1.Node, metadata *apitypes.CloudMetadata) *apitypes.CloudMetadata {
	// Extract from labels
	metadata.InstanceType = node.Labels["node.kubernetes.io/instance-type"]
	metadata.Region = node.Labels["topology.kubernetes.io/region"]
	metadata.Zone = node.Labels["topology.kubernetes.io/zone"]

	// Extract instance ID from provider ID
	// Format: aws:///us-west-2a/i-1234567890abcdef0
	parts := strings.Split(node.Spec.ProviderID, "/")
	if len(parts) > 0 {
		metadata.InstanceID = parts[len(parts)-1]
	}

	// Extract account ID from annotations if available
	if accountID, ok := node.Annotations["eks.amazonaws.com/account-id"]; ok {
		metadata.AccountID = accountID
	} else {
		// Extract account ID from metadata service if available
		client := ec2metadata.New(session.Must(session.NewSession()))
		if client.Available() {
			identity, err := client.GetInstanceIdentityDocument()
			if err == nil {
				metadata.AccountID = identity.AccountID
			}
		}
	}

	return metadata
}

func extractGCPMetadata(node *corev1.Node, metadata *apitypes.CloudMetadata) *apitypes.CloudMetadata {
	// Extract from labels
	metadata.InstanceType = node.Labels["beta.kubernetes.io/instance-type"]
	metadata.Region = node.Labels["topology.kubernetes.io/region"]
	metadata.Zone = node.Labels["topology.kubernetes.io/zone"]

	// Extract project and instance ID from provider ID
	// Format: gce:///project-name/zone/instance-name
	parts := strings.Split(node.Spec.ProviderID, "/")
	if len(parts) > 3 {
		metadata.AccountID = parts[3] // project name
		metadata.InstanceID = parts[len(parts)-1]
	}

	return metadata
}

func extractAzureMetadata(node *corev1.Node, metadata *apitypes.CloudMetadata) *apitypes.CloudMetadata {
	// Extract from labels
	metadata.InstanceType = node.Labels["node.kubernetes.io/instance-type"]
	metadata.Region = node.Labels["topology.kubernetes.io/region"]
	metadata.Zone = node.Labels["topology.kubernetes.io/zone"]

	// Extract subscription ID and resource info from provider ID
	// Format: azure:///subscriptions/<id>/resourceGroups/<name>/providers/Microsoft.Compute/virtualMachineScaleSets/<name>
	if parts := strings.Split(node.Spec.ProviderID, "/"); len(parts) > 3 {
		for i, part := range parts {
			if part == "subscriptions" && i+1 < len(parts) {
				metadata.AccountID = parts[i+1]
			}
			if part == "virtualMachineScaleSets" && i+1 < len(parts) {
				metadata.InstanceID = parts[i+1]
			}
		}
	}

	return metadata
}

func extractDigitalOceanMetadata(node *corev1.Node, metadata *apitypes.CloudMetadata) *apitypes.CloudMetadata {
	// Extract from labels
	metadata.InstanceType = node.Labels["beta.kubernetes.io/instance-type"]
	metadata.Region = node.Labels["topology.kubernetes.io/region"]
	metadata.Zone = node.Labels["topology.kubernetes.io/zone"]

	// Extract droplet ID from provider ID
	// Format: digitalocean:///droplet-id
	parts := strings.Split(node.Spec.ProviderID, "/")
	if len(parts) > 0 {
		metadata.InstanceID = parts[len(parts)-1]
	}

	return metadata
}

func extractOpenstackMetadata(node *corev1.Node, metadata *apitypes.CloudMetadata) *apitypes.CloudMetadata {
	// Extract from labels
	metadata.InstanceType = node.Labels["node.kubernetes.io/instance-type"]
	metadata.Region = node.Labels["topology.kubernetes.io/region"]
	metadata.Zone = node.Labels["topology.kubernetes.io/zone"]

	// Extract instance ID from provider ID
	// Format: openstack:///instance-id
	parts := strings.Split(node.Spec.ProviderID, "/")
	if len(parts) > 0 {
		metadata.InstanceID = parts[len(parts)-1]
	}

	// Extract project ID if available
	if projectID, ok := node.Labels["project.openstack.org/project-id"]; ok {
		metadata.AccountID = projectID
	}

	return metadata
}

func extractVMwareMetadata(node *corev1.Node, metadata *apitypes.CloudMetadata) *apitypes.CloudMetadata {
	// Extract from labels
	metadata.InstanceType = node.Labels["node.kubernetes.io/instance-type"]
	metadata.Zone = node.Labels["topology.kubernetes.io/zone"]

	// Extract VM UUID from provider ID
	// Format: vsphere:///vm-uuid
	parts := strings.Split(node.Spec.ProviderID, "/")
	if len(parts) > 0 {
		metadata.InstanceID = parts[len(parts)-1]
	}

	// Extract datacenter info if available
	if dc, ok := node.Labels["vsphere.kubernetes.io/datacenter"]; ok {
		metadata.Region = dc
	}

	return metadata
}

func extractAlibabaMetadata(node *corev1.Node, metadata *apitypes.CloudMetadata) *apitypes.CloudMetadata {
	// Extract from labels
	metadata.InstanceType = node.Labels["node.kubernetes.io/instance-type"]
	metadata.Region = node.Labels["topology.kubernetes.io/region"]
	metadata.Zone = node.Labels["topology.kubernetes.io/zone"]

	// Extract instance ID from provider ID
	// Format: alicloud:///instance-id
	parts := strings.Split(node.Spec.ProviderID, "/")
	if len(parts) > 0 {
		metadata.InstanceID = parts[len(parts)-1]
	}

	// Extract account ID if available
	if accountID, ok := node.Labels["alibabacloud.com/account-id"]; ok {
		metadata.AccountID = accountID
	}

	return metadata
}

func extractIBMMetadata(node *corev1.Node, metadata *apitypes.CloudMetadata) *apitypes.CloudMetadata {
	// Extract from labels
	metadata.InstanceType = node.Labels["node.kubernetes.io/instance-type"]
	metadata.Region = node.Labels["topology.kubernetes.io/region"]
	metadata.Zone = node.Labels["topology.kubernetes.io/zone"]

	// Extract instance ID from provider ID
	// Format: ibm:///instance-id
	parts := strings.Split(node.Spec.ProviderID, "/")
	if len(parts) > 0 {
		metadata.InstanceID = parts[len(parts)-1]
	}

	// Extract account ID if available
	if accountID, ok := node.Labels["ibm-cloud.kubernetes.io/account-id"]; ok {
		metadata.AccountID = accountID
	}

	return metadata
}

func extractOracleMetadata(node *corev1.Node, metadata *apitypes.CloudMetadata) *apitypes.CloudMetadata {
	// Extract from labels
	metadata.InstanceType = node.Labels["node.kubernetes.io/instance-type"]
	metadata.Region = node.Labels["topology.kubernetes.io/region"]
	metadata.Zone = node.Labels["topology.kubernetes.io/zone"]

	// Extract OCID from provider ID
	// Format: oci:///ocid
	parts := strings.Split(node.Spec.ProviderID, "/")
	if len(parts) > 0 {
		metadata.InstanceID = parts[len(parts)-1]
	}

	// Extract compartment ID if available
	if compartmentID, ok := node.Labels["oci.oraclecloud.com/compartment-id"]; ok {
		metadata.AccountID = compartmentID
	}

	return metadata
}

func extractLinodeMetadata(node *corev1.Node, metadata *apitypes.CloudMetadata) *apitypes.CloudMetadata {
	// Extract from labels
	metadata.InstanceType = node.Labels["node.kubernetes.io/instance-type"]
	metadata.Region = node.Labels["topology.kubernetes.io/region"]
	metadata.Zone = node.Labels["topology.kubernetes.io/zone"]

	// Extract Linode ID from provider ID
	// Format: linode:///linode-id
	parts := strings.Split(node.Spec.ProviderID, "/")
	if len(parts) > 0 {
		metadata.InstanceID = parts[len(parts)-1]
	}

	return metadata
}

func extractScalewayMetadata(node *corev1.Node, metadata *apitypes.CloudMetadata) *apitypes.CloudMetadata {
	// Extract from labels
	metadata.InstanceType = node.Labels["node.kubernetes.io/instance-type"]
	metadata.Region = node.Labels["topology.kubernetes.io/region"]
	metadata.Zone = node.Labels["topology.kubernetes.io/zone"]

	// Extract instance ID from provider ID
	// Format: scaleway:///instance-id
	parts := strings.Split(node.Spec.ProviderID, "/")
	if len(parts) > 0 {
		metadata.InstanceID = parts[len(parts)-1]
	}

	// Extract organization ID if available
	if orgID, ok := node.Labels["scaleway.com/organization-id"]; ok {
		metadata.AccountID = orgID
	}

	return metadata
}

func extractVultrMetadata(node *corev1.Node, metadata *apitypes.CloudMetadata) *apitypes.CloudMetadata {
	// Extract from labels
	metadata.InstanceType = node.Labels["node.kubernetes.io/instance-type"]
	metadata.Region = node.Labels["topology.kubernetes.io/region"]
	metadata.Zone = node.Labels["topology.kubernetes.io/zone"]

	// Extract instance ID from provider ID
	// Format: vultr:///instance-id
	parts := strings.Split(node.Spec.ProviderID, "/")
	if len(parts) > 0 {
		metadata.InstanceID = parts[len(parts)-1]
	}

	return metadata
}

func extractHetznerMetadata(node *corev1.Node, metadata *apitypes.CloudMetadata) *apitypes.CloudMetadata {
	// Extract from labels
	metadata.InstanceType = node.Labels["node.kubernetes.io/instance-type"]
	metadata.Region = node.Labels["topology.kubernetes.io/region"]
	metadata.Zone = node.Labels["topology.kubernetes.io/zone"]

	// Extract server ID from provider ID
	// Format: hcloud:///server-id
	parts := strings.Split(node.Spec.ProviderID, "/")
	if len(parts) > 0 {
		metadata.InstanceID = parts[len(parts)-1]
	}

	// Extract project ID if available
	if projectID, ok := node.Labels["hcloud.hetzner.cloud/project-id"]; ok {
		metadata.AccountID = projectID
	}

	return metadata
}

func extractEquinixMetalMetadata(node *corev1.Node, metadata *apitypes.CloudMetadata) *apitypes.CloudMetadata {
	// Extract from labels
	metadata.InstanceType = node.Labels["node.kubernetes.io/instance-type"]
	metadata.Region = node.Labels["topology.kubernetes.io/region"]
	metadata.Zone = node.Labels["topology.kubernetes.io/zone"]

	// Extract device ID from provider ID
	// Format: equinixmetal:///device-id
	parts := strings.Split(node.Spec.ProviderID, "/")
	if len(parts) > 0 {
		metadata.InstanceID = parts[len(parts)-1]
	}

	// Extract project ID if available
	if projectID, ok := node.Labels["metal.equinix.com/project-id"]; ok {
		metadata.AccountID = projectID
	}

	return metadata
}

func extractExoscaleMetadata(node *corev1.Node, metadata *apitypes.CloudMetadata) *apitypes.CloudMetadata {
	// Extract from labels
	metadata.InstanceType = node.Labels["node.kubernetes.io/instance-type"]
	metadata.Region = node.Labels["topology.kubernetes.io/region"]
	metadata.Zone = node.Labels["topology.kubernetes.io/zone"]

	// Extract instance ID from provider ID
	// Format: exoscale:///instance-id
	parts := strings.Split(node.Spec.ProviderID, "/")
	if len(parts) > 0 {
		metadata.InstanceID = parts[len(parts)-1]
	}

	// Extract organization ID if available
	if orgID, ok := node.Labels["exoscale.com/organization-id"]; ok {
		metadata.AccountID = orgID
	}

	return metadata
}
