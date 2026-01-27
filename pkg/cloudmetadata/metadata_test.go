package cloudmetadata

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	corev1 "k8s.io/api/core/v1"
)

func TestParseAzureResourceGroup(t *testing.T) {
	tests := []struct {
		name       string
		providerID string
		want       string
	}{
		{
			name:       "valid Azure providerID from AKS",
			providerID: "azure:///subscriptions/46858535-647d-4747-a6c5-050b4ba10543/resourceGroups/mc_esidev-common-rg_esidev-aks_westeurope/providers/Microsoft.Compute/virtualMachineScaleSets/aks-esidev-12597773-vmss/virtualMachines/175",
			want:       "mc_esidev-common-rg_esidev-aks_westeurope",
		},
		{
			name:       "case insensitive matching - uppercase RESOURCEGROUPS",
			providerID: "azure:///subscriptions/sub-id/RESOURCEGROUPS/MyResourceGroup/providers/Microsoft.Compute/virtualMachines/vm1",
			want:       "MyResourceGroup",
		},
		{
			name:       "case insensitive matching - mixed case",
			providerID: "azure:///subscriptions/sub-id/ResourceGroups/MyResourceGroup/providers/Microsoft.Compute/virtualMachines/vm1",
			want:       "MyResourceGroup",
		},
		{
			name:       "no trailing path after resource group",
			providerID: "azure:///subscriptions/sub-id/resourceGroups/my-rg",
			want:       "my-rg",
		},
		{
			name:       "resource group with hyphens and underscores",
			providerID: "azure:///subscriptions/sub-id/resourceGroups/my-resource_group-123/providers/test",
			want:       "my-resource_group-123",
		},
		{
			name:       "missing resourceGroups marker",
			providerID: "azure:///subscriptions/sub-id/providers/Microsoft.Compute/virtualMachines/vm1",
			want:       "",
		},
		{
			name:       "empty string",
			providerID: "",
			want:       "",
		},
		{
			name:       "non-Azure providerID",
			providerID: "aws:///us-east-1a/i-1234567890abcdef0",
			want:       "",
		},
		{
			name:       "malformed providerID with resourceGroups but no value",
			providerID: "azure:///subscriptions/sub-id/resourceGroups//providers/test",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseAzureResourceGroup(tt.providerID); got != tt.want {
				t.Errorf("parseAzureResourceGroup() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEnrichCloudMetadataForAzure(t *testing.T) {
	tests := []struct {
		name          string
		node          *corev1.Node
		cMetadata     *armotypes.CloudMetadata
		wantRG        string
		wantUnchanged bool
	}{
		{
			name: "enrich Azure metadata from valid providerID",
			node: &corev1.Node{
				Spec: corev1.NodeSpec{
					ProviderID: "azure:///subscriptions/sub-id/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/vm1",
				},
			},
			cMetadata: &armotypes.CloudMetadata{
				Provider: armotypes.ProviderAzure,
			},
			wantRG:        "my-rg",
			wantUnchanged: false,
		},
		{
			name: "skip if provider is not Azure",
			node: &corev1.Node{
				Spec: corev1.NodeSpec{
					ProviderID: "azure:///subscriptions/sub-id/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/vm1",
				},
			},
			cMetadata: &armotypes.CloudMetadata{
				Provider: armotypes.ProviderAws,
			},
			wantRG:        "",
			wantUnchanged: true,
		},
		{
			name: "skip if ResourceGroup already set",
			node: &corev1.Node{
				Spec: corev1.NodeSpec{
					ProviderID: "azure:///subscriptions/sub-id/resourceGroups/new-rg/providers/Microsoft.Compute/virtualMachines/vm1",
				},
			},
			cMetadata: &armotypes.CloudMetadata{
				Provider:      armotypes.ProviderAzure,
				ResourceGroup: "existing-rg",
			},
			wantRG:        "existing-rg",
			wantUnchanged: true,
		},
		{
			name: "skip if metadata is nil",
			node: &corev1.Node{
				Spec: corev1.NodeSpec{
					ProviderID: "azure:///subscriptions/sub-id/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/vm1",
				},
			},
			cMetadata:     nil,
			wantRG:        "",
			wantUnchanged: true,
		},
		{
			name: "no change if providerID doesn't contain resourceGroups",
			node: &corev1.Node{
				Spec: corev1.NodeSpec{
					ProviderID: "azure:///subscriptions/sub-id/providers/Microsoft.Compute/virtualMachines/vm1",
				},
			},
			cMetadata: &armotypes.CloudMetadata{
				Provider: armotypes.ProviderAzure,
			},
			wantRG:        "",
			wantUnchanged: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Store original value if metadata exists
			var originalRG string
			if tt.cMetadata != nil {
				originalRG = tt.cMetadata.ResourceGroup
			}

			enrichCloudMetadataForAzure(tt.node, tt.cMetadata)

			if tt.cMetadata == nil {
				// If metadata was nil, nothing should happen
				return
			}

			if tt.wantUnchanged && tt.cMetadata.ResourceGroup != originalRG {
				t.Errorf("enrichCloudMetadataForAzure() changed ResourceGroup when it shouldn't, got %v, want %v", tt.cMetadata.ResourceGroup, originalRG)
			}

			if !tt.wantUnchanged && tt.cMetadata.ResourceGroup != tt.wantRG {
				t.Errorf("enrichCloudMetadataForAzure() ResourceGroup = %v, want %v", tt.cMetadata.ResourceGroup, tt.wantRG)
			}
		})
	}
}
