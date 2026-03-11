package signature

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// This test replicates the exact scenario from the production cluster where:
// 1. Profiles are loaded from the cluster with empty TypeMeta (APIVersion="", Kind="")
// 2. The adapter's GetContent() should fill in the correct fallback values
// 3. Signatures created and verified using these profiles should succeed

func TestClusterScenarioIntegration(t *testing.T) {
	// Simulate a profile as it comes from the cluster (empty TypeMeta)
	clusterProfile := &v1beta1.ApplicationProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "",
			Kind:       "",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "replicaset-test-workload-123456789",
			Namespace: "default",
			Labels: map[string]string{
				"kubescape.io/instance-template-hash": "123456789",
				"kubescape.io/workload-kind":          "Deployment",
				"kubescape.io/workload-name":          "test-workload",
				"kubescape.io/workload-namespace":     "default",
			},
		},
	}

	// Create adapter
	adapter := profiles.NewApplicationProfileAdapter(clusterProfile)

	// Verify GetContent() populates TypeMeta correctly
	content := adapter.GetContent()
	contentMap, ok := content.(map[string]interface{})
	if !ok {
		t.Fatalf("GetContent() should return map[string]interface{}, got %T", content)
	}

	// Check that fallback values are applied
	if contentMap["apiVersion"] != "spdx.softwarecomposition.kubescape.io/v1beta1" {
		t.Errorf("Expected apiVersion fallback to be applied, got: %v", contentMap["apiVersion"])
	}
	if contentMap["kind"] != "ApplicationProfile" {
		t.Errorf("Expected kind fallback to be applied, got: %v", contentMap["kind"])
	}

	// Verify metadata is correctly structured
	metadata, ok := contentMap["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("metadata should be a map[string]interface{}")
	}

	if metadata["name"] != clusterProfile.Name {
		t.Errorf("Expected metadata.name=%s, got %v", clusterProfile.Name, metadata["name"])
	}
	if metadata["namespace"] != clusterProfile.Namespace {
		t.Errorf("Expected metadata.namespace=%s, got %v", clusterProfile.Namespace, metadata["namespace"])
	}
	if metadata["labels"] == nil {
		t.Error("metadata.labels should not be nil")
	}

	// Now verify that signing and verification work end-to-end
	if err := SignObjectDisableKeyless(adapter); err != nil {
		t.Fatalf("Failed to sign object: %v", err)
	}

	if clusterProfile.Annotations == nil {
		t.Fatal("Annotations should be set after signing")
	}

	if _, ok := clusterProfile.Annotations[AnnotationSignature]; !ok {
		t.Error("Signature annotation should be set after signing")
	}

	// Verify the signature
	if err := VerifyObjectAllowUntrusted(adapter); err != nil {
		t.Fatalf("Failed to verify object: %v", err)
	}

	t.Log("✓ Cluster scenario integration test passed: profile with empty TypeMeta successfully signed and verified")
}
