//go:build experimental_signing

package profiles

import (
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestContainerProfileAdapterEmptyTypeMeta(t *testing.T) {
	profile := &v1beta1.ContainerProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "",
			Kind:       "",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ap",
			Namespace: "default",
		},
		Spec: v1beta1.ContainerProfileSpec{
			Architectures: []string{"amd64"},
		},
	}

	adapter := NewContainerProfileAdapter(profile)

	content := adapter.GetContent()
	if content == nil {
		t.Fatal("Expected non-nil content")
	}

	apContent, ok := content.(map[string]interface{})
	if !ok {
		t.Fatal("Expected map[string]interface{} content type")
	}

	if apContent["apiVersion"] != "spdx.softwarecomposition.kubescape.io/v1beta1" {
		t.Errorf("Expected fallback apiVersion 'spdx.softwarecomposition.kubescape.io/v1beta1', got '%v'", apContent["apiVersion"])
	}

	if apContent["kind"] != "ContainerProfile" {
		t.Errorf("Expected fallback kind 'ContainerProfile', got '%v'", apContent["kind"])
	}
}

func TestSeccompProfileAdapterEmptyTypeMeta(t *testing.T) {
	profile := &v1beta1.SeccompProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "",
			Kind:       "",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-seccomp",
			Namespace: "default",
		},
		Spec: v1beta1.SeccompProfileSpec{},
	}

	adapter := NewSeccompProfileAdapter(profile)

	content := adapter.GetContent()
	if content == nil {
		t.Fatal("Expected non-nil content")
	}

	scContent, ok := content.(map[string]interface{})
	if !ok {
		t.Fatal("Expected map[string]interface{} content type")
	}

	if scContent["apiVersion"] != "spdx.softwarecomposition.kubescape.io/v1beta1" {
		t.Errorf("Expected fallback apiVersion 'spdx.softwarecomposition.kubescape.io/v1beta1', got '%v'", scContent["apiVersion"])
	}

	if scContent["kind"] != "SeccompProfile" {
		t.Errorf("Expected fallback kind 'SeccompProfile', got '%v'", scContent["kind"])
	}
}
