package profiles

import (
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestApplicationProfileAdapterEmptyTypeMeta(t *testing.T) {
	profile := &v1beta1.ApplicationProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "",
			Kind:       "",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ap",
			Namespace: "default",
		},
		Spec: v1beta1.ApplicationProfileSpec{
			Architectures: []string{"amd64"},
		},
	}

	adapter := NewApplicationProfileAdapter(profile)

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

	if apContent["kind"] != "ApplicationProfile" {
		t.Errorf("Expected fallback kind 'ApplicationProfile', got '%v'", apContent["kind"])
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
