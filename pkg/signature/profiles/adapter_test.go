package profiles

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestApplicationProfileAdapter(t *testing.T) {
	profile := &v1beta1.ApplicationProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "softwarecomposition.kubescape.io/v1beta1",
			Kind:       "ApplicationProfile",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ap",
			Namespace: "default",
			UID:       types.UID("ap-uid-123"),
			Labels: map[string]string{
				"app": "test",
			},
		},
		Spec: v1beta1.ApplicationProfileSpec{
			Architectures: []string{"amd64"},
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name:         "nginx",
					Capabilities: []string{"CAP_NET_BIND_SERVICE"},
				},
			},
		},
	}

	adapter := NewApplicationProfileAdapter(profile)

	if adapter == nil {
		t.Fatal("Expected non-nil adapter")
	}

	if adapter.GetUID() != "ap-uid-123" {
		t.Errorf("Expected UID 'ap-uid-123', got '%s'", adapter.GetUID())
	}

	if adapter.GetNamespace() != "default" {
		t.Errorf("Expected namespace 'default', got '%s'", adapter.GetNamespace())
	}

	if adapter.GetName() != "test-ap" {
		t.Errorf("Expected name 'test-ap', got '%s'", adapter.GetName())
	}

	annotations := adapter.GetAnnotations()
	if annotations == nil {
		t.Error("Expected annotations map, got nil")
	}

	testAnnotations := map[string]string{
		"test-key": "test-value",
	}
	adapter.SetAnnotations(testAnnotations)
	if profile.Annotations["test-key"] != "test-value" {
		t.Error("Failed to set annotations")
	}

	content := adapter.GetContent()
	if content == nil {
		t.Fatal("Expected non-nil content")
	}

	apContent, ok := content.(map[string]interface{})
	if !ok {
		t.Fatal("Expected map[string]interface{} content type")
	}

	metadata, ok := apContent["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected metadata to be map[string]interface{}")
	}

	if metadata["name"] != "test-ap" {
		t.Errorf("Expected content name 'test-ap', got '%v'", metadata["name"])
	}

	if metadata["namespace"] != "default" {
		t.Errorf("Expected content namespace 'default', got '%v'", metadata["namespace"])
	}

	if apContent["apiVersion"] != "softwarecomposition.kubescape.io/v1beta1" {
		t.Errorf("Expected apiVersion 'softwarecomposition.kubescape.io/v1beta1', got '%v'", apContent["apiVersion"])
	}

	if apContent["kind"] != "ApplicationProfile" {
		t.Errorf("Expected kind 'ApplicationProfile', got '%v'", apContent["kind"])
	}
}

func TestApplicationProfileAdapterSignAndVerify(t *testing.T) {
	profile := &v1beta1.ApplicationProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "softwarecomposition.kubescape.io/v1beta1",
			Kind:       "ApplicationProfile",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sign-test-ap",
			Namespace: "default",
			UID:       types.UID("sign-ap-uid"),
			Labels: map[string]string{
				"test": "signing",
			},
		},
		Spec: v1beta1.ApplicationProfileSpec{
			Architectures: []string{"amd64", "arm64"},
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name:         "app",
					Capabilities: []string{"CAP_NET_ADMIN"},
				},
			},
		},
	}

	adapter := NewApplicationProfileAdapter(profile)

	err := signature.SignObjectDisableKeyless(adapter)
	if err != nil {
		t.Fatalf("SignObjectDisableKeyless failed: %v", err)
	}

	if profile.Annotations == nil {
		t.Error("Expected annotations to be set on profile")
	}

	if _, ok := profile.Annotations[signature.AnnotationSignature]; !ok {
		t.Error("Expected signature annotation on profile")
	}

	err = signature.VerifyObjectAllowUntrusted(adapter)
	if err != nil {
		t.Fatalf("VerifyObjectAllowUntrusted failed: %v", err)
	}
}

func TestSeccompProfileAdapter(t *testing.T) {
	profile := &v1beta1.SeccompProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "softwarecomposition.kubescape.io/v1beta1",
			Kind:       "SeccompProfile",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-seccomp",
			Namespace: "default",
			UID:       types.UID("seccomp-uid-456"),
			Labels: map[string]string{
				"seccomp": "test",
			},
		},
		Spec: v1beta1.SeccompProfileSpec{
			Containers: []v1beta1.SingleSeccompProfile{
				{
					Name: "test-container",
				},
			},
		},
	}

	adapter := NewSeccompProfileAdapter(profile)

	if adapter == nil {
		t.Fatal("Expected non-nil adapter")
	}

	if adapter.GetUID() != "seccomp-uid-456" {
		t.Errorf("Expected UID 'seccomp-uid-456', got '%s'", adapter.GetUID())
	}

	if adapter.GetNamespace() != "default" {
		t.Errorf("Expected namespace 'default', got '%s'", adapter.GetNamespace())
	}

	if adapter.GetName() != "test-seccomp" {
		t.Errorf("Expected name 'test-seccomp', got '%s'", adapter.GetName())
	}

	annotations := adapter.GetAnnotations()
	if annotations == nil {
		t.Error("Expected annotations map, got nil")
	}

	testAnnotations := map[string]string{
		"seccomp-key": "seccomp-value",
	}
	adapter.SetAnnotations(testAnnotations)
	if profile.Annotations["seccomp-key"] != "seccomp-value" {
		t.Error("Failed to set annotations")
	}

	content := adapter.GetContent()
	if content == nil {
		t.Fatal("Expected non-nil content")
	}

	scContent, ok := content.(map[string]interface{})
	if !ok {
		t.Fatal("Expected map[string]interface{} content type")
	}

	metadata, ok := scContent["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected metadata to be map[string]interface{}")
	}

	if metadata["name"] != "test-seccomp" {
		t.Errorf("Expected content name 'test-seccomp', got '%v'", metadata["name"])
	}

	if metadata["namespace"] != "default" {
		t.Errorf("Expected content namespace 'default', got '%v'", metadata["namespace"])
	}

	if scContent["apiVersion"] != "softwarecomposition.kubescape.io/v1beta1" {
		t.Errorf("Expected apiVersion 'softwarecomposition.kubescape.io/v1beta1', got '%v'", scContent["apiVersion"])
	}

	if scContent["kind"] != "SeccompProfile" {
		t.Errorf("Expected kind 'SeccompProfile', got '%v'", scContent["kind"])
	}
}

func TestSeccompProfileAdapterSignAndVerify(t *testing.T) {
	profile := &v1beta1.SeccompProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "softwarecomposition.kubescape.io/v1beta1",
			Kind:       "SeccompProfile",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sign-test-seccomp",
			Namespace: "default",
			UID:       types.UID("sign-seccomp-uid"),
			Labels: map[string]string{
				"test": "seccomp-signing",
			},
		},
		Spec: v1beta1.SeccompProfileSpec{
			Containers: []v1beta1.SingleSeccompProfile{
				{
					Name: "app-container",
				},
			},
		},
	}

	adapter := NewSeccompProfileAdapter(profile)

	err := signature.SignObjectDisableKeyless(adapter)
	if err != nil {
		t.Fatalf("SignObjectDisableKeyless failed: %v", err)
	}

	if profile.Annotations == nil {
		t.Error("Expected annotations to be set on profile")
	}

	if _, ok := profile.Annotations[signature.AnnotationSignature]; !ok {
		t.Error("Expected signature annotation on profile")
	}

	err = signature.VerifyObjectAllowUntrusted(adapter)
	if err != nil {
		t.Fatalf("VerifyObjectAllowUntrusted failed: %v", err)
	}
}

func TestAdapterUniqueness(t *testing.T) {
	ap := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "unique-ap",
			Namespace: "default",
			UID:       types.UID("ap-unique-uid"),
		},
		Spec: v1beta1.ApplicationProfileSpec{
			Architectures: []string{"amd64"},
		},
	}

	sp := &v1beta1.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "unique-sp",
			Namespace: "default",
			UID:       types.UID("sp-unique-uid"),
		},
		Spec: v1beta1.SeccompProfileSpec{},
	}

	apAdapter := NewApplicationProfileAdapter(ap)
	spAdapter := NewSeccompProfileAdapter(sp)

	err := signature.SignObjectDisableKeyless(apAdapter)
	if err != nil {
		t.Fatalf("SignObjectDisableKeyless failed for ApplicationProfile: %v", err)
	}

	err = signature.SignObjectDisableKeyless(spAdapter)
	if err != nil {
		t.Fatalf("SignObjectDisableKeyless failed for SeccompProfile: %v", err)
	}

	apSig, err := signature.GetObjectSignature(apAdapter)
	if err != nil {
		t.Fatalf("GetObjectSignature failed for ApplicationProfile: %v", err)
	}

	if apSig == nil {
		t.Fatal("GetObjectSignature returned nil for ApplicationProfile")
	}

	spSig, err := signature.GetObjectSignature(spAdapter)
	if err != nil {
		t.Fatalf("GetObjectSignature failed for SeccompProfile: %v", err)
	}

	if spSig == nil {
		t.Fatal("GetObjectSignature returned nil for SeccompProfile")
	}

	if apSig.Issuer != "local" {
		t.Errorf("Expected AP issuer 'local', got '%s'", apSig.Issuer)
	}

	if spSig.Issuer != "local" {
		t.Errorf("Expected SP issuer 'local', got '%s'", spSig.Issuer)
	}
}
