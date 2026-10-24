//go:build experimental_signing

package profiles

import (
	"errors"
	"testing"

	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestContainerProfileAdapter(t *testing.T) {
	profile := &v1beta1.ContainerProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "softwarecomposition.kubescape.io/v1beta1",
			Kind:       "ContainerProfile",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cp",
			Namespace: "default",
			UID:       types.UID("cp-uid-123"),
			Labels:    map[string]string{"app": "test"},
		},
		Spec: v1beta1.ContainerProfileSpec{
			Architectures: []string{"amd64"},
			Capabilities:  []string{"CAP_NET_BIND_SERVICE"},
		},
	}

	adapter := NewContainerProfileAdapter(profile)
	if adapter == nil {
		t.Fatal("Expected non-nil adapter")
	}
	if adapter.GetUID() != "cp-uid-123" {
		t.Errorf("Expected UID 'cp-uid-123', got '%s'", adapter.GetUID())
	}
	if adapter.GetNamespace() != "default" {
		t.Errorf("Expected namespace 'default', got '%s'", adapter.GetNamespace())
	}
	if adapter.GetName() != "test-cp" {
		t.Errorf("Expected name 'test-cp', got '%s'", adapter.GetName())
	}
	if got := adapter.GetAnnotations(); got != nil {
		t.Errorf("Expected nil annotations on an unset profile, got %v", got)
	}
	adapter.SetAnnotations(map[string]string{"test-key": "test-value"})
	if profile.Annotations["test-key"] != "test-value" {
		t.Error("Failed to set annotations")
	}
	if got := adapter.GetAnnotations(); got["test-key"] != "test-value" {
		t.Error("GetAnnotations should return the set annotations")
	}

	content, ok := adapter.GetContent().(map[string]interface{})
	if !ok {
		t.Fatal("Expected map[string]interface{} content type")
	}
	metadata, ok := content["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected metadata to be map[string]interface{}")
	}
	if metadata["name"] != "test-cp" {
		t.Errorf("Expected content name 'test-cp', got '%v'", metadata["name"])
	}
	// metadata.namespace is deliberately absent from the signed content so a
	// vendor-signed artifact can be installed into any namespace.
	if _, present := metadata["namespace"]; present {
		t.Errorf("namespace must not be part of the signed content, got '%v'", metadata["namespace"])
	}
	if content["apiVersion"] != "softwarecomposition.kubescape.io/v1beta1" {
		t.Errorf("Expected apiVersion, got '%v'", content["apiVersion"])
	}
	if content["kind"] != "ContainerProfile" {
		t.Errorf("Expected kind 'ContainerProfile', got '%v'", content["kind"])
	}
}

func TestContainerProfileAdapterSignAndVerify(t *testing.T) {
	profile := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sign-test-cp",
			Namespace: "default",
			UID:       types.UID("sign-cp-uid"),
			Labels:    map[string]string{"test": "signing"},
		},
		Spec: v1beta1.ContainerProfileSpec{
			Architectures: []string{"amd64", "arm64"},
			Capabilities:  []string{"CAP_NET_ADMIN"},
		},
	}

	adapter := NewContainerProfileAdapter(profile)
	if err := signature.SignObjectDisableKeyless(adapter); err != nil {
		t.Fatalf("SignObjectDisableKeyless failed: %v", err)
	}
	if _, ok := profile.Annotations[signature.AnnotationSignature]; !ok {
		t.Error("Expected signature annotation on profile")
	}
	if err := signature.VerifyObjectAllowUntrusted(adapter); err != nil {
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
			Labels:    map[string]string{"seccomp": "test"},
		},
		Spec: v1beta1.SeccompProfileSpec{
			Containers: []v1beta1.SingleSeccompProfile{{Name: "test-container"}},
		},
	}

	adapter := NewSeccompProfileAdapter(profile)
	if adapter == nil {
		t.Fatal("Expected non-nil adapter")
	}
	if adapter.GetUID() != "seccomp-uid-456" {
		t.Errorf("Expected UID 'seccomp-uid-456', got '%s'", adapter.GetUID())
	}
	if adapter.GetName() != "test-seccomp" {
		t.Errorf("Expected name 'test-seccomp', got '%s'", adapter.GetName())
	}
	if got := adapter.GetAnnotations(); got != nil {
		t.Errorf("Expected nil annotations on an unset profile, got %v", got)
	}
	adapter.SetAnnotations(map[string]string{"seccomp-key": "seccomp-value"})
	if profile.Annotations["seccomp-key"] != "seccomp-value" {
		t.Error("Failed to set annotations")
	}
	scContent, ok := adapter.GetContent().(map[string]interface{})
	if !ok {
		t.Fatal("Expected map[string]interface{} content type")
	}
	if scContent["kind"] != "SeccompProfile" {
		t.Errorf("Expected kind 'SeccompProfile', got '%v'", scContent["kind"])
	}
}

func TestSeccompProfileAdapterSignAndVerify(t *testing.T) {
	profile := &v1beta1.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sign-test-seccomp",
			Namespace: "default",
			UID:       types.UID("sign-seccomp-uid"),
			Labels:    map[string]string{"test": "seccomp-signing"},
		},
		Spec: v1beta1.SeccompProfileSpec{
			Containers: []v1beta1.SingleSeccompProfile{{Name: "app-container"}},
		},
	}

	adapter := NewSeccompProfileAdapter(profile)
	if err := signature.SignObjectDisableKeyless(adapter); err != nil {
		t.Fatalf("SignObjectDisableKeyless failed: %v", err)
	}
	if _, ok := profile.Annotations[signature.AnnotationSignature]; !ok {
		t.Error("Expected signature annotation on profile")
	}
	if err := signature.VerifyObjectAllowUntrusted(adapter); err != nil {
		t.Fatalf("VerifyObjectAllowUntrusted failed: %v", err)
	}
}

func TestAdapterUniqueness(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "unique-cp", Namespace: "default", UID: types.UID("cp-unique-uid")},
		Spec:       v1beta1.ContainerProfileSpec{Architectures: []string{"amd64"}},
	}
	sp := &v1beta1.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "unique-sp", Namespace: "default", UID: types.UID("sp-unique-uid")},
		Spec:       v1beta1.SeccompProfileSpec{},
	}
	cpAdapter := NewContainerProfileAdapter(cp)
	spAdapter := NewSeccompProfileAdapter(sp)

	if err := signature.SignObjectDisableKeyless(cpAdapter); err != nil {
		t.Fatalf("sign CP: %v", err)
	}
	if err := signature.SignObjectDisableKeyless(spAdapter); err != nil {
		t.Fatalf("sign SP: %v", err)
	}
	cpSig, err := signature.GetObjectSignature(cpAdapter)
	if err != nil {
		t.Fatalf("GetObjectSignature CP: %v", err)
	}
	spSig, err := signature.GetObjectSignature(spAdapter)
	if err != nil {
		t.Fatalf("GetObjectSignature SP: %v", err)
	}
	if cpSig == nil || spSig == nil {
		t.Fatal("nil signature")
	}
	if cpSig.Issuer != "local" || spSig.Issuer != "local" {
		t.Errorf("Expected issuer 'local', got CP=%q SP=%q", cpSig.Issuer, spSig.Issuer)
	}
}

// TestContainerProfileAdapter_GetContentDoesNotMutate pins that GetContent
// normalizes PolicyByRuleId on a copy and never mutates the wrapped profile.
func TestContainerProfileAdapter_GetContentDoesNotMutate(t *testing.T) {
	profile := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "cp", Namespace: "default"},
		Spec:       v1beta1.ContainerProfileSpec{Execs: []v1beta1.ExecCalls{{Path: "/bin/sh"}}},
	}
	adapter := NewContainerProfileAdapter(profile)

	content := adapter.GetContent().(map[string]interface{})

	if profile.Spec.PolicyByRuleId != nil {
		t.Error("GetContent mutated PolicyByRuleId on the wrapped profile")
	}
	if got := adapter.GetAnnotations(); got != nil {
		t.Errorf("GetAnnotations must be read-only, got %v", got)
	}
	spec := content["spec"].(v1beta1.ContainerProfileSpec)
	if spec.PolicyByRuleId == nil {
		t.Error("GetContent should normalize PolicyByRuleId to {} in the returned content")
	}
}

// TestContainerProfileAdapter_SignFromNilAnnotations pins that signing an object
// starting with NO annotations works end to end and IsSigned reads a nil map
// without panicking.
func TestContainerProfileAdapter_SignFromNilAnnotations(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "no-annotations", Namespace: "default"},
		Spec:       v1beta1.ContainerProfileSpec{Architectures: []string{"amd64"}},
	}
	if cp.Annotations != nil {
		t.Fatal("precondition: profile must start with nil annotations")
	}
	adapter := NewContainerProfileAdapter(cp)

	if signature.IsSigned(adapter) {
		t.Fatal("IsSigned must be false (and must not panic) for nil annotations")
	}
	if err := signature.SignObjectDisableKeyless(adapter); err != nil {
		t.Fatalf("signing an annotation-less object must still work, got %v", err)
	}
	if cp.Annotations == nil {
		t.Fatal("signing should have attached the signature annotation")
	}
	if !signature.IsSigned(adapter) {
		t.Fatal("object should report as signed after SignObject")
	}
}

func TestEmbeddedSeccompProfileBindsNamespace(t *testing.T) {
	profile := &v1beta1.SeccompProfile{ObjectMeta: metav1.ObjectMeta{Name: "sandbox", Namespace: "source"}}
	adapter := NewSeccompProfileAdapter(profile)
	if err := signature.SignObject(adapter, signature.WithKeyless(false), signature.WithEmbedContent(true)); err != nil {
		t.Fatal(err)
	}
	if err := signature.VerifyObjectAllowUntrusted(adapter); err != nil {
		t.Fatal(err)
	}
	profile.Namespace = "target"
	if err := signature.VerifyObjectAllowUntrusted(adapter); !errors.Is(err, signature.ErrSignatureMismatch) {
		t.Fatalf("relocating namespace-bound seccomp content must fail: %v", err)
	}
}

func TestEmbeddedContainerProfileRemainsNamespacePortable(t *testing.T) {
	profile := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "portable", Namespace: "source"}}
	adapter := NewContainerProfileAdapter(profile)
	if err := signature.SignObject(adapter, signature.WithKeyless(false), signature.WithEmbedContent(true)); err != nil {
		t.Fatal(err)
	}
	profile.Namespace = "target"
	if err := signature.VerifyObjectAllowUntrusted(adapter); err != nil {
		t.Fatalf("an adapter omitting namespace must stay portable: %v", err)
	}
}
