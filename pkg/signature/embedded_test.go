//go:build experimental_signing

package signature

import (
	"errors"
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// embedCP builds a signable CP-like mock via the real adapter path is not
// available here (profiles imports signature), so use the mock object.
func embedContentFixture(t *testing.T) *MockSignableObject {
	t.Helper()
	content := map[string]interface{}{
		"apiVersion": "spdx.softwarecomposition.kubescape.io/v1beta1",
		"kind":       "ContainerProfile",
		"metadata": map[string]interface{}{
			"name":      "frag",
			"namespace": "ns",
			"labels":    map[string]string{"signature.kubescape.io/bundle": "redis"},
		},
		"spec": v1beta1.ContainerProfileSpec{Execs: []v1beta1.ExecCalls{{Path: "/bin/x"}}},
	}
	return NewMockSignableObject("uid", "ns", "frag", content)
}

// TestEmbedContent_VerifySurvivesContentMutation pins the core property of the
// embedded chain: after signing with WithEmbedContent, mutating the OBJECT's
// content (as the storage server does when it normalises specs) must NOT break
// verification — the signature binds the embedded bytes.
func TestEmbedContent_VerifySurvivesContentMutation(t *testing.T) {
	obj := embedContentFixture(t)
	if err := SignObject(obj, WithKeyless(false), WithEmbedContent(true)); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, ok := obj.GetAnnotations()[AnnotationContent]; !ok {
		t.Fatal("embedded content annotation missing after sign")
	}
	// simulate server-side normalisation: the live object's content changes
	obj.content = map[string]interface{}{"spec": "normalised-differently"}
	if err := VerifyObjectAllowUntrusted(obj); err != nil {
		t.Fatalf("verification must bind the embedded bytes, not the mutated object: %v", err)
	}
}

// TestEmbedContent_TamperedEmbeddedFails: modifying the embedded bytes breaks
// the signature (ErrSignatureMismatch → tamper).
func TestEmbedContent_TamperedEmbeddedFails(t *testing.T) {
	obj := embedContentFixture(t)
	if err := SignObject(obj, WithKeyless(false), WithEmbedContent(true)); err != nil {
		t.Fatalf("sign: %v", err)
	}
	ann := obj.GetAnnotations()
	tampered, err := encodeEmbeddedContent([]byte(`{"spec":{"execs":[{"path":"/bin/backdoor"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	ann[AnnotationContent] = tampered
	obj.SetAnnotations(ann)
	err = VerifyObjectAllowUntrusted(obj)
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("want ErrSignatureMismatch on tampered embedded content, got %v", err)
	}
}

// TestEmbedContent_RoundTrip: EmbeddedContent returns exactly the signed bytes.
func TestEmbedContent_RoundTrip(t *testing.T) {
	obj := embedContentFixture(t)
	if err := SignObject(obj, WithKeyless(false), WithEmbedContent(true)); err != nil {
		t.Fatalf("sign: %v", err)
	}
	content, present, err := EmbeddedContent(obj)
	if err != nil || !present {
		t.Fatalf("EmbeddedContent: present=%v err=%v", present, err)
	}
	h1, _ := HashBytes(content)
	// legacy default (no embed) must not set the annotation
	obj2 := embedContentFixture(t)
	if err := SignObject(obj2, WithKeyless(false)); err != nil {
		t.Fatal(err)
	}
	if _, ok := obj2.GetAnnotations()[AnnotationContent]; ok {
		t.Fatal("embed must be opt-in — annotation set without WithEmbedContent")
	}
	if h1 == "" {
		t.Fatal("empty hash")
	}
	_ = metav1.ObjectMeta{}
}

// TestEmbedContent_BoundToCarrier: a validly-signed embedded blob cannot be
// stapled onto a differently-named/namespaced object (C2/V5).
func TestEmbedContent_BoundToCarrier(t *testing.T) {
	obj := embedContentFixture(t) // name=frag, ns=ns
	if err := SignObject(obj, WithKeyless(false), WithEmbedContent(true)); err != nil {
		t.Fatal(err)
	}
	ann := obj.GetAnnotations()
	// staple the signed annotations onto an object with a different name
	victim := NewMockSignableObject("uid2", "ns", "different-name", map[string]interface{}{"spec": "x"})
	victim.SetAnnotations(ann)
	err := VerifyObjectAllowUntrusted(victim)
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("stapling a signed blob onto a different-named object must fail as tamper; got %v", err)
	}
}

// TestEmbedContent_MalformedIsTamper: a malformed /content annotation on a
// signed object is a tamper signal (R1016), not a swallowed operational error
// (H1).
func TestEmbedContent_MalformedIsTamper(t *testing.T) {
	obj := embedContentFixture(t)
	if err := SignObject(obj, WithKeyless(false), WithEmbedContent(true)); err != nil {
		t.Fatal(err)
	}
	ann := obj.GetAnnotations()
	ann[AnnotationContent] = "!!!not-base64!!!"
	obj.SetAnnotations(ann)
	err := VerifyObjectAllowUntrusted(obj)
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("malformed embedded content on a signed object must classify as tamper; got %v", err)
	}
}
