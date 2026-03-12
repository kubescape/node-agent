package signature

import (
	"os"
	"testing"
)

func TestVerifyObjectStrict(t *testing.T) {
	if os.Getenv("ENABLE_KEYLESS_TESTS") == "" {
		t.Skip("Skipping TestVerifyObjectStrict. Set ENABLE_KEYLESS_TESTS to run.")
	}
	profileContent := map[string]interface{}{
		"type":  "test-profile",
		"data":  "test-data",
		"value": 123,
	}

	profile := NewMockSignableObject("test-uid", "test-ns", "test-profile-verify", profileContent)

	err := SignObjectKeyless(profile)
	if err != nil {
		t.Fatalf("SignObjectKeyless failed: %v", err)
	}

	err = VerifyObjectStrict(profile)
	if err != nil {
		t.Fatalf("VerifyObjectStrict failed: %v", err)
	}
}

func TestVerifyObjectAllowUntrusted(t *testing.T) {
	profileContent := map[string]interface{}{
		"type":  "test-profile",
		"data":  "test-data",
		"value": 456,
	}

	profile := NewMockSignableObject("test-uid", "test-ns", "test-profile-verify-2", profileContent)

	err := SignObjectDisableKeyless(profile)
	if err != nil {
		t.Fatalf("SignObjectDisableKeyless failed: %v", err)
	}

	err = VerifyObjectAllowUntrusted(profile)
	if err != nil {
		t.Fatalf("VerifyObjectAllowUntrusted failed: %v", err)
	}
}

func TestVerifyObjectTampered(t *testing.T) {
	if os.Getenv("ENABLE_KEYLESS_TESTS") == "" {
		t.Skip("Skipping TestVerifyObjectTampered. Set ENABLE_KEYLESS_TESTS to run.")
	}
	originalContent := map[string]interface{}{
		"type":      "test-profile",
		"data":      "test-data",
		"value":     789,
		"confident": "secret",
	}

	profile := NewMockSignableObject("test-uid", "test-ns", "test-profile-tamper", originalContent)

	err := SignObjectKeyless(profile)
	if err != nil {
		t.Fatalf("SignObjectKeyless failed: %v", err)
	}

	tamperedContent := map[string]interface{}{
		"type":      "test-profile",
		"data":      "test-data",
		"value":     999,
		"confident": "mod",
	}
	profile.content = tamperedContent

	err = VerifyObjectStrict(profile)
	if err == nil {
		t.Error("Expected verification failure for tampered profile, got success")
	}
}

func TestVerifyObjectNoAnnotations(t *testing.T) {
	profileContent := map[string]interface{}{
		"type": "test-profile",
		"data": "test-data",
	}

	profile := NewMockSignableObject("test-uid", "test-ns", "test-profile-no-sig", profileContent)

	err := VerifyObjectStrict(profile)
	if err == nil {
		t.Error("Expected error for profile without annotations, got nil")
	}
}

func TestVerifyObjectMissingSignature(t *testing.T) {
	profileContent := map[string]interface{}{
		"type": "test-profile",
		"data": "test-data",
	}

	profile := NewMockSignableObject("test-uid", "test-ns", "test-profile-missing-sig", profileContent)
	profile.SetAnnotations(map[string]string{
		AnnotationIssuer:   "test-issuer",
		AnnotationIdentity: "test-identity",
	})

	err := VerifyObjectStrict(profile)
	if err == nil {
		t.Error("Expected error for profile without signature annotation, got nil")
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	if os.Getenv("ENABLE_KEYLESS_TESTS") == "" {
		t.Skip("Skipping TestSignAndVerifyRoundTrip. Set ENABLE_KEYLESS_TESTS to run.")
	}
	profileContent := map[string]interface{}{
		"type":          "roundtrip-profile",
		"containers":    []string{"nginx", "redis"},
		"capabilities":  []string{"NET_BIND_SERVICE"},
		"networkPolicy": "allow",
	}

	profile := NewMockSignableObject("roundtrip-uid", "roundtrip-ns", "roundtrip-profile", profileContent)

	err := SignObjectKeyless(profile)
	if err != nil {
		t.Fatalf("SignObjectKeyless failed: %v", err)
	}

	if !IsSigned(profile) {
		t.Fatal("Profile should be signed after signing")
	}

	sig, err := GetObjectSignature(profile)
	if err != nil {
		t.Fatalf("GetObjectSignature failed: %v", err)
	}

	if len(sig.Signature) == 0 {
		t.Error("Signature should not be empty")
	}

	err = VerifyObjectStrict(profile)
	if err != nil {
		t.Fatalf("VerifyObjectStrict failed after signing: %v", err)
	}
}

func TestSignAndVerifyDifferentKeys(t *testing.T) {
	if os.Getenv("ENABLE_KEYLESS_TESTS") == "" {
		t.Skip("Skipping TestSignAndVerifyDifferentKeys. Set ENABLE_KEYLESS_TESTS to run.")
	}
	profileContent := map[string]interface{}{
		"type": "multi-key-test",
		"data": "data",
	}

	profile1 := NewMockSignableObject("uid1", "ns", "profile1", profileContent)
	profile2 := NewMockSignableObject("uid2", "ns", "profile2", profileContent)

	err := SignObjectDisableKeyless(profile1)
	if err != nil {
		t.Fatalf("SignObjectDisableKeyless failed for profile1: %v", err)
	}

	err = SignObjectKeyless(profile2)
	if err != nil {
		t.Fatalf("SignObjectKeyless failed for profile2: %v", err)
	}

	sig1, err := GetObjectSignature(profile1)
	if err != nil {
		t.Fatalf("GetObjectSignature failed for profile1: %v", err)
	}

	sig2, err := GetObjectSignature(profile2)
	if err != nil {
		t.Fatalf("GetObjectSignature failed for profile2: %v", err)
	}

	if sig1.Issuer != "local" {
		t.Errorf("Expected key-based signing issuer 'local', got '%s'", sig1.Issuer)
	}

	if sig1.Identity != "local-key" {
		t.Errorf("Expected key-based signing identity 'local-key', got '%s'", sig1.Identity)
	}

	if sig2.Issuer == "" {
		t.Errorf("Expected keyless signing to have issuer, got empty")
	}

	if sig2.Identity == "" {
		t.Errorf("Expected keyless signing to have identity, got empty")
	}
}
