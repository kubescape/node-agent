package signature

import (
	"testing"
)

func TestVerifyProfileStrict(t *testing.T) {
	profileContent := map[string]interface{}{
		"type":  "test-profile",
		"data":  "test-data",
		"value": 123,
	}

	profile := NewMockSignableProfile("test-uid", "test-ns", "test-profile-verify", profileContent)

	err := SignProfileKeyless(profile)
	if err != nil {
		t.Fatalf("SignProfileKeyless failed: %v", err)
	}

	err = VerifyProfileStrict(profile)
	if err != nil {
		t.Fatalf("VerifyProfileStrict failed: %v", err)
	}
}

func TestVerifyProfileAllowUntrusted(t *testing.T) {
	profileContent := map[string]interface{}{
		"type":  "test-profile",
		"data":  "test-data",
		"value": 456,
	}

	profile := NewMockSignableProfile("test-uid", "test-ns", "test-profile-verify-2", profileContent)

	err := SignProfileWithKey(profile)
	if err != nil {
		t.Fatalf("SignProfileWithKey failed: %v", err)
	}

	err = VerifyProfileAllowUntrusted(profile)
	if err != nil {
		t.Fatalf("VerifyProfileAllowUntrusted failed: %v", err)
	}
}

func TestVerifyProfileTampered(t *testing.T) {
	originalContent := map[string]interface{}{
		"type":      "test-profile",
		"data":      "test-data",
		"value":     789,
		"confident": "secret",
	}

	profile := NewMockSignableProfile("test-uid", "test-ns", "test-profile-tamper", originalContent)

	err := SignProfileKeyless(profile)
	if err != nil {
		t.Fatalf("SignProfileKeyless failed: %v", err)
	}

	tamperedContent := map[string]interface{}{
		"type":      "test-profile",
		"data":      "test-data",
		"value":     999,
		"confident": "mod",
	}
	profile.content = tamperedContent

	err = VerifyProfileStrict(profile)
	if err == nil {
		t.Error("Expected verification failure for tampered profile, got success")
	}
}

func TestVerifyProfileNoAnnotations(t *testing.T) {
	profileContent := map[string]interface{}{
		"type": "test-profile",
		"data": "test-data",
	}

	profile := NewMockSignableProfile("test-uid", "test-ns", "test-profile-no-sig", profileContent)

	err := VerifyProfileStrict(profile)
	if err == nil {
		t.Error("Expected error for profile without annotations, got nil")
	}
}

func TestVerifyProfileMissingSignature(t *testing.T) {
	profileContent := map[string]interface{}{
		"type": "test-profile",
		"data": "test-data",
	}

	profile := NewMockSignableProfile("test-uid", "test-ns", "test-profile-missing-sig", profileContent)
	profile.SetAnnotations(map[string]string{
		AnnotationIssuer:   "test-issuer",
		AnnotationIdentity: "test-identity",
	})

	err := VerifyProfileStrict(profile)
	if err == nil {
		t.Error("Expected error for profile without signature annotation, got nil")
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	profileContent := map[string]interface{}{
		"type":          "roundtrip-profile",
		"containers":    []string{"nginx", "redis"},
		"capabilities":  []string{"NET_BIND_SERVICE"},
		"networkPolicy": "allow",
	}

	profile := NewMockSignableProfile("roundtrip-uid", "roundtrip-ns", "roundtrip-profile", profileContent)

	err := SignProfileKeyless(profile)
	if err != nil {
		t.Fatalf("SignProfileKeyless failed: %v", err)
	}

	if !IsSigned(profile) {
		t.Fatal("Profile should be signed after signing")
	}

	sig, err := GetProfileSignature(profile)
	if err != nil {
		t.Fatalf("GetProfileSignature failed: %v", err)
	}

	if len(sig.Signature) == 0 {
		t.Error("Signature should not be empty")
	}

	err = VerifyProfileStrict(profile)
	if err != nil {
		t.Fatalf("VerifyProfileStrict failed after signing: %v", err)
	}
}

func TestSignAndVerifyDifferentKeys(t *testing.T) {
	profileContent := map[string]interface{}{
		"type": "multi-key-test",
		"data": "data",
	}

	profile1 := NewMockSignableProfile("uid1", "ns", "profile1", profileContent)
	profile2 := NewMockSignableProfile("uid2", "ns", "profile2", profileContent)

	err := SignProfileWithKey(profile1)
	if err != nil {
		t.Fatalf("SignProfileWithKey failed for profile1: %v", err)
	}

	err = SignProfileKeyless(profile2)
	if err != nil {
		t.Fatalf("SignProfileKeyless failed for profile2: %v", err)
	}

	sig1, err := GetProfileSignature(profile1)
	if err != nil {
		t.Fatalf("GetProfileSignature failed for profile1: %v", err)
	}

	sig2, err := GetProfileSignature(profile2)
	if err != nil {
		t.Fatalf("GetProfileSignature failed for profile2: %v", err)
	}

	if sig1.Issuer == sig2.Issuer && sig1.Issuer != "" {
		t.Log("Both profiles have same issuer")
	}

	if sig1.Identity == sig2.Identity && sig1.Identity != "" {
		t.Log("Both profiles have same identity")
	}
}
