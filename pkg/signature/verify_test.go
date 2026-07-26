package signature

import (
	"io"
	"os"
	"strings"
	"testing"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// captureLogOutput redirects the global logger to a pipe, runs fn, and returns
// the captured log text. The logger is restored to its previous writer afterward.
func captureLogOutput(t *testing.T, fn func()) string {
	t.Helper()

	// Ensure the global logger is initialized as pretty (supports SetWriter).
	logger.InitLogger("pretty")

	oldWriter := logger.L().GetWriter()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	logger.L().SetWriter(w)

	fn()

	w.Close()
	var buf strings.Builder
	io.Copy(&buf, r)
	r.Close()

	// Restore original writer.
	logger.L().SetWriter(oldWriter)

	return buf.String()
}

// TestTamperedAPLogsWarning signs an ApplicationProfile, tampers with it,
// verifies it, and asserts the warning log contains the expected fields:
// namespace, name, and "Object signature verification failed".
func TestTamperedAPLogsWarning(t *testing.T) {
	ap := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tamper-warn-ap",
			Namespace: "tamper-ns",
		},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name:     "curl",
					Execs:    []v1beta1.ExecCalls{{Path: "/usr/bin/curl"}},
					Syscalls: []string{"read", "write"},
				},
			},
		},
	}

	adapter := profiles.NewApplicationProfileAdapter(ap)
	if err := SignObjectDisableKeyless(adapter); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// Tamper: add an exec entry.
	ap.Spec.Containers[0].Execs = append(ap.Spec.Containers[0].Execs,
		v1beta1.ExecCalls{Path: "/usr/bin/nslookup"})

	tamperedAdapter := profiles.NewApplicationProfileAdapter(ap)

	logOutput := captureLogOutput(t, func() {
		err := VerifyObjectAllowUntrusted(tamperedAdapter)
		if err == nil {
			t.Error("expected verification to fail for tampered AP")
		}
	})

	// Assert warning log contains expected fields.
	if !strings.Contains(logOutput, "Object signature verification failed") {
		t.Errorf("expected warning message in log output, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, "tamper-ns") {
		t.Errorf("expected namespace 'tamper-ns' in log output, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, "tamper-warn-ap") {
		t.Errorf("expected name 'tamper-warn-ap' in log output, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, "invalid signature") {
		t.Errorf("expected 'invalid signature' in log output, got:\n%s", logOutput)
	}
}

// TestTamperedNNLogsWarning signs a NetworkNeighborhood, tampers with it,
// verifies it, and asserts the warning log contains the expected fields.
func TestTamperedNNLogsWarning(t *testing.T) {
	nn := &v1beta1.NetworkNeighborhood{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tamper-warn-nn",
			Namespace: "tamper-ns",
		},
		Spec: v1beta1.NetworkNeighborhoodSpec{
			Containers: []v1beta1.NetworkNeighborhoodContainer{
				{
					Name: "curl",
					Egress: []v1beta1.NetworkNeighbor{
						{
							Identifier: "legit",
							DNSNames:   []string{"example.com."},
							IPAddress:  "93.184.216.34",
						},
					},
				},
			},
		},
	}

	adapter := profiles.NewNetworkNeighborhoodAdapter(nn)
	if err := SignObjectDisableKeyless(adapter); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// Tamper: add an egress entry.
	nn.Spec.Containers[0].Egress = append(nn.Spec.Containers[0].Egress,
		v1beta1.NetworkNeighbor{
			Identifier: "evil",
			DNSNames:   []string{"evil-c2.io."},
			IPAddress:  "6.6.6.6",
		})

	tamperedAdapter := profiles.NewNetworkNeighborhoodAdapter(nn)

	logOutput := captureLogOutput(t, func() {
		err := VerifyObjectAllowUntrusted(tamperedAdapter)
		if err == nil {
			t.Error("expected verification to fail for tampered NN")
		}
	})

	if !strings.Contains(logOutput, "Object signature verification failed") {
		t.Errorf("expected warning message in log output, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, "tamper-ns") {
		t.Errorf("expected namespace 'tamper-ns' in log output, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, "tamper-warn-nn") {
		t.Errorf("expected name 'tamper-warn-nn' in log output, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, "invalid signature") {
		t.Errorf("expected 'invalid signature' in log output, got:\n%s", logOutput)
	}
}

// TestSuccessfulVerifyLogsInfo verifies that a valid signature produces the
// "Successfully verified object signature" info log with identity and issuer.
func TestSuccessfulVerifyLogsInfo(t *testing.T) {
	ap := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "valid-ap",
			Namespace: "valid-ns",
		},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name:     "nginx",
					Execs:    []v1beta1.ExecCalls{{Path: "/usr/sbin/nginx"}},
					Syscalls: []string{"read", "write", "openat"},
				},
			},
		},
	}

	adapter := profiles.NewApplicationProfileAdapter(ap)
	if err := SignObjectDisableKeyless(adapter); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	logOutput := captureLogOutput(t, func() {
		if err := VerifyObjectAllowUntrusted(adapter); err != nil {
			t.Fatalf("expected verification to succeed: %v", err)
		}
	})

	if !strings.Contains(logOutput, "Successfully verified object signature") {
		t.Errorf("expected info message in log output, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, "valid-ns") {
		t.Errorf("expected namespace 'valid-ns' in log output, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, "valid-ap") {
		t.Errorf("expected name 'valid-ap' in log output, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, "local-key") {
		t.Errorf("expected identity 'local-key' in log output, got:\n%s", logOutput)
	}
}

// TestSignLogsInfo verifies that signing an object produces the
// "Successfully signed object" info log with identity and issuer.
func TestSignLogsInfo(t *testing.T) {
	ap := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sign-log-ap",
			Namespace: "sign-ns",
		},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name:     "app",
					Execs:    []v1beta1.ExecCalls{{Path: "/app/main"}},
					Syscalls: []string{"read"},
				},
			},
		},
	}

	adapter := profiles.NewApplicationProfileAdapter(ap)

	logOutput := captureLogOutput(t, func() {
		if err := SignObjectDisableKeyless(adapter); err != nil {
			t.Fatalf("sign failed: %v", err)
		}
	})

	if !strings.Contains(logOutput, "Successfully signed object") {
		t.Errorf("expected sign info message in log output, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, "sign-ns") {
		t.Errorf("expected namespace 'sign-ns' in log output, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, "sign-log-ap") {
		t.Errorf("expected name 'sign-log-ap' in log output, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, "local-key") {
		t.Errorf("expected identity 'local-key' in log output, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, "local") {
		t.Errorf("expected issuer 'local' in log output, got:\n%s", logOutput)
	}
}
