package signature

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"

	sigstore_signature "github.com/sigstore/sigstore/pkg/signature"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func TestClusterProfileStructure(t *testing.T) {
	// Simulate a cluster profile with empty TypeMeta (like from cluster)
	profile := &v1beta1.ApplicationProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "",
			Kind:       "",
		},
	}
	profile.Name = "test-signed"
	profile.Namespace = "default"

	adapter := profiles.NewApplicationProfileAdapter(profile)
	content := adapter.GetContent()

	if m, ok := content.(map[string]interface{}); ok {
		t.Logf("apiVersion: %v (type: %T)", m["apiVersion"], m["apiVersion"])
		t.Logf("kind: %v (type: %T)", m["kind"], m["kind"])

		// Verify fallback values are applied
		if m["apiVersion"] != "spdx.softwarecomposition.kubescape.io/v1beta1" {
			t.Errorf("Expected fallback apiVersion, got %s", m["apiVersion"])
		}
		if m["kind"] != "ApplicationProfile" {
			t.Errorf("Expected fallback kind, got %s", m["kind"])
		}
	} else {
		t.Errorf("Expected map, got %T", content)
	}
}

func TestReproduceClusterVerificationFlow(t *testing.T) {
	// Simulate the exact scenario from the cluster
	profile := &v1beta1.ApplicationProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "",
			Kind:       "",
		},
	}
	profile.Name = "replicaset-nginx2-5bffdcc777-signed"
	profile.Namespace = "default"
	profile.Labels = map[string]string{
		"kubescape.io/instance-template-hash":    "5bffdcc777",
		"kubescape.io/workload-api-group":        "apps",
		"kubescape.io/workload-api-version":      "v1",
		"kubescape.io/workload-kind":             "Deployment",
		"kubescape.io/workload-name":             "nginx2",
		"kubescape.io/workload-namespace":        "default",
		"kubescape.io/workload-resource-version": "15471",
	}

	adapter := profiles.NewApplicationProfileAdapter(profile)

	// Calculate hash
	cosignAdapter := &CosignAdapter{}
	hash, err := cosignAdapter.GetContentHash(adapter.GetContent())
	if err != nil {
		t.Fatalf("Failed to compute hash: %v", err)
	}

	t.Logf("Computed hash: %s", hash)

	// Generate a key and sign
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := sigstore_signature.LoadECDSASigner(privKey, crypto.SHA256)

	sig, _ := signer.SignMessage(bytes.NewReader([]byte(hash)))
	certBytes := generateTestCertificate(privKey)

	// Add signature annotations
	adapter.SetAnnotations(map[string]string{
		"signature.kubescape.io/signature":   base64.StdEncoding.EncodeToString(sig),
		"signature.kubescape.io/certificate": base64.StdEncoding.EncodeToString(certBytes),
	})

	// Now verify
	sigObj, _ := cosignAdapter.DecodeSignatureFromAnnotations(adapter.GetAnnotations())
	verifier, _ := sigstore_signature.LoadECDSAVerifier(&privKey.PublicKey, crypto.SHA256)

	err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader([]byte(hash)))
	t.Logf("Verification after signing with hash string: %v", err)

	// Try with hex-decoded bytes
	hashBytes, _ := hex.DecodeString(hash)
	err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(hashBytes))
	t.Logf("Verification with hex-decoded bytes: %v", err)

	// Clean up: verify the signature is correctly stored and retrieved
	if sigObj.Signature == nil {
		t.Error("Signature was not properly decoded from annotations")
	}
}

func generateTestCertificate(privKey *ecdsa.PrivateKey) []byte {
	certPEM := `-----BEGIN CERTIFICATE-----
MIIBgDCCASagAwIBAgIRAI2ZHwaseDxijN4mwQBzDX0wCgYIKoZIzj0EAwIwJjEk
MCIGA1UEAwwbbWF0dGhpYXMuYmVydHNjaHlAZ21haWwuY29tMB4XDTI2MDMwOTE1
NDQxNloXDTI3MDMwOTE1NDQxNlowJjEkMCIGA1UEAwwbbWF0dGhpYXMuYmVydHNj
aHlAZ21haWwuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsw03ufyGYW/+
XZYflPREBvDuKYQ/vkg94kuHSDlPnsqkisDCdusaI61FKAN1O2ICVgpSkultFDkVY
yXUVgC9wuMbKNTANBgkqhkiG9w0BAQsFAAOCAQEAnJKHv40VUxqsKS0hF45sKSvVN
2l2xLOo0Rke0FPQrCIQCuwFKMxQo42ZbJxdhqpnpCgmLmOeGN/M4GgaGKOrynvg==
-----END CERTIFICATE-----`
	return []byte(certPEM)
}
