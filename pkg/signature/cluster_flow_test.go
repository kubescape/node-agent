package signature

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

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
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	signer, err := sigstore_signature.LoadECDSASigner(privKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to load signer: %v", err)
	}

	sig, err := signer.SignMessage(bytes.NewReader([]byte(hash)))
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}
	certBytes, err := generateTestCertificate(privKey)
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Use the package-level annotation flow
	sigObj := &Signature{
		Signature:   sig,
		Certificate: certBytes,
		Timestamp:   time.Now().Unix(),
	}
	annotations, err := cosignAdapter.EncodeSignatureToAnnotations(sigObj)
	if err != nil {
		t.Fatalf("Failed to encode signature to annotations: %v", err)
	}
	adapter.SetAnnotations(annotations)

	// Now verify using the higher-level flow
	err = VerifyObjectAllowUntrusted(adapter)
	if err != nil {
		t.Fatalf("VerifyObjectAllowUntrusted failed: %v", err)
	}
}

func generateTestCertificate(privKey *ecdsa.PrivateKey) ([]byte, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "test-signer",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM, nil
}
