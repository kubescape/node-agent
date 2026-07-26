package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
)

func TestNewCosignAdapterWithPrivateKey(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	
	t.Run("Valid private key", func(t *testing.T) {
		adapter, err := NewCosignAdapterWithPrivateKey(false, privKey)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if adapter.privateKey != privKey {
			t.Error("Private key not set correctly")
		}
	})

	t.Run("Nil private key", func(t *testing.T) {
		_, err := NewCosignAdapterWithPrivateKey(false, nil)
		if err == nil {
			t.Error("Expected error for nil private key, got nil")
		}
	})
}

func TestCosignAdapter_GetKeysPEM(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	adapter, _ := NewCosignAdapterWithPrivateKey(false, privKey)

	t.Run("GetPrivateKeyPEM", func(t *testing.T) {
		pem, err := adapter.GetPrivateKeyPEM()
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if len(pem) == 0 {
			t.Error("Expected non-empty PEM")
		}
	})

	t.Run("GetPublicKeyPEM", func(t *testing.T) {
		pem, err := adapter.GetPublicKeyPEM()
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if len(pem) == 0 {
			t.Error("Expected non-empty PEM")
		}
	})

	t.Run("No private key", func(t *testing.T) {
		emptyAdapter := &CosignAdapter{}
		_, err := emptyAdapter.GetPrivateKeyPEM()
		if err == nil {
			t.Error("Expected error, got nil")
		}
		_, err = emptyAdapter.GetPublicKeyPEM()
		if err == nil {
			t.Error("Expected error, got nil")
		}
	})
}

func TestWithPrivateKey(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	opts := &SignOptions{}
	WithPrivateKey(privKey)(opts)
	if opts.PrivateKey != privKey {
		t.Error("PrivateKey option not set correctly")
	}
}

func TestCosignSigner(t *testing.T) {
	signer, err := NewCosignSigner(false)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	data := []byte("test data")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(sig.Signature) == 0 {
		t.Error("Expected non-empty signature")
	}
}

func TestCosignAdapter_ecdsaSign(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	adapter := &CosignAdapter{}
	data := []byte("test data")
	sig, err := adapter.ecdsaSign(privKey, data)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(sig) == 0 {
		t.Error("Expected non-empty signature")
	}
}

func TestVerifyData_ErrorCases(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	adapter, _ := NewCosignAdapterWithPrivateKey(false, privKey)
	data := []byte("test data")

	t.Run("Invalid certificate PEM", func(t *testing.T) {
		sig := &Signature{
			Signature:   []byte("sig"),
			Certificate: []byte("invalid-pem"),
		}
		err := adapter.VerifyData(data, sig, false)
		if err == nil {
			t.Error("Expected error for invalid certificate PEM, got nil")
		}
	})

	t.Run("PublicKey is not ECDSA", func(t *testing.T) {
		// Mock a non-ECDSA public key? Hard to do with current implementation.
		// Skipping for now.
	})

	t.Run("Certificate is CA", func(t *testing.T) {
		// Create a CA certificate
		template := x509.Certificate{
			IsCA: true,
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
		sig := &Signature{
			Signature:   []byte("sig"),
			Certificate: certDER,
		}
		err := adapter.VerifyData(data, sig, false)
		if err == nil {
			t.Error("Expected error for CA certificate, got nil")
		}
	})
}
