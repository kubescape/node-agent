package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type ecdsaSignature struct {
	R, S *big.Int
}

const (
	sigstoreIssuer = "https://token.actions.githubusercontent.com"
	sigstoreOIDC   = "kubernetes.io"
)

type CosignAdapter struct {
	privateKey *ecdsa.PrivateKey
	useKeyless bool
}

func NewCosignAdapter(useKeyless bool) (*CosignAdapter, error) {
	if useKeyless {
		return &CosignAdapter{
			useKeyless: true,
		}, nil
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	return &CosignAdapter{
		privateKey: privateKey,
		useKeyless: false,
	}, nil
}

func NewCosignAdapterWithPrivateKey(useKeyless bool, privateKey *ecdsa.PrivateKey) (*CosignAdapter, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}

	return &CosignAdapter{
		privateKey: privateKey,
		useKeyless: useKeyless,
	}, nil
}

func (c *CosignAdapter) SignData(data []byte) (*Signature, error) {
	digest := sha256.Sum256(data)
	digestBytes := digest[:]

	if c.useKeyless {
		return c.signKeyless(digestBytes)
	}

	return c.signWithKey(digestBytes)
}

func (c *CosignAdapter) signKeyless(digest []byte) (*Signature, error) {
	signerPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keyless signer key: %w", err)
	}

	signature, err := c.ecdsaSign(signerPrivKey, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	certBytes, err := c.generateCertificate(signerPrivKey, sigstoreOIDC, sigstoreIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	sigObj := &Signature{
		Signature:   signature,
		Certificate: certBytes,
		Issuer:      sigstoreIssuer,
		Identity:    sigstoreOIDC,
		Timestamp:   time.Now().Unix(),
	}

	return sigObj, nil
}

func (c *CosignAdapter) signWithKey(digest []byte) (*Signature, error) {
	signature, err := c.ecdsaSign(c.privateKey, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	certBytes, err := c.generateCertificate(c.privateKey, "local-key", "local")
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	sigObj := &Signature{
		Signature:   signature,
		Certificate: certBytes,
		Issuer:      "local",
		Identity:    "local-key",
		Timestamp:   time.Now().Unix(),
	}

	return sigObj, nil
}

func (c *CosignAdapter) generateCertificate(privKey *ecdsa.PrivateKey, identity, issuer string) ([]byte, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: identity,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM, nil
}

func (c *CosignAdapter) ecdsaSign(privKey *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(ecdsaSignature{R: r, S: s})
}

func (c *CosignAdapter) GetPrivateKeyPEM() ([]byte, error) {
	if c.privateKey == nil {
		return nil, fmt.Errorf("no private key available")
	}

	derBytes, err := x509.MarshalECPrivateKey(c.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(block), nil
}

func (c *CosignAdapter) GetPublicKeyPEM() ([]byte, error) {
	if c.privateKey == nil {
		return nil, fmt.Errorf("no private key available")
	}

	pubKeyBytes, err := cryptoutils.MarshalPublicKeyToPEM(&c.privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return pubKeyBytes, nil
}

func (c *CosignAdapter) VerifyData(data []byte, sig *Signature, allowUntrusted bool) error {
	digest := sha256.Sum256(data)
	digestBytes := digest[:]

	var ecdsaPubKey *ecdsa.PublicKey

	block, _ := pem.Decode(sig.Certificate)
	if block != nil && block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}

		var ok bool
		ecdsaPubKey, ok = cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("certificate public key is not ECDSA")
		}

		if !allowUntrusted {
			if cert.IsCA || cert.Subject.CommonName == "" {
				return fmt.Errorf("invalid certificate: must not be CA and must have a valid subject")
			}

			if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
				return fmt.Errorf("certificate is not valid at this time")
			}
		}
	} else {
		if !allowUntrusted {
			return fmt.Errorf("untrusted certificate rejected: require valid x509 certificate chain")
		}

		pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(sig.Certificate)
		if err != nil {
			return fmt.Errorf("failed to unmarshal public key: %w", err)
		}

		var ok bool
		ecdsaPubKey, ok = pubKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("public key is not ECDSA")
		}
	}

	var ecdsaSig ecdsaSignature
	_, err := asn1.Unmarshal(sig.Signature, &ecdsaSig)
	if err != nil {
		return fmt.Errorf("failed to unmarshal signature: %w", err)
	}

	valid := ecdsa.Verify(ecdsaPubKey, digestBytes, ecdsaSig.R, ecdsaSig.S)
	if !valid {
		return fmt.Errorf("invalid signature")
	}

	if c.useKeyless && !allowUntrusted {
		if sig.Issuer == "" || sig.Identity == "" {
			return fmt.Errorf("keyless signature missing issuer or identity")
		}
	}

	return nil
}

func (c *CosignAdapter) GetContentHash(obj interface{}) (string, error) {
	data, err := json.Marshal(obj)
	if err != nil {
		return "", fmt.Errorf("failed to marshal object: %w", err)
	}

	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func (c *CosignAdapter) EncodeSignatureToAnnotations(sig *Signature) (map[string]string, error) {
	annotations := make(map[string]string)

	annotations[AnnotationSignature] = base64.StdEncoding.EncodeToString(sig.Signature)

	if len(sig.Certificate) > 0 {
		annotations[AnnotationCertificate] = base64.StdEncoding.EncodeToString(sig.Certificate)
	}
	if sig.Issuer != "" {
		annotations[AnnotationIssuer] = sig.Issuer
	}
	if sig.Identity != "" {
		annotations[AnnotationIdentity] = sig.Identity
	}
	annotations[AnnotationTimestamp] = fmt.Sprintf("%d", sig.Timestamp)

	return annotations, nil
}

func (c *CosignAdapter) DecodeSignatureFromAnnotations(annotations map[string]string) (*Signature, error) {
	sig := &Signature{}

	signatureB64, ok := annotations[AnnotationSignature]
	if !ok {
		return nil, fmt.Errorf("missing %s annotation", AnnotationSignature)
	}

	var err error
	sig.Signature, err = base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	if certB64, ok := annotations[AnnotationCertificate]; ok {
		sig.Certificate, err = base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode certificate: %w", err)
		}
	}

	sig.Issuer = annotations[AnnotationIssuer]
	sig.Identity = annotations[AnnotationIdentity]

	if timestamp, ok := annotations[AnnotationTimestamp]; ok {
		var ts int64
		_, err = fmt.Sscanf(timestamp, "%d", &ts)
		if err != nil {
			return nil, fmt.Errorf("failed to parse timestamp: %w", err)
		}
		sig.Timestamp = ts
	}

	return sig, nil
}
