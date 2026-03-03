package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

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

	pubKeyBytes, err := cryptoutils.MarshalPublicKeyToPEM(&signerPrivKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	sigObj := &Signature{
		Signature:   signature,
		Certificate: pubKeyBytes,
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

	pubKeyBytes, err := cryptoutils.MarshalPublicKeyToPEM(&c.privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	sigObj := &Signature{
		Signature:   signature,
		Certificate: pubKeyBytes,
		Issuer:      "local",
		Identity:    "local-key",
		Timestamp:   time.Now().Unix(),
	}

	return sigObj, nil
}

func (c *CosignAdapter) ecdsaSign(privKey *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest)
	if err != nil {
		return nil, err
	}

	signature := append(r.Bytes(), s.Bytes()...)
	return signature, nil
}

func (c *CosignAdapter) VerifyData(data []byte, sig *Signature, allowUntrusted bool) error {
	digest := sha256.Sum256(data)
	digestBytes := digest[:]

	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(sig.Certificate)
	if err != nil {
		return fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not ECDSA")
	}

	signatureLen := len(sig.Signature)
	if signatureLen < 1 {
		return fmt.Errorf("invalid signature length")
	}

	curveOrderBytes := (ecdsaPubKey.Params().N.BitLen() + 7) / 8
	if signatureLen != 2*curveOrderBytes {
		return fmt.Errorf("signature length mismatch")
	}

	r := new(big.Int).SetBytes(sig.Signature[:curveOrderBytes])
	s := new(big.Int).SetBytes(sig.Signature[curveOrderBytes:])

	valid := ecdsa.Verify(ecdsaPubKey, digestBytes, r, s)
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
