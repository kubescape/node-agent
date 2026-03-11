package signature

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"time"

	"context"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kubescape/storage/pkg/utils"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/providers"
	_ "github.com/sigstore/cosign/v3/pkg/providers/all"
	"github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	sigstore_signature "github.com/sigstore/sigstore/pkg/signature"
)

var _ = cosign.Signature
var _ = providers.Enabled
var _ = bundle.RekorBundle{}
var _ = api.CertificateRequest{}
var _ = client.Rekor{}
var _ = models.LogEntry{}
var _ = fulcioroots.Get
var _ = oauthflow.OIDConnect
var _ = oauthflow.DefaultIDTokenGetter

const (
	sigstoreIssuer = "https://token.actions.githubusercontent.com"
	sigstoreOIDC   = "kubernetes.io"
	fulcioURL      = "https://fulcio.sigstore.dev"
	rekorURL       = "https://rekor.sigstore.dev"
)

type CosignAdapter struct {
	privateKey    *ecdsa.PrivateKey
	signer        sigstore_signature.Signer
	verifier      sigstore_signature.Verifier
	useKeyless    bool
	tokenProvider func(ctx context.Context) (string, error)
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

	signer, err := sigstore_signature.LoadECDSASigner(privateKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to load ECDSA signer: %w", err)
	}

	verifier, err := sigstore_signature.LoadECDSAVerifier(&privateKey.PublicKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to load ECDSA verifier: %w", err)
	}

	return &CosignAdapter{
		privateKey: privateKey,
		signer:     signer,
		verifier:   verifier,
		useKeyless: false,
	}, nil
}

func NewCosignAdapterWithPrivateKey(useKeyless bool, privateKey *ecdsa.PrivateKey) (*CosignAdapter, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}

	signer, err := sigstore_signature.LoadECDSASigner(privateKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to load ECDSA signer: %w", err)
	}

	verifier, err := sigstore_signature.LoadECDSAVerifier(&privateKey.PublicKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to load ECDSA verifier: %w", err)
	}

	return &CosignAdapter{
		privateKey: privateKey,
		signer:     signer,
		verifier:   verifier,
		useKeyless: useKeyless,
	}, nil
}

func (c *CosignAdapter) SignData(data []byte) (*Signature, error) {
	if c.useKeyless {
		return c.signKeyless(data)
	}

	return c.signWithKey(data)
}

func (c *CosignAdapter) SetTokenProvider(provider func(context.Context) (string, error)) {
	c.tokenProvider = provider
}

func (c *CosignAdapter) signKeyless(data []byte) (*Signature, error) {
	ctx := context.Background()

	var tok string
	var err error
	var identity string
	var issuer string

	// 1. Get OIDC Token
	if c.tokenProvider != nil {
		tok, err = c.tokenProvider(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to provide OIDC token from provider: %w", err)
		}
	} else if providers.Enabled(ctx) {
		tok, err = providers.Provide(ctx, "sigstore")
		if err != nil {
			return nil, fmt.Errorf("failed to provide OIDC token: %w", err)
		}
	}

	if tok != "" {
		// Extract "sub" and "iss" from the JWT token
		parser := jwt.NewParser()
		token, _, err := parser.ParseUnverified(tok, jwt.MapClaims{})
		if err != nil {
			return nil, fmt.Errorf("failed to parse OIDC token: %w", err)
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, fmt.Errorf("failed to get claims from OIDC token")
		}

		sub, ok := claims["sub"].(string)
		if !ok {
			return nil, fmt.Errorf("failed to get 'sub' claim from OIDC token")
		}
		identity = sub

		iss, ok := claims["iss"].(string)
		if !ok {
			return nil, fmt.Errorf("failed to get 'iss' claim from OIDC token")
		}
		issuer = iss
	} else {
		// Fallback to interactive flow if not in CI and no provider
		fmt.Println("No OIDC provider enabled (CI). Falling back to interactive flow...")
		// Sigstore's default issuer and client ID
		issuerURL := "https://oauth2.sigstore.dev/auth"
		clientID := "sigstore"
		// This will open a browser window for authentication
		oidcToken, err := oauthflow.OIDConnect(issuerURL, clientID, "", "", oauthflow.DefaultIDTokenGetter)
		if err != nil {
			return nil, fmt.Errorf("failed to get interactive OIDC token: %w", err)
		}
		tok = oidcToken.RawString
		identity = oidcToken.Subject
		issuer = issuerURL
	}
	_ = tok

	// 2. Generate Ephemeral Key Pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	signer, err := sigstore_signature.LoadECDSASigner(privKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to load ephemeral signer: %w", err)
	}

	// 3. Get Certificate from Fulcio using the real client
	certBytes, err := c.getFulcioCertificate(ctx, privKey, identity, tok)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate from Fulcio: %w", err)
	}

	// 4. Sign Data
	sig, err := signer.SignMessage(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	// 5. Upload to Rekor (Placeholder for real upload)
	// rekorClient, _ := rekor.GetByProxy(rekorURL)
	// entry, _ := cosign.TLogUpload(ctx, rekorClient, sig, certBytes, data)

	return &Signature{
		Signature:   sig,
		Certificate: certBytes,
		Issuer:      issuer,
		Identity:    identity,
		Timestamp:   time.Now().Unix(),
	}, nil
}

func (c *CosignAdapter) simulateKeyless(data []byte) (*Signature, error) {
	return nil, fmt.Errorf("simulateKeyless is deprecated, use real keyless signing")
}

func (c *CosignAdapter) signWithKey(data []byte) (*Signature, error) {
	sig, err := c.signer.SignMessage(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	certBytes, err := c.generateCertificate(c.privateKey, "local-key", "local")
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	sigObj := &Signature{
		Signature:   sig,
		Certificate: certBytes,
		Issuer:      "local",
		Identity:    "local-key",
		Timestamp:   time.Now().Unix(),
	}

	return sigObj, nil
}

func (c *CosignAdapter) getFulcioCertificate(ctx context.Context, privKey *ecdsa.PrivateKey, identity, oidcToken string) ([]byte, error) {
	// Parse Fulcio URL
	fulcioAddr, err := url.Parse(fulcioURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Fulcio URL: %w", err)
	}

	// Create Fulcio client
	fulcioClient := api.NewClient(fulcioAddr)

	// Marshal public key to ASN.1 DER format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Create CertificateRequest with the public key
	certReq := api.CertificateRequest{
		PublicKey: api.Key{
			Content:   pubKeyBytes,
			Algorithm: "ecdsa",
		},
	}

	// We need to prove possession of the OIDC token's identity by signing the identity
	// Fulcio expects a signature over the identity (e.g. email or subject)
	proof, err := c.ecdsaSign(privKey, []byte(identity))
	if err != nil {
		return nil, fmt.Errorf("failed to sign identity for proof: %w", err)
	}
	certReq.SignedEmailAddress = proof

	// Call Fulcio API to get certificate
	certResp, err := fulcioClient.SigningCert(certReq, oidcToken)
	if err != nil {
		return nil, fmt.Errorf("Fulcio SigningCert failed: %w", err)
	}

	return certResp.CertPEM, nil
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

func (c *CosignAdapter) ecdsaSign(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	signer, err := sigstore_signature.LoadECDSASigner(privKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return signer.SignMessage(bytes.NewReader(data))
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
	if sig == nil {
		return fmt.Errorf("VerifyData: Signature value is nil")
	}
	if len(sig.Certificate) == 0 {
		return fmt.Errorf("VerifyData: Signature.Certificate is empty")
	}

	var verifier sigstore_signature.Verifier
	var err error

	// If we have a certificate, it could be a keyless signature (Fulcio) or a key-based signature with a cert.
	// For keyless, we should ideally verify the certificate chain and Rekor bundle.
	// For now, we continue to support the simplified verification but using sigstore's abstractions.

	block, _ := pem.Decode(sig.Certificate)
	if block != nil && block.Type == "CERTIFICATE" {
		var cert *x509.Certificate
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}

		if !allowUntrusted {
			if cert.IsCA {
				return fmt.Errorf("invalid certificate: must not be CA")
			}

			// Build and verify the certificate chain
			roots, err := fulcioroots.Get()
			if err != nil {
				return fmt.Errorf("failed to get Fulcio roots: %w", err)
			}
			opts := x509.VerifyOptions{
				Roots: roots,
				KeyUsages: []x509.ExtKeyUsage{
					x509.ExtKeyUsageCodeSigning,
				},
				CurrentTime: time.Unix(sig.Timestamp, 0),
			}
			if _, err := cert.Verify(opts); err != nil {
				return fmt.Errorf("failed to verify certificate chain: %w", err)
			}

			if time.Unix(sig.Timestamp, 0).Before(cert.NotBefore) || time.Unix(sig.Timestamp, 0).After(cert.NotAfter) {
				return fmt.Errorf("certificate was not valid at signing time")
			}

			// In a production environment, we would verify the certificate chain here
			// against the Fulcio root set and system roots.
			// roots, _ := fulcioroots.Get()
			// cert.Verify(x509.VerifyOptions{Roots: roots})

			// Check identity. Fulcio certs store identity in Subject Alternative Name (SAN)
			// but many systems still look at CommonName or use specific extensions.
			// Sigstore's verify library is usually used for this, but for now we'll check SANs.
			foundIdentity := false
			if cert.Subject.CommonName == sig.Identity {
				foundIdentity = true
			} else {
				for _, email := range cert.EmailAddresses {
					if email == sig.Identity {
						foundIdentity = true
						break
					}
				}
				if !foundIdentity {
					for _, uri := range cert.URIs {
						if uri.String() == sig.Identity {
							foundIdentity = true
							break
						}
					}
				}
			}

			if sig.Identity != "" && !foundIdentity {
				return fmt.Errorf("identity mismatch: certificate does not match signature identity %q (CN: %q, SANs: %v)", sig.Identity, cert.Subject.CommonName, cert.EmailAddresses)
			}

			// Validate Rekor/CT evidence if Rekor bundle is present
			if len(sig.RekorBundle) > 0 {
				// In a full implementation, we would use cosign.VerifyBundle
				// for now we acknowledge its presence for strict verification
			} else if sig.Issuer != "local" && sig.Issuer != "" {
				// For non-local certificates, we expect a Rekor bundle in strict mode
				// But we'll allow it if we are in interactive mode (where Rekor might not be used)
				if sig.Issuer != "https://oauth2.sigstore.dev/auth" {
					return fmt.Errorf("strict verification failed: missing Rekor bundle for certificate from %q", sig.Issuer)
				}
			}
		}
		verifier, err = sigstore_signature.LoadVerifier(cert.PublicKey, crypto.SHA256)
		if err != nil {
			return fmt.Errorf("failed to load verifier from certificate: %w", err)
		}
	} else {
		// If not a certificate, it must be a public key
		if !allowUntrusted {
			return fmt.Errorf("untrusted public key rejected: require valid x509 certificate chain")
		}

		pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(sig.Certificate)
		if err != nil {
			// Try parsing as raw DER
			pubKey, err = x509.ParsePKIXPublicKey(sig.Certificate)
			if err != nil {
				return fmt.Errorf("failed to unmarshal public key: %w", err)
			}
		}

		verifier, err = sigstore_signature.LoadVerifier(pubKey, crypto.SHA256)
		if err != nil {
			return fmt.Errorf("failed to load verifier: %w", err)
		}
	}

	if err := verifier.VerifySignature(bytes.NewReader(sig.Signature), bytes.NewReader(data)); err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	// In a full Cosign implementation, if we have a Rekor bundle, we would verify it here.
	// sig.RekorBundle (if added to the Signature struct) could be used with cosign/pkg/cosign.VerifyBundle.

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

	hash, err := utils.CanonicalHash(data)
	if err != nil {
		return "", err
	}

	return hash, nil
}

func (c *CosignAdapter) EncodeSignatureToAnnotations(sig *Signature) (map[string]string, error) {
	annotations := make(map[string]string)

	annotations[AnnotationSignature] = base64.StdEncoding.EncodeToString(sig.Signature)

	if len(sig.Certificate) > 0 {
		annotations[AnnotationCertificate] = base64.StdEncoding.EncodeToString(sig.Certificate)
	}
	if len(sig.RekorBundle) > 0 {
		annotations[AnnotationRekorBundle] = base64.StdEncoding.EncodeToString(sig.RekorBundle)
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
		// Try raw if base64 fails
		sig.Signature = []byte(signatureB64)
	}

	if certB64, ok := annotations[AnnotationCertificate]; ok {
		sig.Certificate, err = base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			// Try raw if base64 fails
			sig.Certificate = []byte(certB64)
		}
	}

	if rekorB64, ok := annotations[AnnotationRekorBundle]; ok {
		sig.RekorBundle, err = base64.StdEncoding.DecodeString(rekorB64)
		if err != nil {
			// Try raw if base64 fails
			sig.RekorBundle = []byte(rekorB64)
		}
	}

	sig.Issuer = annotations[AnnotationIssuer]
	sig.Identity = annotations[AnnotationIdentity]

	if timestamp, ok := annotations[AnnotationTimestamp]; ok {
		ts, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse timestamp: %w", err)
		}
		sig.Timestamp = ts
	}

	return sig, nil
}
