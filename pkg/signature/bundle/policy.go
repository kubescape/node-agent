//go:build experimental_signing

package bundle

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kubescape/node-agent/pkg/signature"
)

// signedTrustPolicyArtifact is the on-disk shape of a root-signed trust policy
// (typically a mounted ConfigMap value). The signature in Annotations is
// computed over the CANONICAL Policy content — not the raw file bytes — so it
// survives ConfigMap string round-trips and JSON re-serialisation.
//
//	{"policy": {"classes": {...}},
//	 "annotations": {"signature.kubescape.io/signature": "...",
//	                 "signature.kubescape.io/certificate": "...", ...}}
type signedTrustPolicyArtifact struct {
	Policy      *TrustPolicy      `json:"policy"`
	Annotations map[string]string `json:"annotations"`
}

// policySignable adapts a TrustPolicy to signature.SignableObject so the exact
// same crypto envelope (SignObject / VerifyObject) that protects CP fragments
// also protects the trust policy.
//
// GetContent returns the *TrustPolicy value (NOT raw file bytes): Sign/Verify
// hash json.Marshal(GetContent()) through utils.CanonicalHash, which is
// order-independent. Because both signing and reloading marshal the SAME
// *TrustPolicy struct type, the canonical hash is identical across a
// sign → serialise → ConfigMap round-trip → reload cycle. Signing raw bytes
// would break the moment whitespace or key order changed.
type policySignable struct {
	policy      *TrustPolicy
	annotations map[string]string
}

func newPolicySignable(policy *TrustPolicy, annotations map[string]string) *policySignable {
	if annotations == nil {
		annotations = make(map[string]string)
	}
	return &policySignable{policy: policy, annotations: annotations}
}

func (p *policySignable) GetAnnotations() map[string]string { return p.annotations }

func (p *policySignable) SetAnnotations(a map[string]string) {
	if a == nil {
		a = make(map[string]string)
	}
	p.annotations = a
}

func (p *policySignable) GetUID() string          { return "" }
func (p *policySignable) GetNamespace() string    { return "" }
func (p *policySignable) GetName() string         { return "trust-policy" }
func (p *policySignable) GetContent() interface{} { return p.policy }
func (p *policySignable) GetUpdatedObject() interface{} {
	return signedTrustPolicyArtifact{Policy: p.policy, Annotations: p.annotations}
}

// SignTrustPolicy signs a TrustPolicy with the offline ROOT private key and
// returns the serialised {policy, annotations} artifact. The signature covers
// the canonical policy content; the resulting artifact is what node-agent loads
// via LoadSignedTrustPolicy and pins to the embedded root fingerprint.
func SignTrustPolicy(policy *TrustPolicy, rootKey *ecdsa.PrivateKey) ([]byte, error) {
	if policy == nil {
		return nil, fmt.Errorf("nil trust policy")
	}
	if rootKey == nil {
		return nil, fmt.Errorf("nil root key")
	}
	it := newPolicySignable(policy, nil)
	if err := signature.SignObject(it, signature.WithPrivateKey(rootKey)); err != nil {
		return nil, fmt.Errorf("sign trust policy: %w", err)
	}
	artifact := signedTrustPolicyArtifact{Policy: policy, Annotations: it.GetAnnotations()}
	out, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal signed trust policy: %w", err)
	}
	return out, nil
}

// parseSignedTrustPolicy verifies and returns a root-signed trust policy from
// its serialised {policy, annotations} bytes. It fails closed on every failure:
//
//  1. The signature must verify over the canonical policy content against the
//     certificate embedded in the annotations (VerifyObjectAllowUntrusted).
//  2. The signer's public-key fingerprint MUST equal the embedded root
//     fingerprint — the pin that stops an attacker re-signing an edited policy
//     with their own key.
//  3. The policy must declare at least one class.
func parseSignedTrustPolicy(data []byte) (*TrustPolicy, error) {
	rootFp, err := rootFingerprint()
	if err != nil {
		return nil, fmt.Errorf("compute embedded root fingerprint: %w", err)
	}
	return verifyAndPinPolicy(data, rootFp)
}

// verifyAndPinPolicy is the crypto core: it verifies the artifact's signature
// over the canonical policy content and pins the signer to expectedRootFp. The
// production path (parseSignedTrustPolicy) always passes the embedded root
// fingerprint; the split lets tests exercise the exact same logic with their own
// generated keypair, so NO private key needs to exist on disk. Fails closed on
// every path.
func verifyAndPinPolicy(data []byte, expectedRootFp string) (*TrustPolicy, error) {
	var artifact signedTrustPolicyArtifact
	if err := json.Unmarshal(data, &artifact); err != nil {
		return nil, fmt.Errorf("parse signed trust policy: %w", err)
	}
	if artifact.Policy == nil {
		return nil, fmt.Errorf("signed trust policy has no policy")
	}
	if len(artifact.Annotations) == 0 {
		return nil, fmt.Errorf("signed trust policy has no signature annotations")
	}

	it := newPolicySignable(artifact.Policy, artifact.Annotations)

	// (1) The signature must verify over the canonical policy content. Any
	// mismatch (including a tampered policy object) fails here.
	if err := signature.VerifyObjectAllowUntrusted(it); err != nil {
		return nil, fmt.Errorf("trust policy signature verification failed: %w", err)
	}

	// (2) Pin the signer to the (embedded) root key.
	sig, err := signature.GetObjectSignature(it)
	if err != nil {
		return nil, fmt.Errorf("trust policy signature verification failed: %w", err)
	}
	signer, err := signerIdentity(sig)
	if err != nil {
		return nil, fmt.Errorf("trust policy signature verification failed: %w", err)
	}
	if signer != expectedRootFp {
		return nil, errors.New("trust policy not signed by the embedded root key")
	}

	// (3) Same minimum-content check as LoadTrustPolicy.
	if len(artifact.Policy.Classes) == 0 {
		return nil, fmt.Errorf("trust policy has no classes")
	}

	return artifact.Policy, nil
}
