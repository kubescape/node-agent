//go:build experimental_signing

// Package bundle implements signed ContainerProfile fragment bundles: multiple
// independently signed partial ContainerProfiles ("fragments"), authored by
// different parties, verified per-leaf against a trust policy, deterministically
// assembled into one effective ContainerProfile, and bound to the exact set of
// admissible leaves via a Merkle leaf-tree. node-agent then re-signs the
// composite internally so the R1016 tamper path protects it.
//
// This is the multi-file overlay layer on top of the flat single-signed-CP
// support in pkg/signature + containerprofilecache/tamper_alert.go.
package bundle

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"reflect"

	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// FragmentClass declares what a fragment is allowed to contribute and who may
// sign it. Precedence (base < admission < overlay) also fixes assembly order so
// higher-precedence fragments win scalar conflicts deterministically.
type FragmentClass string

const (
	ClassBase      FragmentClass = "base"
	ClassAdmission FragmentClass = "admission"
	ClassOverlay   FragmentClass = "overlay"
)

// classPrecedence orders fragments in the composite. Unknown classes sort last.
func classPrecedence(c FragmentClass) int {
	switch c {
	case ClassBase:
		return 0
	case ClassAdmission:
		return 1
	case ClassOverlay:
		return 2
	default:
		return 3
	}
}

// Labels a fragment ContainerProfile carries.
const (
	// LabelBundle groups fragments that assemble into one effective profile.
	LabelBundle = "signature.kubescape.io/bundle"
	// LabelFragmentClass declares the fragment's class (base|admission|overlay).
	LabelFragmentClass = "signature.kubescape.io/fragment-class"
	// LabelVersion is the fragment's monotonic version within its
	// (bundle, class, name) slot. It is part of the signed labels, so it cannot
	// be forged. A vendor increments it when shipping a replacement; node-agent
	// refuses a fragment whose version is below the highest already accepted for
	// that slot, which blocks replay of an older validly-signed fragment. Absent
	// is treated as version 0 (back-compatible with unversioned fragments).
	LabelVersion = "signature.kubescape.io/version"
)

// ManifestAnnotation carries the serialized BundleManifest on the composite.
const ManifestAnnotation = "signature.kubescape.io/bundle-manifest"

// ClassPolicy is the admissibility rule for one fragment class: which signer
// identities may author it and which spec paths it may set.
type ClassPolicy struct {
	Signers          []string `json:"signers"`
	AllowedSpecPaths []string `json:"allowedSpecPaths"`
}

func (p ClassPolicy) allowsSigner(id string) bool {
	for _, s := range p.Signers {
		if s == id {
			return true
		}
	}
	return false
}

func (p ClassPolicy) allowsPath(path string) bool {
	for _, s := range p.AllowedSpecPaths {
		if s == path || s == "*" {
			return true
		}
	}
	return false
}

// TrustPolicy maps each fragment class to its admissibility rule.
//
// Classes governs signed ContainerProfile fragments; RuleClasses governs signed
// Rules fragments (see rules.go). The two are independent: a policy with no
// ruleClasses leaves rule signing DISABLED, which is the back-compatible
// default for deployments that only use profile bundles.
type TrustPolicy struct {
	Mode           SigningMode                          `json:"mode,omitempty"`
	Classes        map[FragmentClass]ClassPolicy        `json:"classes"`
	RuleClasses    map[RuleClass]RuleClassPolicy        `json:"ruleClasses,omitempty"`
	BindingClasses map[FragmentClass]BindingClassPolicy `json:"bindingClasses,omitempty"`
	// PolicyVersion is a monotonic counter inside the signed content: a reload
	// carrying a lower version than the policy in force is a rollback replay
	// and is refused. Absent means 0 (back-compatible).
	PolicyVersion int64 `json:"policyVersion,omitempty"`
}

// SigningMode is the single global signing state. OFF is the absence of a
// mounted policy; a mounted policy is ON and is at least alerting. enforce
// refuses unsigned/unverifiable artifacts; alert loads them but logs loudly.
type SigningMode string

const (
	ModeAlert   SigningMode = "alert"
	ModeEnforce SigningMode = "enforce"
)

// EffectiveMode resolves the mode a mounted policy runs in. A mounted policy
// with no explicit mode defaults to alert, never to silent — enforce must be
// asked for, so an operator cannot brick a cluster by omission.
func (p TrustPolicy) EffectiveMode() SigningMode {
	if p.Mode == ModeEnforce {
		return ModeEnforce
	}
	return ModeAlert
}

func (p TrustPolicy) Enforcing() bool { return p.EffectiveMode() == ModeEnforce }

// RuleSigningEnabled reports whether the policy governs signed Rules fragments.
// Absent ruleClasses means rule signing is off and the rules watcher keeps its
// pre-signing behaviour.
func (p TrustPolicy) RuleSigningEnabled() bool { return len(p.RuleClasses) > 0 }

func (p TrustPolicy) BindingSigningEnabled() bool { return len(p.BindingClasses) > 0 }

// LeafRef is one verified fragment's entry in the bundle manifest.
type LeafRef struct {
	Class         FragmentClass `json:"class"`
	Signer        string        `json:"signer"`
	Name          string        `json:"name"`
	ContentDigest string        `json:"contentDigest"` // hex sha256 of the signed content
	Version       int64         `json:"version"`       // monotonic version from the signed labels
}

// BundleManifest is committed to by the composite: it lists the admissible
// leaves and the Merkle root binding them, so any verifier can independently
// re-verify each leaf and confirm the composite derives from exactly this set.
type BundleManifest struct {
	Root   string    `json:"root"` // hex Merkle root over the leaves in manifest order
	Leaves []LeafRef `json:"leaves"`
}

// signerIdentity returns a stable identity for whoever signed the fragment: a
// SHA-256 fingerprint of the signing public key extracted from the embedded
// certificate.
//
// SECURITY: the identity is derived ONLY from the public key that the signature
// was actually verified against. The OIDC identity/issuer annotations are NOT
// used — verification runs allow-untrusted (no Fulcio chain / SAN attestation),
// so those annotations are attacker-controlled plaintext and trusting them would
// let anyone spoof a trusted signer by stamping two strings. Binding trust to the
// verified public key is the only sound choice in this trust model; keyless/OIDC
// signers would require strict (Fulcio-attested) verification, which this path
// deliberately does not do.
func signerIdentity(sig *signature.Signature) (string, error) {
	if sig == nil {
		return "", fmt.Errorf("nil signature")
	}
	if len(sig.Certificate) == 0 {
		return "", fmt.Errorf("signature has no certificate to fingerprint")
	}
	block, _ := pem.Decode(sig.Certificate)
	if block == nil {
		return "", fmt.Errorf("failed to PEM-decode certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}
	pub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	sum := sha256.Sum256(pub)
	return "key:" + hex.EncodeToString(sum[:]), nil
}

// SignerID returns the trust-policy signer identity of a signed fragment — the
// signing public-key fingerprint (key:<sha256(PKIX(pub))>). Exposed for
// authoring trust policies (which list allowed signer IDs per class) and tests.
func SignerID(cp *v1beta1.ContainerProfile) (string, error) {
	sig, err := signature.GetObjectSignature(profiles.NewContainerProfileAdapter(cp))
	if err != nil {
		return "", err
	}
	return signerIdentity(sig)
}

// contentDigest returns the hex SHA-256 of the fragment's canonical signed
// content — the same content the signature covers (metadata{name,namespace,
// labels} + spec, annotations excluded), so a leaf's digest is exactly what its
// author signed.
func contentDigest(cp *v1beta1.ContainerProfile) (string, error) {
	adapter := profiles.NewContainerProfileAdapter(cp)
	h, err := signature.HashSignableContent(adapter)
	if err != nil {
		return "", err
	}
	return h, nil
}

// setSpecPaths returns the sorted set of spec paths a fragment actually sets
// (non-zero fields), used to enforce class confinement (an admission fragment
// may only set ingress/egress, etc.).
func setSpecPaths(spec *v1beta1.ContainerProfileSpec) []string {
	var paths []string
	if len(spec.Architectures) > 0 {
		paths = append(paths, "architectures")
	}
	if len(spec.Capabilities) > 0 {
		paths = append(paths, "capabilities")
	}
	if len(spec.Execs) > 0 {
		paths = append(paths, "execs")
	}
	if len(spec.Opens) > 0 {
		paths = append(paths, "opens")
	}
	if len(spec.Syscalls) > 0 {
		paths = append(paths, "syscalls")
	}
	if !reflect.DeepEqual(spec.SeccompProfile, v1beta1.SingleSeccompProfile{}) {
		// Any non-zero seccomp content confines to the class — not just
		// DefaultAction (Syscalls/Architectures/ListenerPath/etc. also count),
		// else an admission fragment could smuggle seccomp settings past the
		// class check by leaving DefaultAction empty.
		paths = append(paths, "seccompProfile")
	}
	if len(spec.Endpoints) > 0 {
		paths = append(paths, "endpoints")
	}
	if spec.ImageID != "" {
		paths = append(paths, "imageID")
	}
	if spec.ImageTag != "" {
		paths = append(paths, "imageTag")
	}
	if len(spec.PolicyByRuleId) > 0 {
		paths = append(paths, "rulePolicies")
	}
	if len(spec.IdentifiedCallStacks) > 0 {
		paths = append(paths, "identifiedCallStacks")
	}
	if len(spec.MatchLabels) > 0 || len(spec.MatchExpressions) > 0 {
		paths = append(paths, "labelSelector")
	}
	if len(spec.Ingress) > 0 {
		paths = append(paths, "ingress")
	}
	if len(spec.Egress) > 0 {
		paths = append(paths, "egress")
	}
	return paths
}
