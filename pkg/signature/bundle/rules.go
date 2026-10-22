//go:build experimental_signing

package bundle

import (
	"encoding/json"
	"errors"
	"fmt"

	rulemanagertypesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
)

// RuleClass declares the blast radius of a signed Rules fragment: a base
// fragment contributes detection rules to every workload, an overlay fragment
// only to the workloads bound to its BUNDLE.
//
// Rule fragments are labelled exactly like ContainerProfile fragments —
// LabelBundle + LabelFragmentClass — because the two are the halves of one
// vendor-shipped bundle: the base-class ContainerProfile fragments describe the
// expected behaviour, the overlay-class Rules fragment ships the detections that
// go with them. A workload opts into the bundle with the pod label
// kubescape.io/user-defined-profile, and BOTH halves follow that opt-in.
type RuleClass string

const (
	// RuleClassBase is the baseline ruleset (default-rules), applying
	// cluster-wide. It belongs to no bundle.
	RuleClassBase RuleClass = "base"
	// RuleClassOverlay is a vendor-shipped rule overlay. It applies to exactly
	// the workloads bound to its bundle — in ANY namespace — overriding the base
	// rule with the same ID for them. Bundle membership is SIGNED (it lives in
	// metadata.labels), so an installer cannot re-target an overlay at another
	// bundle; metadata.namespace is not signed and plays no part in scoping,
	// because a vendor cannot know the customer's namespaces.
	RuleClassOverlay RuleClass = "overlay"
)

// Rule-fragment admissibility failure sentinels. They complement the
// ContainerProfile fragment sentinels in verify.go and deliberately reuse
// ErrFragmentUnsigned / ErrFragmentTampered / ErrSignerNotTrusted / ErrNoClass
// so callers can treat both fragment kinds uniformly.
var (
	ErrRuleClassNotAllowed = errors.New("rule class not present in trust policy")
	ErrRuleIDNotAllowed    = errors.New("rule ID not permitted for this rule class")
	ErrRuleBundleRequired  = errors.New("overlay rule fragment has no bundle label")
)

// RuleClassPolicy is the admissibility rule for one rule class: which signer
// identities may author it and which rule IDs it may carry.
type RuleClassPolicy struct {
	Signers        []string `json:"signers"`
	AllowedRuleIDs []string `json:"allowedRuleIDs"`
}

func (p RuleClassPolicy) allowsSigner(id string) bool {
	for _, s := range p.Signers {
		if s == id {
			return true
		}
	}
	return false
}

// allowsRuleID reports whether the class may carry the given rule ID. The
// wildcard entry "*" admits any ID.
func (p RuleClassPolicy) allowsRuleID(id string) bool {
	for _, s := range p.AllowedRuleIDs {
		if s == id || s == "*" {
			return true
		}
	}
	return false
}

// VerifiedRules is the admitted view of a signed Rules object. Every field is
// derived from the VERIFIED content, never from the stored carrier object.
type VerifiedRules struct {
	Rules  []rulemanagertypesv1.Rule
	Class  RuleClass
	Signer string
	// Bundle is the VERIFIED bundle this fragment belongs to, read from the
	// signed metadata.labels. Empty for a base fragment (the cluster baseline
	// belongs to no bundle), mandatory for an overlay.
	Bundle      string
	ClusterWide bool // true iff Class == RuleClassBase
}

// rulesEmbeddedView is the canonical signed content layout produced by the
// Rules adapter's GetContent (profiles.RulesAdapter).
type rulesEmbeddedView struct {
	Metadata struct {
		Name   string            `json:"name"`
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec rulemanagertypesv1.RulesSpec `json:"spec"`
}

// AdmitRulesFragment runs the full admissibility check on one Rules object: it
// must be signed, verify cleanly, declare a class the trust policy knows, be
// signed by a signer that class trusts, and carry only rule IDs that class is
// allowed to ship.
//
// When the object carries embedded signed content (signed with --embed-content),
// the EMBEDDED bytes are the verified source of truth: name, labels (i.e. the
// class AND the bundle) and the rule list all come from them. This is what makes
// bundle scoping sound — an attacker who relabels a validly signed overlay
// cannot re-target it at another bundle, because the bundle the agent acts on is
// the signed one.
func AdmitRulesFragment(r *rulemanagertypesv1.Rules, policy TrustPolicy) (VerifiedRules, error) {
	if r == nil {
		return VerifiedRules{}, fmt.Errorf("nil Rules object")
	}
	adapter := profiles.NewRulesAdapter(r)
	if !signature.IsSigned(adapter) {
		return VerifiedRules{}, fmt.Errorf("%w: %q", ErrFragmentUnsigned, r.Name)
	}
	if err := signature.VerifyObjectAllowUntrusted(adapter); err != nil {
		if errors.Is(err, signature.ErrSignatureMismatch) {
			return VerifiedRules{}, fmt.Errorf("%w: %q: %v", ErrFragmentTampered, r.Name, err)
		}
		return VerifiedRules{}, fmt.Errorf("verify rules fragment %q: %w", r.Name, err)
	}

	// Establish the verified view: embedded content when present, else the
	// stored object.
	name := r.Name
	labels := r.Labels
	rules := r.Spec.Rules
	if embedded, present, embErr := signature.EmbeddedContent(adapter); present {
		if embErr != nil {
			return VerifiedRules{}, fmt.Errorf("embedded content of %q: %w", r.Name, embErr)
		}
		var view rulesEmbeddedView
		if err := json.Unmarshal(embedded, &view); err != nil {
			return VerifiedRules{}, fmt.Errorf("parse embedded content of %q: %w", r.Name, err)
		}
		name = view.Metadata.Name
		labels = view.Metadata.Labels
		rules = view.Spec.Rules
		// metadata.namespace is deliberately absent from the verified view: it is
		// not signed and it no longer scopes anything — bundle membership does.
	}

	class := RuleClass(labels[LabelFragmentClass])
	if class == "" {
		return VerifiedRules{}, fmt.Errorf("%w: %q", ErrNoClass, name)
	}
	rpol, ok := policy.RuleClasses[class]
	if !ok {
		return VerifiedRules{}, fmt.Errorf("%w: class %q (fragment %q)", ErrRuleClassNotAllowed, class, name)
	}

	sig, err := signature.GetObjectSignature(adapter)
	if err != nil {
		return VerifiedRules{}, fmt.Errorf("read signature of %q: %w", name, err)
	}
	signer, err := signerIdentity(sig)
	if err != nil {
		return VerifiedRules{}, fmt.Errorf("signer identity of %q: %w", name, err)
	}
	if !rpol.allowsSigner(signer) {
		return VerifiedRules{}, fmt.Errorf("%w: signer %q, class %q (fragment %q)", ErrSignerNotTrusted, signer, class, name)
	}

	for _, rule := range rules {
		if !rpol.allowsRuleID(rule.ID) {
			return VerifiedRules{}, fmt.Errorf("%w: rule %q, class %q (fragment %q)", ErrRuleIDNotAllowed, rule.ID, class, name)
		}
	}

	// The bundle comes from the VERIFIED labels, never from the carrier object.
	bundleName := labels[LabelBundle]
	if class == RuleClassOverlay && bundleName == "" {
		// An overlay with no bundle would have no way to be scoped and would
		// either apply nowhere or everywhere. Reject it rather than guess.
		return VerifiedRules{}, fmt.Errorf("%w: fragment %q", ErrRuleBundleRequired, name)
	}

	return VerifiedRules{
		Rules:       rules,
		Class:       class,
		Signer:      signer,
		Bundle:      bundleName,
		ClusterWide: class == RuleClassBase,
	}, nil
}

// RulesSignerID returns the trust-policy signer identity of a signed Rules
// object — the signing public-key fingerprint (key:<sha256(PKIX(pub))>).
// Exposed for authoring trust policies and tests.
func RulesSignerID(r *rulemanagertypesv1.Rules) (string, error) {
	sig, err := signature.GetObjectSignature(profiles.NewRulesAdapter(r))
	if err != nil {
		return "", err
	}
	return signerIdentity(sig)
}
