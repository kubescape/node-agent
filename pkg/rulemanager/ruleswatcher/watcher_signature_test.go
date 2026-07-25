package ruleswatcher

import (
	"errors"
	"testing"

	"github.com/kubescape/node-agent/pkg/config"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// unsignedRules builds a minimal Rules resource with no signature annotation.
func unsignedRules() *typesv1.Rules {
	return &typesv1.Rules{
		ObjectMeta: metav1.ObjectMeta{Name: "test-rules", Namespace: "default"},
		Spec: typesv1.RulesSpec{
			Rules: []typesv1.Rule{{Enabled: true, ID: "rule-1", Name: "Test Rule"}},
		},
	}
}

// TestVerifyRules_DisabledIsNoOp pins that rule-signature verification is off
// by default: with a nil config or EnableSignatureVerification=false, an
// unsigned Rules resource is admitted unchanged.
func TestVerifyRules_DisabledIsNoOp(t *testing.T) {
	w := &RulesWatcherImpl{} // nil cfg — verification can't be enabled
	if err := w.verifyRules(unsignedRules()); err != nil {
		t.Fatalf("nil cfg must be a no-op, got %v", err)
	}

	w = &RulesWatcherImpl{cfg: &config.Config{EnableSignatureVerification: false}}
	if err := w.verifyRules(unsignedRules()); err != nil {
		t.Fatalf("verification disabled must be a no-op, got %v", err)
	}
}

// TestVerifyRules_EnabledRejectsUnsigned pins that, once verification is
// enabled, an unsigned Rules resource is rejected (ErrObjectNotSigned) so the
// watcher skips it rather than admitting unverified rules.
func TestVerifyRules_EnabledRejectsUnsigned(t *testing.T) {
	w := &RulesWatcherImpl{cfg: &config.Config{EnableSignatureVerification: true}}
	err := w.verifyRules(unsignedRules())
	if err == nil {
		t.Fatal("verification enabled must reject an unsigned rules resource")
	}
	if !errors.Is(err, signature.ErrObjectNotSigned) {
		t.Fatalf("expected ErrObjectNotSigned, got %v", err)
	}
}

// TestVerifyRules_EnabledAcceptsSigned pins the round-trip: a Rules resource
// signed with a local (non-keyless) key must verify when verification is
// enabled. Rules are signed by the operator's local key, so verifyRules uses
// AllowUntrusted — strict verification would reject every adapter-signed rule.
func TestVerifyRules_EnabledAcceptsSigned(t *testing.T) {
	rules := unsignedRules()
	if err := signature.SignObjectDisableKeyless(profiles.NewRulesAdapter(rules)); err != nil {
		t.Fatalf("failed to sign rules: %v", err)
	}
	w := &RulesWatcherImpl{cfg: &config.Config{EnableSignatureVerification: true}}
	if err := w.verifyRules(rules); err != nil {
		t.Fatalf("a validly-signed rules resource must be accepted, got %v", err)
	}
}
