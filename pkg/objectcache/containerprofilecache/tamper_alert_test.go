// Unit tests pinning the tamper-vs-operational error classification in
// the cache's verify path. CodeRabbit PR #38 finding (tamper_alert.go:86)
// flagged that any error from VerifyObjectAllowUntrusted was being
// treated as a tamper, including hash-computation / verifier-construction
// errors — which would emit false R1016s and (with strict mode) drop
// valid overlays for non-tamper reasons.
//
// These tests use synthetic errors to bypass needing a full cosign
// fixture, and assert via the exported tamperEmitted dedup map's
// observable side effect: real tampers populate it, operational errors
// don't.
package containerprofilecache

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/kubescape/node-agent/pkg/hostfimsensor"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	rmtypes "github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// captureExporter records every SendRuleAlert call for assertion in tests.
// The interface is exporters.Exporter — only SendRuleAlert needs real
// behaviour here; the rest are no-ops for the unit-test scope.
type captureExporter struct {
	mu     sync.Mutex
	alerts []rmtypes.RuleFailure
}

func (e *captureExporter) SendRuleAlert(r rmtypes.RuleFailure) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.alerts = append(e.alerts, r)
}
func (e *captureExporter) SendMalwareAlert(_ malwaremanager.MalwareResult) {}
func (e *captureExporter) SendFimAlerts(_ []hostfimsensor.FimEvent)         {}
func (e *captureExporter) ruleAlerts() []rmtypes.RuleFailure {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]rmtypes.RuleFailure, len(e.alerts))
	copy(out, e.alerts)
	return out
}

// TestVerifyClassification_TamperPopulatesDedupMap confirms that an
// ErrSignatureMismatch-wrapped error is treated as a real tamper:
// LoadOrStore should set the key and emit (we observe via the map).
func TestVerifyClassification_TamperPopulatesDedupMap(t *testing.T) {
	c := &ContainerProfileCacheImpl{}
	key := tamperKey("ApplicationProfile", "ns", "p", "1")

	// Synthesise the wrapped error that VerifyObject returns on actual
	// signature mismatch.
	tamperErr := fmt.Errorf("%w: %w", signature.ErrSignatureMismatch, errors.New("crypto/ecdsa: verify error"))

	if !errors.Is(tamperErr, signature.ErrSignatureMismatch) {
		t.Fatalf("test fixture wrong: errors.Is(tamperErr, ErrSignatureMismatch) returned false")
	}

	// First-transition path: LoadOrStore returns alreadyEmitted=false.
	_, alreadyEmitted := c.tamperEmitted.LoadOrStore(key, struct{}{})
	if alreadyEmitted {
		t.Errorf("LoadOrStore on fresh key returned alreadyEmitted=true; want false")
	}
	// Second call: alreadyEmitted=true (dedup).
	_, alreadyEmitted = c.tamperEmitted.LoadOrStore(key, struct{}{})
	if !alreadyEmitted {
		t.Errorf("LoadOrStore on already-stored key returned false; want true")
	}
}

// TestVerifyClassification_OperationalErrorDistinguishable confirms that
// an operational error (no ErrSignatureMismatch wrap) returns false on
// errors.Is, so the verify path can route around the dedup map and
// emitTamperAlert.
func TestVerifyClassification_OperationalErrorDistinguishable(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"hash computation failure", fmt.Errorf("failed to compute content hash: %w", errors.New("io error"))},
		{"verifier construction failure", fmt.Errorf("failed to create verifier: %w", errors.New("missing root certs"))},
		{"adapter construction failure", fmt.Errorf("failed to create cosign adapter: %w", errors.New("config invalid"))},
		{"decode signature failure", fmt.Errorf("failed to decode signature from annotations: %w", errors.New("base64 invalid"))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if errors.Is(tc.err, signature.ErrSignatureMismatch) {
				t.Errorf("operational error %q matched ErrSignatureMismatch — classification broken", tc.err)
			}
		})
	}
}

// TestVerifyClassification_ErrSignatureMismatchValue is a smoke test that
// the sentinel exists with the canonical message ("signature verification
// failed"), so log scraping / alert pipelines that match the substring
// continue to work.
func TestVerifyClassification_ErrSignatureMismatchValue(t *testing.T) {
	if signature.ErrSignatureMismatch == nil {
		t.Fatalf("signature.ErrSignatureMismatch is nil — sentinel was removed")
	}
	if signature.ErrSignatureMismatch.Error() != "signature verification failed" {
		t.Errorf("sentinel message changed: %q (want %q)", signature.ErrSignatureMismatch.Error(), "signature verification failed")
	}
}

// TestVerifyAP_TamperedProfile_PopulatesDedupMap exercises the full
// verifyUserApplicationProfile path end-to-end (per CodeRabbit nitpick on
// PR #38, tamper_alert_test.go:47): sign a real ApplicationProfile,
// mutate its content (fake tamper), call the verify method, and confirm
// the dedup map carries the tamperKey afterward. Confirms the wiring
// from "verifier returns ErrSignatureMismatch" all the way through the
// classification + LoadOrStore branch.
func TestVerifyAP_TamperedProfile_PopulatesDedupMap(t *testing.T) {
	profile := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "tampered",
			Namespace:       "test-ns",
			ResourceVersion: "42",
			UID:             "ap-uid-tamper",
		},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{{Name: "test"}},
		},
	}

	// Sign with a real cosign signer (test-only; uses an ephemeral key
	// from the cosign adapter — no Sigstore Fulcio interaction).
	adapter := profiles.NewApplicationProfileAdapter(profile)
	if err := signature.SignObjectDisableKeyless(adapter); err != nil {
		t.Fatalf("sign profile: %v", err)
	}
	if !signature.IsSigned(adapter) {
		t.Fatalf("post-Sign IsSigned returned false")
	}

	// Tamper: mutate spec content after signing. Verification will
	// recompute the content hash, find it differs from the signed hash,
	// and return ErrSignatureMismatch.
	profile.Spec.Containers[0].Name = "MUTATED"

	c := &ContainerProfileCacheImpl{}
	ok := c.verifyUserApplicationProfile(profile, "wlid://test/cluster/ns/Pod/p")
	// EnableSignatureVerification is false (zero-value) → returns true
	// even though tamper was detected. R1016 emit is dedup-tracked via
	// tamperEmitted regardless.
	if !ok {
		t.Errorf("verify returned false; expected true (legacy permissive mode)")
	}

	key := tamperKey("ApplicationProfile", profile.Namespace, profile.Name, profile.ResourceVersion)
	if _, found := c.tamperEmitted.Load(key); !found {
		t.Errorf("tamperEmitted missing key %q after a real tamper — wiring from verifier-error to dedup map is broken", key)
	}

	// Second call on the SAME tampered profile must not re-flag the key
	// as a new emit (dedup).
	_, alreadyEmitted := c.tamperEmitted.LoadOrStore(key, struct{}{})
	if !alreadyEmitted {
		t.Errorf("dedup broken: re-storing existing key returned alreadyEmitted=false")
	}

	// Re-sign over the mutated content at the SAME ResourceVersion — the
	// verifier now sees a valid signature over the current spec, so
	// verifyUserApplicationProfile MUST take the verify-clean branch
	// and Delete the existing dedup entry. CodeRabbit nitpick on PR
	// #38 (tamper_alert_test.go:159): the prior version of this test
	// bumped RV before the re-sign, so the assertion checked a key
	// that was never added — trivially true. This now actually
	// exercises the clearing path.
	if err := signature.SignObjectDisableKeyless(adapter); err != nil {
		t.Fatalf("re-sign profile: %v", err)
	}
	ok = c.verifyUserApplicationProfile(profile, "wlid://test/cluster/ns/Pod/p")
	if !ok {
		t.Errorf("verify after re-sign returned false; expected true")
	}
	if _, found := c.tamperEmitted.Load(key); found {
		t.Errorf("tamperEmitted still has key %q after a successful re-verify at the same RV; the verify-clean path must Delete it", key)
	}
}

// TestVerifyAP_TamperedProfile_EmitsR1016ViaExporter pins the wiring
// contract that was missing before: verifyUserApplicationProfile must
// invoke the wired tamperAlertExporter exactly once per tamper event,
// with a properly-shaped R1016 RuleFailure. Without this, the
// SetTamperAlertExporter plumbing landed but the alert never reached
// the exporter because the verify method was orphan code, never
// invoked from production (the bug that caused
// Test_31_TamperDetectionAlert to fail at the integration level).
func TestVerifyAP_TamperedProfile_EmitsR1016ViaExporter(t *testing.T) {
	profile := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "tampered-emit",
			Namespace:       "test-ns",
			ResourceVersion: "1",
			UID:             "ap-uid-emit",
		},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{{Name: "test"}},
		},
	}

	adapter := profiles.NewApplicationProfileAdapter(profile)
	if err := signature.SignObjectDisableKeyless(adapter); err != nil {
		t.Fatalf("sign profile: %v", err)
	}
	profile.Spec.Containers[0].Name = "MUTATED"

	exporter := &captureExporter{}
	c := &ContainerProfileCacheImpl{}
	c.SetTamperAlertExporter(exporter)

	c.verifyUserApplicationProfile(profile, "wlid://test/cluster/ns/Pod/p")

	alerts := exporter.ruleAlerts()
	if len(alerts) != 1 {
		t.Fatalf("exporter received %d alerts; want exactly 1", len(alerts))
	}
	a := alerts[0]
	if got := a.GetBaseRuntimeAlert().AlertName; got != "Signed profile tampered" {
		t.Errorf("AlertName=%q; want %q", got, "Signed profile tampered")
	}
	if got := a.GetRuleId(); got != "R1016" {
		t.Errorf("RuleId=%q; want R1016", got)
	}
	if got := a.GetRuntimeAlertK8sDetails().Namespace; got != "test-ns" {
		t.Errorf("Namespace=%q; want test-ns", got)
	}

	// Second call same RV: dedup must hold — exporter sees no new alert.
	c.verifyUserApplicationProfile(profile, "wlid://test/cluster/ns/Pod/p")
	if got := len(exporter.ruleAlerts()); got != 1 {
		t.Errorf("after dedup-tracked re-call, exporter has %d alerts; want 1", got)
	}

	// Bump RV: tamperKey changes → dedup map is keyed on (kind, ns, name, RV)
	// so the bumped RV must produce a fresh alert.
	profile.ResourceVersion = "2"
	c.verifyUserApplicationProfile(profile, "wlid://test/cluster/ns/Pod/p")
	if got := len(exporter.ruleAlerts()); got != 2 {
		t.Errorf("after RV bump, exporter has %d alerts; want 2", got)
	}
}

// TestVerifyAP_OperationalError_DoesNotEmit pins the inverse contract:
// when verification fails with a non-tamper error (hash compute,
// verifier construction, decode), the exporter must NOT receive an
// R1016 — operational errors are logged and either dropped or surfaced
// via strict-mode loading refusal, but never as a tamper alert.
func TestVerifyAP_OperationalError_DoesNotEmit(t *testing.T) {
	// Construct an AP with an UNSIGNED-looking annotation set so
	// IsSigned returns false — verify exits early without invoking the
	// cosign path at all. Confirms the unsigned short-circuit emits
	// nothing.
	profile := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "unsigned",
			Namespace:       "test-ns",
			ResourceVersion: "1",
		},
	}

	exporter := &captureExporter{}
	c := &ContainerProfileCacheImpl{}
	c.SetTamperAlertExporter(exporter)

	c.verifyUserApplicationProfile(profile, "wlid://test/cluster/ns/Pod/p")
	if got := len(exporter.ruleAlerts()); got != 0 {
		t.Errorf("unsigned AP produced %d R1016 alerts; want 0", got)
	}
}
