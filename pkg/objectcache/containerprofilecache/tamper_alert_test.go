//go:build experimental_signing

// Unit tests for the ContainerProfile tamper-detection path. Ported from the
// legacy AP/NN tamper tests (fix/sign-object-release-v0.0.3) to the single
// verifyUserContainerProfile method. They pin: the tamper-vs-operational error
// classification, the R1016 emit + dedup wiring, and strict-mode drop.
package containerprofilecache

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/hostfimsensor"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	rmtypes "github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// captureExporter records every SendRuleAlert call for assertion in tests.
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
func (e *captureExporter) SendFimAlerts(_ []hostfimsensor.FimEvent)        {}
func (e *captureExporter) ruleAlerts() []rmtypes.RuleFailure {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]rmtypes.RuleFailure, len(e.alerts))
	copy(out, e.alerts)
	return out
}

func signedCP(name, ns, rv string) *v1beta1.ContainerProfile {
	return &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       ns,
			ResourceVersion: rv,
			UID:             types.UID("cp-uid-" + name),
		},
		Spec: v1beta1.ContainerProfileSpec{
			Architectures: []string{"amd64"},
			Execs:         []v1beta1.ExecCalls{{Path: "/bin/sh", Args: []string{"/bin/sh"}}},
		},
	}
}

// TestVerifyClassification_ErrSignatureMismatchValue is a smoke test that the
// sentinel exists with its canonical message, so log/alert pipelines matching
// the substring keep working.
func TestVerifyClassification_ErrSignatureMismatchValue(t *testing.T) {
	if signature.ErrSignatureMismatch == nil {
		t.Fatalf("signature.ErrSignatureMismatch is nil — sentinel was removed")
	}
	if signature.ErrSignatureMismatch.Error() != "signature verification failed" {
		t.Errorf("sentinel message changed: %q", signature.ErrSignatureMismatch.Error())
	}
}

// TestVerifyClassification_OperationalErrorDistinguishable confirms operational
// errors do NOT match ErrSignatureMismatch, so the verify path routes around
// the dedup map + emit.
func TestVerifyClassification_OperationalErrorDistinguishable(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"hash computation failure", fmt.Errorf("failed to compute content hash: %w", errors.New("io error"))},
		{"verifier construction failure", fmt.Errorf("failed to create verifier: %w", errors.New("missing root certs"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if errors.Is(tc.err, signature.ErrSignatureMismatch) {
				t.Errorf("operational error %q matched ErrSignatureMismatch", tc.err)
			}
		})
	}
}

// TestVerifyCP_Unsigned_ReturnsTrue: signing is opt-in; an unsigned CP passes
// without alerting.
func TestVerifyCP_Unsigned_ReturnsTrue(t *testing.T) {
	profile := signedCP("unsigned", "ns", "1")
	exporter := &captureExporter{}
	c := &ContainerProfileCacheImpl{}
	c.SetTamperAlertExporter(exporter)
	if !c.verifyUserContainerProfile(profile, "wlid://test/cluster/ns/Pod/p") {
		t.Errorf("unsigned CP returned false; want true")
	}
	if got := len(exporter.ruleAlerts()); got != 0 {
		t.Errorf("unsigned CP emitted %d alerts; want 0", got)
	}
}

// TestVerifyCP_TamperedProfile_PopulatesDedupMap: sign a real CP, mutate its
// spec, verify → dedup map carries the key; re-sign at the same RV clears it.
func TestVerifyCP_TamperedProfile_PopulatesDedupMap(t *testing.T) {
	profile := signedCP("tampered", "test-ns", "42")
	adapter := profiles.NewContainerProfileAdapter(profile)
	if err := signature.SignObjectDisableKeyless(adapter); err != nil {
		t.Fatalf("sign profile: %v", err)
	}
	if !signature.IsSigned(adapter) {
		t.Fatalf("post-Sign IsSigned returned false")
	}

	// Tamper: mutate spec content after signing.
	profile.Spec.Execs[0].Path = "/bin/evil"

	c := &ContainerProfileCacheImpl{}
	if !c.verifyUserContainerProfile(profile, "wlid://test/cluster/ns/Pod/p") {
		t.Errorf("verify returned false; expected true (permissive mode)")
	}
	key := tamperKey("ContainerProfile", profile.Namespace, profile.Name, profile.ResourceVersion)
	if _, found := c.tamperEmitted.Load(key); !found {
		t.Errorf("tamperEmitted missing key %q after a real tamper", key)
	}

	// Re-sign over the mutated content at the SAME RV → verify-clean branch
	// must Delete the dedup entry.
	if err := signature.SignObjectDisableKeyless(adapter); err != nil {
		t.Fatalf("re-sign profile: %v", err)
	}
	if !c.verifyUserContainerProfile(profile, "wlid://test/cluster/ns/Pod/p") {
		t.Errorf("verify after re-sign returned false; expected true")
	}
	if _, found := c.tamperEmitted.Load(key); found {
		t.Errorf("tamperEmitted still has key %q after successful re-verify; verify-clean path must Delete it", key)
	}
}

// TestVerifyCP_TamperedProfile_EmitsR1016ViaExporter: one R1016 per tamper
// event, deduped per RV, re-alerts on RV bump.
func TestVerifyCP_TamperedProfile_EmitsR1016ViaExporter(t *testing.T) {
	profile := signedCP("tampered-emit", "test-ns", "1")
	adapter := profiles.NewContainerProfileAdapter(profile)
	if err := signature.SignObjectDisableKeyless(adapter); err != nil {
		t.Fatalf("sign profile: %v", err)
	}
	profile.Spec.Execs[0].Path = "/bin/evil"

	exporter := &captureExporter{}
	c := &ContainerProfileCacheImpl{}
	c.SetTamperAlertExporter(exporter)

	c.verifyUserContainerProfile(profile, "wlid://test/cluster/ns/Pod/p")
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

	// Same RV: dedup holds.
	c.verifyUserContainerProfile(profile, "wlid://test/cluster/ns/Pod/p")
	if got := len(exporter.ruleAlerts()); got != 1 {
		t.Errorf("after dedup re-call, exporter has %d alerts; want 1", got)
	}

	// Bump RV → fresh alert.
	profile.ResourceVersion = "2"
	c.verifyUserContainerProfile(profile, "wlid://test/cluster/ns/Pod/p")
	if got := len(exporter.ruleAlerts()); got != 2 {
		t.Errorf("after RV bump, exporter has %d alerts; want 2", got)
	}
}

// TestVerifyCP_StrictMode_ReturnsFalseOnTamper: with EnableSignatureVerification
// the caller must drop a tampered overlay (verify returns false).
func TestVerifyCP_StrictMode_ReturnsFalseOnTamper(t *testing.T) {
	profile := signedCP("tampered-strict", "test-ns", "7")
	adapter := profiles.NewContainerProfileAdapter(profile)
	if err := signature.SignObjectDisableKeyless(adapter); err != nil {
		t.Fatalf("sign profile: %v", err)
	}
	profile.Spec.Execs[0].Path = "/bin/evil"

	c := &ContainerProfileCacheImpl{cfg: config.Config{EnableSignatureVerification: true}}
	if c.verifyUserContainerProfile(profile, "wlid://test/cluster/ns/Pod/p") {
		t.Errorf("strict mode returned true on tamper; want false (drop the overlay)")
	}
}

func TestVerifyCP_StrictMode_RefusesUnsignedUserProfile(t *testing.T) {
	profile := signedCP("unsigned-strict", "test-ns", "11")
	profile.Annotations = map[string]string{}

	c := &ContainerProfileCacheImpl{cfg: config.Config{EnableSignatureVerification: true}}
	if c.verifyUserContainerProfile(profile, "wlid://test/cluster/ns/Pod/p") {
		t.Error("strict mode must refuse an unsigned user-defined profile")
	}
}

func TestVerifyCP_PermissiveMode_AcceptsUnsignedUserProfile(t *testing.T) {
	profile := signedCP("unsigned-permissive", "test-ns", "12")
	profile.Annotations = map[string]string{}

	c := &ContainerProfileCacheImpl{cfg: config.Config{EnableSignatureVerification: false}}
	if !c.verifyUserContainerProfile(profile, "wlid://test/cluster/ns/Pod/p") {
		t.Error("with verification off an unsigned user-defined profile must still load")
	}
}

// TestTamperAlert_StampsEmissionTime pins the same for R1016.
func TestTamperAlert_StampsEmissionTime(t *testing.T) {
	exporter := &captureExporter{}
	c := &ContainerProfileCacheImpl{}
	c.SetTamperAlertExporter(exporter)
	c.emitTamperAlert("tamper-app", "ns", "wlid://cluster/namespace-ns/deployment-d", "ContainerProfile", errTamper)

	alerts := exporter.ruleAlerts()
	require.Len(t, alerts, 1)
	ts := alerts[0].GetBaseRuntimeAlert().Timestamp
	require.False(t, ts.IsZero(), "R1016 must carry an emission timestamp")
	require.WithinDuration(t, time.Now(), ts, 5*time.Second)
	b, err := json.Marshal(alerts[0])
	require.NoError(t, err)
	require.NotContains(t, string(b), `"timestamp":"0001-01-01T00:00:00Z"`, "serialised R1016 alert timestamp must not be the zero value")
}

var errTamper = fmt.Errorf("signature verification failed")
