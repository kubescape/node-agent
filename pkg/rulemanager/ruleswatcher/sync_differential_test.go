//go:build experimental_signing

package ruleswatcher

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"testing"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
)

type ruleProvenance struct {
	ID          string
	Bundle      string
	ClusterWide bool
}

// archetype is one Rules-object shape with its own oracle: what the object
// contributes to the effective ruleset with signing OFF and with signing ON.
type archetype struct {
	name    string
	build   func(t *testing.T, baseKey, overlayKey, attackerKey *ecdsa.PrivateKey) *typesv1.Rules
	whenOff []ruleProvenance
	whenOn  []ruleProvenance
	admits  bool
}

func rulesObjMixed(name, namespace, bundleName, class string) *typesv1.Rules {
	r := rulesObj(name, namespace, bundleName, class, "R0001", "R0002")
	r.Spec.Rules = append(r.Spec.Rules, typesv1.Rule{Enabled: false, ID: "R0003", Name: "rule-R0003"})
	return r
}

func syncArchetypes() []archetype {
	cw := func(ids ...string) []ruleProvenance {
		out := make([]ruleProvenance, 0, len(ids))
		for _, id := range ids {
			out = append(out, ruleProvenance{ID: id, ClusterWide: true})
		}
		return out
	}
	return []archetype{
		{
			name: "unsigned-baseline",
			build: func(t *testing.T, _, _, _ *ecdsa.PrivateKey) *typesv1.Rules {
				return rulesObjMixed("unsigned-baseline", "kubescape", "", "")
			},
			whenOff: cw("R0001", "R0002"), whenOn: nil, admits: false,
		},
		{
			name: "signed-baseline",
			build: func(t *testing.T, baseKey, _, _ *ecdsa.PrivateKey) *typesv1.Rules {
				return sign(t, rulesObjMixed("signed-baseline", "kubescape", "", string(bundle.RuleClassBase)), baseKey)
			},
			whenOff: cw("R0001", "R0002"), whenOn: cw("R0001", "R0002"), admits: true,
		},
		{
			name: "wrong-signer-baseline",
			build: func(t *testing.T, _, _, attackerKey *ecdsa.PrivateKey) *typesv1.Rules {
				return sign(t, rulesObjMixed("wrong-signer", "attacker", "", string(bundle.RuleClassBase)), attackerKey)
			},
			whenOff: cw("R0001", "R0002"), whenOn: nil, admits: false,
		},
		{
			name: "corrupt-signature",
			build: func(t *testing.T, baseKey, _, _ *ecdsa.PrivateKey) *typesv1.Rules {
				r := sign(t, rulesObjMixed("corrupt-signature", "kubescape", "", string(bundle.RuleClassBase)), baseKey)
				r.Annotations[signature.AnnotationSignature] = "AAAA" + r.Annotations[signature.AnnotationSignature][4:]
				return r
			},
			whenOff: cw("R0001", "R0002"), whenOn: nil, admits: false,
		},
		{
			// Non-embedded signature + stored-spec tamper: the signature binds
			// the stored content, so the whole object is rejected.
			name: "stale-spec-injection",
			build: func(t *testing.T, baseKey, _, _ *ecdsa.PrivateKey) *typesv1.Rules {
				r := sign(t, rulesObjMixed("stale-spec", "kubescape", "", string(bundle.RuleClassBase)), baseKey)
				r.Spec.Rules = append(r.Spec.Rules, typesv1.Rule{Enabled: true, ID: "R9999", Name: "rule-R9999"})
				return r
			},
			whenOff: cw("R0001", "R0002", "R9999"), whenOn: nil, admits: false,
		},
		{
			// Embedded-content signature + stored-spec tamper: only the signed
			// embedded rules load; the injected stored rule is inert.
			name: "stale-spec-embedded",
			build: func(t *testing.T, baseKey, _, _ *ecdsa.PrivateKey) *typesv1.Rules {
				r := signEmbedded(t, rulesObjMixed("stale-spec-embedded", "kubescape", "", string(bundle.RuleClassBase)), baseKey)
				r.Spec.Rules = append(r.Spec.Rules, typesv1.Rule{Enabled: true, ID: "R9999", Name: "rule-R9999"})
				return r
			},
			whenOff: cw("R0001", "R0002", "R9999"), whenOn: cw("R0001", "R0002"), admits: true,
		},
		{
			name: "overlay-bundled",
			build: func(t *testing.T, _, overlayKey, _ *ecdsa.PrivateKey) *typesv1.Rules {
				return sign(t, rulesObj("overlay-bundled", "redis", "redis", string(bundle.RuleClassOverlay), "R0001"), overlayKey)
			},
			whenOff: []ruleProvenance{{ID: "R0001", ClusterWide: true}},
			whenOn:  []ruleProvenance{{ID: "R0001", Bundle: "redis", ClusterWide: false}},
			admits:  true,
		},
		{
			name: "overlay-no-bundle",
			build: func(t *testing.T, _, overlayKey, _ *ecdsa.PrivateKey) *typesv1.Rules {
				return sign(t, rulesObj("overlay-no-bundle", "redis", "", string(bundle.RuleClassOverlay), "R0001"), overlayKey)
			},
			whenOff: []ruleProvenance{{ID: "R0001", ClusterWide: true}}, whenOn: nil, admits: false,
		},
		{
			// A key trusted for base signing an overlay fragment: cross-class
			// use of a legitimate key is refused like an unknown key.
			name: "cross-class-trusted-key",
			build: func(t *testing.T, baseKey, _, _ *ecdsa.PrivateKey) *typesv1.Rules {
				return sign(t, rulesObj("cross-class", "redis", "redis", string(bundle.RuleClassOverlay), "R0001"), baseKey)
			},
			whenOff: []ruleProvenance{{ID: "R0001", ClusterWide: true}}, whenOn: nil, admits: false,
		},
		{
			name: "overlay-id-not-allowed",
			build: func(t *testing.T, _, overlayKey, _ *ecdsa.PrivateKey) *typesv1.Rules {
				return sign(t, rulesObj("overlay-bad-id", "redis", "redis", string(bundle.RuleClassOverlay), "R0040"), overlayKey)
			},
			whenOff: []ruleProvenance{{ID: "R0040", ClusterWide: true}}, whenOn: nil, admits: false,
		},
		{
			// Admits but contributes nothing: distinguishes "zero enabled rules"
			// from the zero-ADMITTED detection outage.
			name: "signed-all-disabled",
			build: func(t *testing.T, baseKey, _, _ *ecdsa.PrivateKey) *typesv1.Rules {
				r := rulesObj("signed-all-disabled", "kubescape", "", string(bundle.RuleClassBase))
				r.Spec.Rules = []typesv1.Rule{{Enabled: false, ID: "R0005", Name: "rule-R0005"}}
				return sign(t, r, baseKey)
			},
			whenOff: nil, whenOn: nil, admits: true,
		},
	}
}

func signEmbedded(t *testing.T, r *typesv1.Rules, key *ecdsa.PrivateKey) *typesv1.Rules {
	t.Helper()
	if err := signature.SignObject(profiles.NewRulesAdapter(r), signature.WithPrivateKey(key), signature.WithEmbedContent(true)); err != nil {
		t.Fatalf("sign embedded %s: %v", r.Name, err)
	}
	return r
}

func provKey(p ruleProvenance) string {
	return fmt.Sprintf("%s|%s|%v", p.ID, p.Bundle, p.ClusterWide)
}

// sortedKeys dedups by (bundle, ID) — SyncRules keys rules that way, so two
// objects contributing the same cluster-wide rule collapse to one.
func sortedKeys(ps []ruleProvenance) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		k := provKey(p)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestSyncDifferential_EffectiveRulesetMatrix runs scenario sets of Rules
// objects through the real watcher sync, signing OFF and ON, and compares the
// SyncRules payload against an independent per-archetype oracle. The oracle
// also predicts the detection-outage backstop condition (zero fragments
// admitted while Rules objects exist).
func TestSyncDifferential_EffectiveRulesetMatrix(t *testing.T) {
	arch := syncArchetypes()
	byName := map[string]archetype{}
	for _, a := range arch {
		byName[a.name] = a
	}
	scenarios := [][]string{
		{},
		{"unsigned-baseline"},
		{"signed-baseline"},
		{"unsigned-baseline", "signed-baseline"},
		{"wrong-signer-baseline"},
		{"corrupt-signature"},
		{"stale-spec-injection"},
		{"stale-spec-embedded"},
		{"signed-baseline", "overlay-bundled"},
		{"overlay-no-bundle"},
		{"cross-class-trusted-key"},
		{"overlay-id-not-allowed"},
		{"signed-all-disabled"},
		{"unsigned-baseline", "wrong-signer-baseline", "corrupt-signature", "overlay-no-bundle", "overlay-id-not-allowed"},
		{"unsigned-baseline", "signed-baseline", "wrong-signer-baseline", "corrupt-signature", "stale-spec-injection", "stale-spec-embedded", "overlay-bundled", "overlay-no-bundle", "overlay-id-not-allowed", "signed-all-disabled"},
	}

	checks := 0
	for _, names := range scenarios {
		for _, signingOn := range []bool{false, true} {
			baseKey, overlayKey, attackerKey := testKey(t), testKey(t), testKey(t)

			objs := make([]*typesv1.Rules, 0, len(names))
			var want []ruleProvenance
			admitted, objects := 0, len(names)
			for _, n := range names {
				a := byName[n]
				objs = append(objs, a.build(t, baseKey, overlayKey, attackerKey))
				if signingOn {
					want = append(want, a.whenOn...)
					if a.admits {
						admitted++
					}
				} else {
					want = append(want, a.whenOff...)
				}
			}

			creator := rulecreator.NewRuleCreator()
			w := NewRulesWatcher(newFakeK8sClient(t, objs...), creator, nil)
			if signingOn {
				probe := sign(t, rulesObj("probe-base", "x", "", string(bundle.RuleClassBase), "R0001"), baseKey)
				probeOvl := sign(t, rulesObj("probe-ovl", "x", "b", string(bundle.RuleClassOverlay), "R0001"), overlayKey)
				w.SetTrustPolicy(&bundle.TrustPolicy{RuleClasses: map[bundle.RuleClass]bundle.RuleClassPolicy{
					bundle.RuleClassBase:    {Signers: []string{signerOf(t, probe)}, AllowedRuleIDs: []string{"*"}},
					bundle.RuleClassOverlay: {Signers: []string{signerOf(t, probeOvl)}, AllowedRuleIDs: []string{"R0001", "R0002"}},
				}})
			}

			if err := w.syncAllRulesFromCluster(context.Background()); err != nil {
				t.Fatalf("scenario %v signingOn=%v: sync: %v", names, signingOn, err)
			}

			got := make([]ruleProvenance, 0)
			for _, r := range creator.CreateAllRules() {
				got = append(got, ruleProvenance{ID: r.ID, Bundle: r.Bundle, ClusterWide: r.ClusterWide})
			}
			g, wnt := sortedKeys(got), sortedKeys(want)
			if strings.Join(g, ",") != strings.Join(wnt, ",") {
				t.Fatalf("scenario %v signingOn=%v: effective ruleset mismatch\n got: %v\nwant: %v", names, signingOn, g, wnt)
			}

			if signingOn {
				wantOutage := admitted == 0 && objects > 0
				zeroEnabled := len(got) == 0
				if wantOutage && !zeroEnabled {
					t.Fatalf("scenario %v: oracle says outage but rules loaded: %v", names, g)
				}
				_ = wantOutage
			}
			checks++
		}
	}
	t.Logf("sync differential: %d scenario cells matched the independent oracle", checks)
}

// The detection-outage backstop must fire exactly when signing is on, Rules
// objects exist, and none admitted — and must NOT fire when a fragment admits
// with only disabled rules (zero enabled != zero admitted).
func TestSyncBackstop_FiresOnZeroAdmittedOnly(t *testing.T) {
	cases := []struct {
		name       string
		objects    []string
		wantOutage bool
	}{
		{"all-rejected", []string{"unsigned-baseline", "wrong-signer-baseline"}, true},
		{"admitted-but-all-disabled", []string{"signed-all-disabled"}, false},
		{"no-objects", nil, false},
		{"one-admits", []string{"unsigned-baseline", "signed-baseline"}, false},
	}
	arch := syncArchetypes()
	byName := map[string]archetype{}
	for _, a := range arch {
		byName[a.name] = a
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			baseKey, overlayKey, attackerKey := testKey(t), testKey(t), testKey(t)
			objs := make([]*typesv1.Rules, 0, len(tc.objects))
			for _, n := range tc.objects {
				objs = append(objs, byName[n].build(t, baseKey, overlayKey, attackerKey))
			}
			creator := rulecreator.NewRuleCreator()
			w := NewRulesWatcher(newFakeK8sClient(t, objs...), creator, nil)
			probe := sign(t, rulesObj("probe-base", "x", "", string(bundle.RuleClassBase), "R0001"), baseKey)
			w.SetTrustPolicy(&bundle.TrustPolicy{RuleClasses: map[bundle.RuleClass]bundle.RuleClassPolicy{
				bundle.RuleClassBase: {Signers: []string{signerOf(t, probe)}, AllowedRuleIDs: []string{"*"}},
			}})

			out := captureLoggerOutput(t, func() {
				if err := w.syncAllRulesFromCluster(context.Background()); err != nil {
					t.Fatalf("sync: %v", err)
				}
			})
			fired := strings.Contains(out, "detection is effectively OFF")
			if fired != tc.wantOutage {
				t.Fatalf("backstop fired=%v want=%v\nlogs:\n%s", fired, tc.wantOutage, out)
			}
		})
	}
}

func captureLoggerOutput(t *testing.T, fn func()) string {
	t.Helper()
	origStderr, origStdout := os.Stderr, os.Stdout
	r, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr, os.Stdout = wPipe, wPipe
	logger.InitLogger("pretty")
	fn()
	wPipe.Close()
	os.Stderr, os.Stdout = origStderr, origStdout
	logger.InitLogger("pretty")
	b, _ := io.ReadAll(r)
	return string(b)
}
