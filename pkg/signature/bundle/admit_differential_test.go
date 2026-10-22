//go:build experimental_signing

package bundle

import (
	"crypto/ecdsa"
	"errors"
	"testing"

	rulemanagertypesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func cpSpecForPath(path string) v1beta1.ContainerProfileSpec {
	switch path {
	case "execs":
		return v1beta1.ContainerProfileSpec{Execs: []v1beta1.ExecCalls{{Path: "/bin/x"}}}
	case "opens":
		return v1beta1.ContainerProfileSpec{Opens: []v1beta1.OpenCalls{{Path: "/data/x", Flags: []string{"O_RDONLY"}}}}
	case "ingress":
		port := int32(80)
		return v1beta1.ContainerProfileSpec{Ingress: []v1beta1.NetworkNeighbor{{Identifier: "n", Type: "internal", Ports: []v1beta1.NetworkPort{{Name: "TCP-80", Port: &port, Protocol: "TCP"}}}}}
	default:
		return v1beta1.ContainerProfileSpec{Capabilities: []string{"CAP_NET_ADMIN"}}
	}
}

func buildFragment(t *testing.T, name string, bundleLabel, class string, spec v1beta1.ContainerProfileSpec, key *ecdsa.PrivateKey, signed bool) *v1beta1.ContainerProfile {
	t.Helper()
	labels := map[string]string{}
	if bundleLabel != "" {
		labels[LabelBundle] = bundleLabel
	}
	if class != "" {
		labels[LabelFragmentClass] = class
	}
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "any", Labels: labels},
		Spec:       spec,
	}
	if signed {
		if err := signature.SignObject(profiles.NewContainerProfileAdapter(cp), signature.WithPrivateKey(key)); err != nil {
			t.Fatalf("sign %s: %v", name, err)
		}
	}
	return cp
}

func TestAdmitDifferential_ContainerProfileMatrix(t *testing.T) {
	baseKey, admKey, ovlKey, attackerKey := genKey(t), genKey(t), genKey(t), genKey(t)

	fpOf := func(key *ecdsa.PrivateKey) string {
		cp := buildFragment(t, "probe", "bundleX", "base", cpSpecForPath("execs"), key, true)
		return signerIDOf(t, cp)
	}
	baseFp, admFp, ovlFp := fpOf(baseKey), fpOf(admKey), fpOf(ovlKey)

	const bundleName = "bundleX"
	policy := TrustPolicy{Classes: map[FragmentClass]ClassPolicy{
		ClassBase:      {Signers: []string{baseFp}, AllowedSpecPaths: []string{"execs"}},
		ClassAdmission: {Signers: []string{admFp}, AllowedSpecPaths: []string{"ingress"}},
		ClassOverlay:   {Signers: []string{ovlFp}, AllowedSpecPaths: []string{"opens"}},
	}}

	type classInfo struct {
		name        string
		inPolicy    bool
		trustedKey  *ecdsa.PrivateKey
		allowedPath string
		forbidPath  string
	}
	classes := []classInfo{
		{"base", true, baseKey, "execs", "ingress"},
		{"admission", true, admKey, "ingress", "execs"},
		{"overlay", true, ovlKey, "opens", "ingress"},
		{"unknown", false, attackerKey, "execs", "execs"},
		{"", false, attackerKey, "execs", "execs"},
	}

	expected := func(signed, bundleMatch bool, ci classInfo, signerTrusted, pathAllowed bool) error {
		if !signed {
			return ErrFragmentUnsigned
		}
		if !bundleMatch {
			return ErrNoClass
		}
		if ci.name == "" {
			return ErrNoClass
		}
		if !ci.inPolicy {
			return ErrClassNotAllowed
		}
		if !signerTrusted {
			return ErrSignerNotTrusted
		}
		if !pathAllowed {
			return ErrPathNotAllowed
		}
		return nil
	}

	checks := 0
	admitted := 0
	for _, signed := range []bool{true, false} {
		for _, bundleMatch := range []bool{true, false} {
			for _, ci := range classes {
				for _, signerTrusted := range []bool{true, false} {
					for _, pathAllowed := range []bool{true, false} {
						key := ci.trustedKey
						if !signerTrusted {
							key = attackerKey
						}
						path := ci.allowedPath
						if !pathAllowed {
							path = ci.forbidPath
						}
						bl := bundleName
						if !bundleMatch {
							bl = "otherBundle"
						}
						cp := buildFragment(t, "matrix-frag", bl, ci.name, cpSpecForPath(path), key, signed)

						want := expected(signed, bundleMatch, ci, signerTrusted, pathAllowed)
						_, err := admitFragment(cp, bundleName, policy)

						if want == nil {
							if err != nil {
								t.Fatalf("signed=%v bundleMatch=%v class=%q signerTrusted=%v pathAllowed=%v: expected ADMIT, got %v", signed, bundleMatch, ci.name, signerTrusted, pathAllowed, err)
							}
							admitted++
						} else {
							if !errors.Is(err, want) {
								t.Fatalf("signed=%v bundleMatch=%v class=%q signerTrusted=%v pathAllowed=%v: expected errors.Is(%v), got %v", signed, bundleMatch, ci.name, signerTrusted, pathAllowed, want, err)
							}
						}
						checks++
					}
				}
			}
		}
	}
	t.Logf("admitFragment matched an independent precedence model on all %d matrix cells (%d admits, %d rejections)", checks, admitted, checks-admitted)
}

func buildRules(t *testing.T, name, bundleLabel, class string, ids []string, key *ecdsa.PrivateKey, signed bool) *rulemanagertypesv1.Rules {
	t.Helper()
	labels := map[string]string{}
	if bundleLabel != "" {
		labels[LabelBundle] = bundleLabel
	}
	if class != "" {
		labels[LabelFragmentClass] = class
	}
	var rules []rulemanagertypesv1.Rule
	for _, id := range ids {
		rules = append(rules, rulemanagertypesv1.Rule{Enabled: true, ID: id, Name: "rule-" + id})
	}
	r := &rulemanagertypesv1.Rules{
		TypeMeta:   metav1.TypeMeta{APIVersion: "kubescape.io/v1", Kind: "Rules"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "any", Labels: labels},
		Spec:       rulemanagertypesv1.RulesSpec{Rules: rules},
	}
	if signed {
		if err := signature.SignObject(profiles.NewRulesAdapter(r), signature.WithPrivateKey(key)); err != nil {
			t.Fatalf("sign rules %s: %v", name, err)
		}
	}
	return r
}

func TestAdmitDifferential_RulesMatrix(t *testing.T) {
	baseKey, ovlKey, attackerKey := genKey(t), genKey(t), genKey(t)

	fpOf := func(key *ecdsa.PrivateKey) string {
		return rulesSignerIDOf(t, buildRules(t, "probe", "bundleX", "base", []string{"R0001"}, key, true))
	}
	baseFp, ovlFp := fpOf(baseKey), fpOf(ovlKey)

	policy := TrustPolicy{RuleClasses: map[RuleClass]RuleClassPolicy{
		RuleClassBase:    {Signers: []string{baseFp}, AllowedRuleIDs: []string{"R0001", "R0002"}},
		RuleClassOverlay: {Signers: []string{ovlFp}, AllowedRuleIDs: []string{"R0001"}},
	}}

	type rClassInfo struct {
		name       string
		inPolicy   bool
		trustedKey *ecdsa.PrivateKey
	}
	rclasses := []rClassInfo{
		{"base", true, baseKey},
		{"overlay", true, ovlKey},
		{"unknown", false, attackerKey},
		{"", false, attackerKey},
	}

	allowedIDs := []string{"R0001"}
	disallowedIDs := []string{"R0001", "R9999"}

	expected := func(signed bool, ci rClassInfo, signerTrusted, idsAllowed, bundlePresent bool) error {
		if !signed {
			return ErrFragmentUnsigned
		}
		if ci.name == "" {
			return ErrNoClass
		}
		if !ci.inPolicy {
			return ErrRuleClassNotAllowed
		}
		if !signerTrusted {
			return ErrSignerNotTrusted
		}
		if !idsAllowed {
			return ErrRuleIDNotAllowed
		}
		if ci.name == "overlay" && !bundlePresent {
			return ErrRuleBundleRequired
		}
		return nil
	}

	checks := 0
	admitted := 0
	for _, signed := range []bool{true, false} {
		for _, ci := range rclasses {
			for _, signerTrusted := range []bool{true, false} {
				for _, idsAllowed := range []bool{true, false} {
					for _, bundlePresent := range []bool{true, false} {
						key := ci.trustedKey
						if !signerTrusted {
							key = attackerKey
						}
						ids := allowedIDs
						if !idsAllowed {
							ids = disallowedIDs
						}
						bl := "bundleX"
						if !bundlePresent {
							bl = ""
						}
						r := buildRules(t, "matrix-rules", bl, ci.name, ids, key, signed)

						want := expected(signed, ci, signerTrusted, idsAllowed, bundlePresent)
						_, err := AdmitRulesFragment(r, policy)

						if want == nil {
							if err != nil {
								t.Fatalf("signed=%v class=%q signerTrusted=%v idsAllowed=%v bundlePresent=%v: expected ADMIT, got %v", signed, ci.name, signerTrusted, idsAllowed, bundlePresent, err)
							}
							admitted++
						} else {
							if !errors.Is(err, want) {
								t.Fatalf("signed=%v class=%q signerTrusted=%v idsAllowed=%v bundlePresent=%v: expected errors.Is(%v), got %v", signed, ci.name, signerTrusted, idsAllowed, bundlePresent, want, err)
							}
						}
						checks++
					}
				}
			}
		}
	}
	t.Logf("AdmitRulesFragment matched an independent precedence model on all %d matrix cells (%d admits, %d rejections)", checks, admitted, checks-admitted)
}
