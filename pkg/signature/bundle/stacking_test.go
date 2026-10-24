//go:build experimental_signing

// Stacking truth table for bundle-fragment composition: which spec surfaces
// are ADDITIVE (union across fragments), which are REPLACEMENT (keyed, the
// higher-precedence class wins wholly), and that multi-stacked composites are
// deterministic regardless of input order (canonical order: class precedence
// base < admission < overlay, then signer, then digest).
package bundle

import (
	"crypto/ecdsa"
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func stackPolicy(baseID, admissionID, overlayID string) TrustPolicy {
	all := []string{"architectures", "capabilities", "execs", "opens", "syscalls", "rulePolicies", "endpoints", "identifiedCallStacks", "labelSelector", "ingress", "egress", "imageID", "imageTag", "seccompProfile"}
	return TrustPolicy{Classes: map[FragmentClass]ClassPolicy{
		ClassBase:      {Signers: []string{baseID}, AllowedSpecPaths: all},
		ClassAdmission: {Signers: []string{admissionID}, AllowedSpecPaths: all},
		ClassOverlay:   {Signers: []string{overlayID}, AllowedSpecPaths: all},
	}}
}

func egressEntry(id string, port int32) v1beta1.NetworkNeighbor {
	return v1beta1.NetworkNeighbor{
		Identifier: id, Type: "internal",
		PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "peer"}},
		Ports:       []v1beta1.NetworkPort{{Name: "TCP", Port: &port, Protocol: "TCP"}},
	}
}

// P-A1/P-A2: disjoint contributions from stacked fragments UNION into the
// composite — exec/open lists appended (deduped), string sets merged.
func TestStacking_AdditiveUnion(t *testing.T) {
	vendor, op, ov := genKey(t), genKey(t), genKey(t)
	base := fragment(t, "app", "base", v1beta1.ContainerProfileSpec{
		Architectures: []string{"amd64"},
		Capabilities:  []string{"NET_BIND_SERVICE"},
		Execs:         []v1beta1.ExecCalls{{Path: "/bin/server", Args: []string{"server"}}},
		Opens:         []v1beta1.OpenCalls{{Path: "/etc/app.conf", Flags: []string{"O_RDONLY"}}},
	}, vendor)
	overlay := fragment(t, "app-extra", "overlay", v1beta1.ContainerProfileSpec{
		Architectures: []string{"arm64"},
		Capabilities:  []string{"CHOWN"},
		Execs:         []v1beta1.ExecCalls{{Path: "/bin/backup", Args: []string{"backup"}}},
	}, ov)
	policy := stackPolicy(signerIDOf(t, base), signerIDOf(t, base), signerIDOf(t, overlay))
	_ = op

	composite, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, overlay}, policy)
	if err != nil {
		t.Fatalf("AssembleAndVerify: %v", err)
	}
	if len(composite.Spec.Execs) != 2 {
		t.Errorf("execs must union across fragments: got %+v", composite.Spec.Execs)
	}
	if len(composite.Spec.Architectures) != 2 || len(composite.Spec.Capabilities) != 2 {
		t.Errorf("set fields must union: arch=%v caps=%v", composite.Spec.Architectures, composite.Spec.Capabilities)
	}
	if len(composite.Spec.Opens) != 1 {
		t.Errorf("base opens must survive: %+v", composite.Spec.Opens)
	}
}

// P-R1: a network entry with the SAME Identifier is REPLACED WHOLLY by the
// higher-precedence class — ports are not merged across fragments.
func TestStacking_ReplacementByIdentifier(t *testing.T) {
	vendor, ov := genKey(t), genKey(t)
	base := fragment(t, "app", "base", v1beta1.ContainerProfileSpec{
		Egress: []v1beta1.NetworkNeighbor{egressEntry("db", 5432)},
	}, vendor)
	overlay := fragment(t, "app-egress", "overlay", v1beta1.ContainerProfileSpec{
		Egress: []v1beta1.NetworkNeighbor{egressEntry("db", 5433)},
	}, ov)
	policy := stackPolicy(signerIDOf(t, base), signerIDOf(t, base), signerIDOf(t, overlay))

	composite, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, overlay}, policy)
	if err != nil {
		t.Fatalf("AssembleAndVerify: %v", err)
	}
	if len(composite.Spec.Egress) != 1 {
		t.Fatalf("same-Identifier entries must collapse to one: %+v", composite.Spec.Egress)
	}
	ports := composite.Spec.Egress[0].Ports
	if len(ports) != 1 || ports[0].Port == nil || *ports[0].Port != 5433 {
		t.Errorf("overlay must replace the entry WHOLLY (no port merge): %+v", ports)
	}
}

// P-R2: PolicyByRuleId entries with the same rule ID are replaced wholly by
// the higher-precedence class.
func TestStacking_RulePolicyReplacement(t *testing.T) {
	vendor, ov := genKey(t), genKey(t)
	base := fragment(t, "app", "base", v1beta1.ContainerProfileSpec{
		PolicyByRuleId: map[string]v1beta1.RulePolicy{"R0001": {AllowedProcesses: []string{"/bin/a"}}},
	}, vendor)
	overlay := fragment(t, "app-pol", "overlay", v1beta1.ContainerProfileSpec{
		PolicyByRuleId: map[string]v1beta1.RulePolicy{"R0001": {AllowedProcesses: []string{"/bin/b"}}},
	}, ov)
	policy := stackPolicy(signerIDOf(t, base), signerIDOf(t, base), signerIDOf(t, overlay))

	composite, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, overlay}, policy)
	if err != nil {
		t.Fatalf("AssembleAndVerify: %v", err)
	}
	got := composite.Spec.PolicyByRuleId["R0001"].AllowedProcesses
	if len(got) != 1 || got[0] != "/bin/b" {
		t.Errorf("overlay rule policy must replace base's wholly: %v", got)
	}
}

// P-M1: three stacked classes — additive fields are the 3-way union;
// replacement fields follow full precedence (overlay > admission > base).
func TestStacking_MultiStackThreeClasses(t *testing.T) {
	vendor, op, ov := genKey(t), genKey(t), genKey(t)
	base := fragment(t, "app", "base", v1beta1.ContainerProfileSpec{
		Execs:  []v1beta1.ExecCalls{{Path: "/bin/server", Args: []string{"server"}}},
		Egress: []v1beta1.NetworkNeighbor{egressEntry("db", 1111)},
	}, vendor)
	adm := fragment(t, "app-adm", "admission", v1beta1.ContainerProfileSpec{
		Execs:  []v1beta1.ExecCalls{{Path: "/bin/probe", Args: []string{"probe"}}},
		Egress: []v1beta1.NetworkNeighbor{egressEntry("db", 2222)},
	}, op)
	overlay := fragment(t, "app-ov", "overlay", v1beta1.ContainerProfileSpec{
		Execs:  []v1beta1.ExecCalls{{Path: "/bin/backup", Args: []string{"backup"}}},
		Egress: []v1beta1.NetworkNeighbor{egressEntry("db", 3333)},
	}, ov)
	policy := stackPolicy(signerIDOf(t, base), signerIDOf(t, adm), signerIDOf(t, overlay))

	composite, manifest, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, adm, overlay}, policy)
	if err != nil {
		t.Fatalf("AssembleAndVerify: %v", err)
	}
	if len(composite.Spec.Execs) != 3 {
		t.Errorf("3-way additive union of execs: %+v", composite.Spec.Execs)
	}
	if len(composite.Spec.Egress) != 1 || *composite.Spec.Egress[0].Ports[0].Port != 3333 {
		t.Errorf("highest class (overlay) must win the keyed entry: %+v", composite.Spec.Egress)
	}
	if len(manifest.Leaves) != 3 {
		t.Errorf("manifest must carry all 3 members: %d", len(manifest.Leaves))
	}
}

// P-A4: the composite spec AND Merkle root are invariant under every input
// permutation of a 3-fragment stack.
func TestStacking_PermutationInvariance(t *testing.T) {
	vendor, op, ov := genKey(t), genKey(t), genKey(t)
	base := fragment(t, "app", "base", v1beta1.ContainerProfileSpec{
		Execs:  []v1beta1.ExecCalls{{Path: "/bin/server", Args: []string{"server"}}},
		Egress: []v1beta1.NetworkNeighbor{egressEntry("db", 1111)},
	}, vendor)
	adm := fragment(t, "app-adm", "admission", v1beta1.ContainerProfileSpec{
		Egress: []v1beta1.NetworkNeighbor{egressEntry("db", 2222)},
	}, op)
	overlay := fragment(t, "app-ov", "overlay", v1beta1.ContainerProfileSpec{
		Egress: []v1beta1.NetworkNeighbor{egressEntry("cache", 6379)},
	}, ov)
	policy := stackPolicy(signerIDOf(t, base), signerIDOf(t, adm), signerIDOf(t, overlay))

	perms := [][]*v1beta1.ContainerProfile{
		{base, adm, overlay}, {base, overlay, adm}, {adm, base, overlay},
		{adm, overlay, base}, {overlay, base, adm}, {overlay, adm, base},
	}
	var wantRoot, wantSpec string
	for i, p := range perms {
		composite, manifest, err := AssembleAndVerify("redis", "redis", p, policy)
		if err != nil {
			t.Fatalf("perm %d: %v", i, err)
		}
		spec := jsonKey(composite.Spec)
		if i == 0 {
			wantRoot, wantSpec = manifest.Root, spec
			continue
		}
		if manifest.Root != wantRoot {
			t.Errorf("perm %d: Merkle root depends on input order", i)
		}
		if spec != wantSpec {
			t.Errorf("perm %d: composite spec depends on input order", i)
		}
	}
	// Sanity on the fixed point: admission (class 1) beat base (class 0) on "db".
	composite, _, _ := AssembleAndVerify("redis", "redis", perms[0], policy)
	byID := map[string]int32{}
	for _, e := range composite.Spec.Egress {
		byID[e.Identifier] = *e.Ports[0].Port
	}
	if byID["db"] != 2222 || byID["cache"] != 6379 {
		t.Errorf("expected db→2222 (admission wins), cache→6379: %v", byID)
	}
}

// P-M2: two fragments of the SAME class also stack deterministically — the
// canonical (signer, digest) tiebreak makes the same-Identifier winner stable
// under permutation.
func TestStacking_SameClassTieIsDeterministic(t *testing.T) {
	vendor := genKey(t)
	ovKeyA, ovKeyB := genKey(t), genKey(t)
	base := fragment(t, "app", "base", baseSpec(), vendor)
	ovA := fragment(t, "app-ov-a", "overlay", v1beta1.ContainerProfileSpec{
		Egress: []v1beta1.NetworkNeighbor{egressEntry("db", 1000)},
	}, ovKeyA)
	ovB := fragment(t, "app-ov-b", "overlay", v1beta1.ContainerProfileSpec{
		Egress: []v1beta1.NetworkNeighbor{egressEntry("db", 2000)},
	}, ovKeyB)
	policy := TrustPolicy{Classes: map[FragmentClass]ClassPolicy{
		ClassBase:    {Signers: []string{signerIDOf(t, base)}, AllowedSpecPaths: []string{"architectures", "execs", "opens"}},
		ClassOverlay: {Signers: []string{signerIDOf(t, ovA), signerIDOf(t, ovB)}, AllowedSpecPaths: []string{"egress"}},
	}}

	c1, m1, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, ovA, ovB}, policy)
	if err != nil {
		t.Fatalf("AssembleAndVerify: %v", err)
	}
	c2, m2, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{ovB, base, ovA}, policy)
	if err != nil {
		t.Fatalf("AssembleAndVerify: %v", err)
	}
	if m1.Root != m2.Root || jsonKey(c1.Spec) != jsonKey(c2.Spec) {
		t.Errorf("same-class stacking must be order-invariant (signer/digest tiebreak)")
	}
	if len(c1.Spec.Egress) != 1 {
		t.Errorf("same-Identifier same-class entries must still collapse to one: %+v", c1.Spec.Egress)
	}
}

// P-A3: duplicated fragment content must not duplicate composite entries.
func TestStacking_DuplicateContentIsIdempotent(t *testing.T) {
	vendor, ov := genKey(t), genKey(t)
	base := fragment(t, "app", "base", baseSpec(), vendor)
	dup := fragment(t, "app-dup", "overlay", baseSpec(), ov) // same content, different class/name
	policy := stackPolicy(signerIDOf(t, base), signerIDOf(t, base), signerIDOf(t, dup))

	composite, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, dup}, policy)
	if err != nil {
		t.Fatalf("AssembleAndVerify: %v", err)
	}
	if len(composite.Spec.Execs) != 1 || len(composite.Spec.Opens) != 1 {
		t.Errorf("identical entries across fragments must dedup: execs=%+v opens=%+v", composite.Spec.Execs, composite.Spec.Opens)
	}
}

var _ = ecdsa.PrivateKey{} // keep ecdsa import when helpers move

// ---- Wave 2: complex multi-entry overlays ----------------------------------

// W1: one overlay carrying MANY entries — some colliding, some new. Colliding
// Identifiers replace wholly; new ones add; untouched base keys survive.
func TestStacking_MultiKeyMixedAddAndReplace(t *testing.T) {
	vendor, ov := genKey(t), genKey(t)
	base := fragment(t, "app", "base", v1beta1.ContainerProfileSpec{
		Execs:  []v1beta1.ExecCalls{{Path: "/bin/server", Args: []string{"server"}}},
		Egress: []v1beta1.NetworkNeighbor{egressEntry("db", 5432), egressEntry("cache", 6379)},
	}, vendor)
	overlay := fragment(t, "app-multi", "overlay", v1beta1.ContainerProfileSpec{
		Execs: []v1beta1.ExecCalls{{Path: "/bin/backup", Args: []string{"backup"}}, {Path: "/bin/probe", Args: []string{"probe"}}},
		Egress: []v1beta1.NetworkNeighbor{
			egressEntry("db", 5433),      // collides -> replaces
			egressEntry("s3", 9000),      // new
			egressEntry("metrics", 9090), // new
		},
	}, ov)
	policy := stackPolicy(signerIDOf(t, base), signerIDOf(t, base), signerIDOf(t, overlay))

	composite, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, overlay}, policy)
	if err != nil {
		t.Fatalf("AssembleAndVerify: %v", err)
	}
	byID := map[string]int32{}
	for _, e := range composite.Spec.Egress {
		byID[e.Identifier] = *e.Ports[0].Port
	}
	want := map[string]int32{"db": 5433, "cache": 6379, "s3": 9000, "metrics": 9090}
	if len(byID) != 4 {
		t.Fatalf("mixed add+replace must yield 4 keys: %v", byID)
	}
	for k, p := range want {
		if byID[k] != p {
			t.Errorf("key %s: port %d, want %d (collide→replace, new→add, untouched→survive)", k, byID[k], p)
		}
	}
	if len(composite.Spec.Execs) != 3 {
		t.Errorf("multi-entry exec union: got %d, want 3", len(composite.Spec.Execs))
	}
}

// W2: key aliasing BYPASSES replacement — an overlay that replaces db's port
// can simultaneously re-grant the old port under a fresh Identifier for the
// SAME address; the effective allow-set is the union over entries, so the
// "replaced" port remains reachable. This pins the actual behavior: keyed
// replacement constrains the KEY, not the address, and reviewers of overlay
// fragments must treat new Identifiers on known addresses as grants.
func TestStacking_AliasedKeyBypassesReplacement(t *testing.T) {
	mk := func(id, ip string, port int32) v1beta1.NetworkNeighbor {
		return v1beta1.NetworkNeighbor{
			Identifier: id, Type: "external", IPAddress: ip,
			Ports: []v1beta1.NetworkPort{{Name: "TCP", Port: &port, Protocol: "TCP"}},
		}
	}
	vendor, ov := genKey(t), genKey(t)
	base := fragment(t, "app", "base", v1beta1.ContainerProfileSpec{
		Egress: []v1beta1.NetworkNeighbor{mk("db", "10.0.0.5", 5432)},
	}, vendor)
	overlay := fragment(t, "app-alias", "overlay", v1beta1.ContainerProfileSpec{
		Egress: []v1beta1.NetworkNeighbor{
			mk("db", "10.0.0.5", 5433),        // replaces the key: 5432 -> 5433
			mk("db-legacy", "10.0.0.5", 5432), // aliases the old grant back in
		},
	}, ov)
	policy := stackPolicy(signerIDOf(t, base), signerIDOf(t, base), signerIDOf(t, overlay))

	composite, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, overlay}, policy)
	if err != nil {
		t.Fatalf("AssembleAndVerify: %v", err)
	}
	if len(composite.Spec.Egress) != 2 {
		t.Fatalf("alias adds a second entry for the same address: %+v", composite.Spec.Egress)
	}
	allowed := map[int32]bool{}
	for _, e := range composite.Spec.Egress {
		if e.IPAddress == "10.0.0.5" {
			for _, p := range e.Ports {
				allowed[*p.Port] = true
			}
		}
	}
	if !allowed[5433] || !allowed[5432] {
		t.Fatalf("effective allow-set for 10.0.0.5 is the union over entries: %v", allowed)
	}
}

// W3: near-duplicate additive entries BALLOON — jsonKey dedup is byte-exact,
// so arg variants of one path all survive, and same-path opens with different
// flags are kept as separate entries (flags are NOT merged during assembly,
// unlike storage's learned-profile merge which folds flags per path).
func TestStacking_NearDuplicatesBalloonNotMerge(t *testing.T) {
	vendor, ov := genKey(t), genKey(t)
	base := fragment(t, "app", "base", v1beta1.ContainerProfileSpec{
		Execs: []v1beta1.ExecCalls{{Path: "/bin/sh", Args: []string{"-c", "a"}}},
		Opens: []v1beta1.OpenCalls{{Path: "/etc/cfg", Flags: []string{"O_RDONLY"}}},
	}, vendor)
	overlay := fragment(t, "app-near", "overlay", v1beta1.ContainerProfileSpec{
		Execs: []v1beta1.ExecCalls{
			{Path: "/bin/sh", Args: []string{"-c", "b"}}, // variant -> kept
			{Path: "/bin/sh", Args: []string{"-c", "a"}}, // exact dup -> folded
		},
		Opens: []v1beta1.OpenCalls{{Path: "/etc/cfg", Flags: []string{"O_RDWR"}}}, // same path, new flags -> kept
	}, ov)
	policy := stackPolicy(signerIDOf(t, base), signerIDOf(t, base), signerIDOf(t, overlay))

	composite, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, overlay}, policy)
	if err != nil {
		t.Fatalf("AssembleAndVerify: %v", err)
	}
	if len(composite.Spec.Execs) != 2 {
		t.Errorf("arg variants of one path are distinct entries (exact dup folds): got %d, want 2", len(composite.Spec.Execs))
	}
	if len(composite.Spec.Opens) != 2 {
		t.Errorf("same-path opens with different flags stay separate (no flag merge at assembly): got %d, want 2", len(composite.Spec.Opens))
	}
}

// W4: rulePolicies maps with PARTIAL key overlap — overlapping IDs replaced,
// disjoint IDs from both sides survive.
func TestStacking_RulePoliciesPartialOverlap(t *testing.T) {
	vendor, ov := genKey(t), genKey(t)
	base := fragment(t, "app", "base", v1beta1.ContainerProfileSpec{
		PolicyByRuleId: map[string]v1beta1.RulePolicy{
			"R0001": {AllowedProcesses: []string{"/bin/a"}},
			"R0004": {AllowedProcesses: []string{"/bin/b"}},
			"R0011": {AllowedContainer: true},
		},
	}, vendor)
	overlay := fragment(t, "app-pol2", "overlay", v1beta1.ContainerProfileSpec{
		PolicyByRuleId: map[string]v1beta1.RulePolicy{
			"R0004": {AllowedProcesses: []string{"/bin/x"}},
			"R0999": {AllowedContainer: true},
		},
	}, ov)
	policy := stackPolicy(signerIDOf(t, base), signerIDOf(t, base), signerIDOf(t, overlay))

	composite, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, overlay}, policy)
	if err != nil {
		t.Fatalf("AssembleAndVerify: %v", err)
	}
	got := composite.Spec.PolicyByRuleId
	if len(got) != 4 {
		t.Fatalf("partial overlap must keep 4 rule IDs: %v", got)
	}
	if got["R0004"].AllowedProcesses[0] != "/bin/x" {
		t.Errorf("overlapping ID replaced wholly: %v", got["R0004"])
	}
	if got["R0001"].AllowedProcesses[0] != "/bin/a" || !got["R0011"].AllowedContainer || !got["R0999"].AllowedContainer {
		t.Errorf("disjoint IDs from both sides must survive: %v", got)
	}
}

// W5: two SAME-class overlays with disjoint AND colliding keys in one stack:
// disjoint keys union, the colliding key resolves deterministically across
// input orders.
func TestStacking_SameClassMultiFragmentMixedKeys(t *testing.T) {
	vendor, ka, kb := genKey(t), genKey(t), genKey(t)
	base := fragment(t, "app", "base", baseSpec(), vendor)
	ovA := fragment(t, "app-ov-a", "overlay", v1beta1.ContainerProfileSpec{
		Egress: []v1beta1.NetworkNeighbor{egressEntry("only-a", 1000), egressEntry("shared", 1111)},
	}, ka)
	ovB := fragment(t, "app-ov-b", "overlay", v1beta1.ContainerProfileSpec{
		Egress: []v1beta1.NetworkNeighbor{egressEntry("only-b", 2000), egressEntry("shared", 2222)},
	}, kb)
	policy := TrustPolicy{Classes: map[FragmentClass]ClassPolicy{
		ClassBase:    {Signers: []string{signerIDOf(t, base)}, AllowedSpecPaths: []string{"architectures", "execs", "opens"}},
		ClassOverlay: {Signers: []string{signerIDOf(t, ovA), signerIDOf(t, ovB)}, AllowedSpecPaths: []string{"egress"}},
	}}

	c1, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, ovA, ovB}, policy)
	if err != nil {
		t.Fatalf("AssembleAndVerify: %v", err)
	}
	c2, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{ovB, ovA, base}, policy)
	if err != nil {
		t.Fatalf("AssembleAndVerify: %v", err)
	}
	if len(c1.Spec.Egress) != 3 {
		t.Fatalf("disjoint keys union, colliding key collapses: %+v", c1.Spec.Egress)
	}
	if jsonKey(c1.Spec) != jsonKey(c2.Spec) {
		t.Errorf("same-class multi-fragment stack must be input-order invariant")
	}
}

// W7: selector and scalar precedence — matchLabels override-merge per key,
// matchExpressions APPEND (near-dups kept), scalars last-non-empty-writer
// (an empty higher-class value does NOT erase the base's).
func TestStacking_SelectorAndScalarPrecedence(t *testing.T) {
	vendor, ov := genKey(t), genKey(t)
	expr := metav1.LabelSelectorRequirement{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"db"}}
	base := fragment(t, "app", "base", v1beta1.ContainerProfileSpec{
		LabelSelector: metav1.LabelSelector{
			MatchLabels:      map[string]string{"app": "x", "tier": "db"},
			MatchExpressions: []metav1.LabelSelectorRequirement{expr},
		},
		ImageID:  "sha256:base-id",
		ImageTag: "registry/app:1.0",
	}, vendor)
	overlay := fragment(t, "app-sel", "overlay", v1beta1.ContainerProfileSpec{
		LabelSelector: metav1.LabelSelector{
			MatchLabels:      map[string]string{"tier": "cache", "extra": "1"},
			MatchExpressions: []metav1.LabelSelectorRequirement{expr}, // exact dup — appended anyway
		},
		ImageTag: "registry/app:2.0", // overrides
		// ImageID deliberately empty — must NOT erase the base's
	}, ov)
	policy := stackPolicy(signerIDOf(t, base), signerIDOf(t, base), signerIDOf(t, overlay))

	composite, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, overlay}, policy)
	if err != nil {
		t.Fatalf("AssembleAndVerify: %v", err)
	}
	ml := composite.Spec.MatchLabels
	if ml["app"] != "x" || ml["tier"] != "cache" || ml["extra"] != "1" {
		t.Errorf("matchLabels override-merge per key: %v", ml)
	}
	if len(composite.Spec.MatchExpressions) != 2 {
		t.Errorf("matchExpressions APPEND without dedup (2 copies of the same expr): got %d", len(composite.Spec.MatchExpressions))
	}
	if composite.Spec.ImageTag != "registry/app:2.0" {
		t.Errorf("scalar last-writer: ImageTag = %q", composite.Spec.ImageTag)
	}
	if composite.Spec.ImageID != "sha256:base-id" {
		t.Errorf("empty higher-class scalar must not erase the base's: ImageID = %q", composite.Spec.ImageID)
	}
}
