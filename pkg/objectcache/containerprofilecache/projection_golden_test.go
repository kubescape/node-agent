package containerprofilecache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/objectcache/callstackcache"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// This file adds a golden-corpus CHARACTERIZATION oracle for Apply.
//
// HONEST SCOPE — this is NOT a differential oracle. A true differential
// oracle would run the same inputs through the legacy ApplicationProfile /
// NetworkNeighborhood projection and assert byte-identical results. That is
// impossible here: those legacy types and their projection code were deleted
// in the ContainerProfile migration, so there is no second implementation to
// diff against. What this file provides instead is a regression / freeze
// oracle: it pins the EXACT projected output of the current Apply across a
// representative corpus of ContainerProfiles + compiled specs. Any later
// change to the projection that alters the output for these fixtures fails the
// oracle, forcing a deliberate golden regeneration and review. It complements
// (does not replace) the assertion-based TestApply_* property tests in
// projection_apply_test.go, which pin individual behaviours; this file pins
// the whole-profile shape.
//
// Regenerate goldens after an INTENTIONAL projection change:
//
//	UPDATE_GOLDEN=1 go test ./pkg/objectcache/containerprofilecache/ -run TestApply_Golden -count=1
//
// then review the diff under testdata/golden/ before committing.

// projectionGolden is the serializable view of a ProjectedContainerProfile.
//
// We do NOT marshal *objectcache.ProjectedContainerProfile directly: its
// CallStackTree field is a *callstackcache.CallStackSearchTree whose
// BidirectionalNode carries a Parent back-pointer (a reference cycle) and an
// internal dghubble/trie — neither of which json.Marshal can encode (a cycle
// errors; the trie has no stable exported shape). Instead we copy every
// marshalable projected surface verbatim and reduce the call-stack tree to a
// deterministic summary (sorted CallIDs with per-path frame depths). The
// surfaces that Apply actually computes are frozen byte-for-byte; the tree —
// which Apply only stores by pointer, it does not transform it — is pinned by
// its structural summary. Go's json encoder emits map keys in sorted order, so
// Values / PrefixHits / SuffixHits / ExecsByPath / PolicyByRuleId all
// serialize canonically without extra work.
type projectionGolden struct {
	SpecHash         string                        `json:"specHash"`
	SyncChecksum     string                        `json:"syncChecksum"`
	Opens            objectcache.ProjectedField    `json:"opens"`
	Execs            objectcache.ProjectedField    `json:"execs"`
	Endpoints        objectcache.ProjectedField    `json:"endpoints"`
	Capabilities     objectcache.ProjectedField    `json:"capabilities"`
	Syscalls         objectcache.ProjectedField    `json:"syscalls"`
	EgressDomains    objectcache.ProjectedField    `json:"egressDomains"`
	EgressAddresses  objectcache.ProjectedField    `json:"egressAddresses"`
	IngressDomains   objectcache.ProjectedField    `json:"ingressDomains"`
	IngressAddresses objectcache.ProjectedField    `json:"ingressAddresses"`
	ExecsByPath      map[string][][]string         `json:"execsByPath"`
	PolicyByRuleId   map[string]v1beta1.RulePolicy `json:"policyByRuleId"`
	CallStacks       []callStackSummary            `json:"callStacks"`
}

// callStackSummary is a deterministic structural digest of one identified
// call stack held in the search tree.
type callStackSummary struct {
	CallID     string `json:"callID"`
	PathCount  int    `json:"pathCount"`
	PathDepths []int  `json:"pathDepths"`
}

// toGolden converts a projected profile plus its (pre-built) call-stack tree
// into the serializable golden view.
func toGolden(pcp *objectcache.ProjectedContainerProfile, tree *callstackcache.CallStackSearchTree) projectionGolden {
	g := projectionGolden{
		SpecHash:         pcp.SpecHash,
		SyncChecksum:     pcp.SyncChecksum,
		Opens:            pcp.Opens,
		Execs:            pcp.Execs,
		Endpoints:        pcp.Endpoints,
		Capabilities:     pcp.Capabilities,
		Syscalls:         pcp.Syscalls,
		EgressDomains:    pcp.EgressDomains,
		EgressAddresses:  pcp.EgressAddresses,
		IngressDomains:   pcp.IngressDomains,
		IngressAddresses: pcp.IngressAddresses,
		ExecsByPath:      pcp.ExecsByPath,
		PolicyByRuleId:   pcp.PolicyByRuleId,
	}
	if tree != nil {
		for id, paths := range tree.PathsByCallID {
			depths := make([]int, len(paths))
			for i, p := range paths {
				depths[i] = len(p)
			}
			sort.Ints(depths)
			g.CallStacks = append(g.CallStacks, callStackSummary{
				CallID:     string(id),
				PathCount:  len(paths),
				PathDepths: depths,
			})
		}
		sort.Slice(g.CallStacks, func(i, j int) bool {
			return g.CallStacks[i].CallID < g.CallStacks[j].CallID
		})
	}
	return g
}

// --- fixture construction helpers ---

// declaredAll returns a FieldRequirement declaring the whole surface.
func declaredAll() typesv1.FieldRequirement {
	return typesv1.FieldRequirement{Declared: true, All: true}
}

// declaredPatterns returns a FieldRequirement declaring a set of pattern
// selectors (exact / prefix / suffix / contains).
func declaredPatterns(pats ...typesv1.PatternObject) typesv1.FieldRequirement {
	return typesv1.FieldRequirement{Declared: true, Patterns: pats}
}

// linearCallStack builds a single-path identified call stack from an ordered
// list of {fileID, lineno} frames. Root carries an empty frame (the
// tree-builder skips it), so the frames become one leaf path.
func linearCallStack(id string, frames [][2]string) v1beta1.IdentifiedCallStack {
	var children []v1beta1.CallStackNode
	for i := len(frames) - 1; i >= 0; i-- {
		children = []v1beta1.CallStackNode{{
			Frame:    v1beta1.StackFrame{FileID: frames[i][0], Lineno: frames[i][1]},
			Children: children,
		}}
	}
	return v1beta1.IdentifiedCallStack{
		CallID: v1beta1.CallID(id),
		CallStack: v1beta1.CallStack{
			Root: v1beta1.CallStackNode{Children: children},
		},
	}
}

// buildTree assembles the call-stack search tree Apply expects the caller to
// have built from cp.Spec.IdentifiedCallStacks.
func buildTree(cp *v1beta1.ContainerProfile) *callstackcache.CallStackSearchTree {
	if len(cp.Spec.IdentifiedCallStacks) == 0 {
		return nil
	}
	tree := callstackcache.NewCallStackSearchTree()
	for _, cs := range cp.Spec.IdentifiedCallStacks {
		tree.AddCallStack(cs)
	}
	return tree
}

// dyn is the single-segment dynamic identifier ("⋯"); wild is the
// zero-or-more wildcard ("*"). Always sourced from the storage constants so
// the fixtures stay pinned to whatever glyphs the detector uses.
var (
	dyn  = dynamicpathdetector.DynamicIdentifier
	wild = dynamicpathdetector.WildcardIdentifier
)

// richProfile is a ContainerProfile exercising every surface Apply projects:
// execs (Args, ArgsRequired, a literal "*" arg, an "⋯" ellipsis arg, and a
// nil-Args entry), opens (a plain path, a trailing-"*" path, an "⋯"
// dynamic-segment path, and a suffix-matchable path), syscalls, capabilities,
// HTTP endpoints, network ingress/egress (IPAddresses incl. a literal, a CIDR
// and the "*" sentinel, plus DNS + DNSNames), identified call stacks, and
// PolicyByRuleId. It also carries the SyncChecksum annotation.
func richProfile() *v1beta1.ContainerProfile {
	return &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"kubescape.io/sync-checksum": "sync-abc123",
			},
		},
		Spec: v1beta1.ContainerProfileSpec{
			Capabilities: []string{"NET_ADMIN", "SYS_PTRACE"},
			Syscalls:     []string{"read", "write", "openat"},
			Execs: []v1beta1.ExecCalls{
				{Path: "/bin/ls", Args: []string{"-la", "/tmp"}},
				{Path: "/bin/curl", Args: []string{wild, "https://example.com"}, ArgsRequired: true},
				{Path: "/usr/bin/app", Args: []string{"run", dyn}, ArgsRequired: true},
				{Path: "/bin/echo", Args: nil},
			},
			Opens: []v1beta1.OpenCalls{
				{Path: "/etc/passwd", Flags: []string{"O_RDONLY"}},
				{Path: "/var/log/" + wild, Flags: []string{"O_RDONLY"}},
				{Path: "/data/" + dyn + "/config", Flags: []string{"O_RDONLY"}},
				{Path: "/etc/app.conf", Flags: []string{"O_RDONLY"}},
			},
			Endpoints: []v1beta1.HTTPEndpoint{
				{Endpoint: "/api/v1/health", Methods: []string{"GET"}},
				{Endpoint: "/metrics", Methods: []string{"GET"}},
			},
			Ingress: []v1beta1.NetworkNeighbor{
				{
					Identifier:  "ingress-1",
					DNSNames:    []string{"client.internal"},
					IPAddresses: []string{"10.0.0.5", "10.1.0.0/16", wild},
				},
			},
			Egress: []v1beta1.NetworkNeighbor{
				{
					Identifier:  "egress-1",
					DNSNames:    []string{"cdn.example.com"},
					IPAddresses: []string{"8.8.8.8", "0.0.0.0/0", wild},
				},
			},
			IdentifiedCallStacks: []v1beta1.IdentifiedCallStack{
				linearCallStack("cs-open-1", [][2]string{{"10", "100"}, {"20", "200"}, {"30", "300"}}),
				linearCallStack("cs-exec-1", [][2]string{{"11", "111"}, {"22", "222"}}),
			},
			PolicyByRuleId: map[string]v1beta1.RulePolicy{
				"R0001": {AllowedProcesses: []string{"cat", "ls"}},
				"R0002": {AllowedContainer: true},
			},
		},
	}
}

// networkProfile isolates the network surfaces so the golden pins address /
// domain projection independently of the file surfaces.
func networkProfile() *v1beta1.ContainerProfile {
	return &v1beta1.ContainerProfile{
		Spec: v1beta1.ContainerProfileSpec{
			Ingress: []v1beta1.NetworkNeighbor{
				{Identifier: "in-a", DNS: "old.internal", DNSNames: []string{"a.internal", "b.internal"}, IPAddresses: []string{"192.168.1.10", "192.168.0.0/16"}},
				{Identifier: "in-b", IPAddresses: []string{wild}},
			},
			Egress: []v1beta1.NetworkNeighbor{
				{Identifier: "eg-a", DNSNames: []string{"c.example.com"}, IPAddress: "203.0.113.7", IPAddresses: []string{"203.0.113.0/24", wild}},
			},
		},
	}
}

// --- rule sets that compile into representative specs ---

// mixedFilterRules declares multiple surfaces with a mix of selector kinds so
// CompileSpec produces a spec that actually filters:
//   - opens: exact + prefix + suffix + contains
//   - execs: all
//   - capabilities: exact
//   - syscalls: all
//   - endpoints: prefix
//   - egress/ingress domains + addresses: all
func mixedFilterRules() []typesv1.Rule {
	return []typesv1.Rule{
		{
			ID:   "RULE-A",
			Name: "mixed-file-and-net",
			ProfileDataRequired: &typesv1.ProfileDataRequired{
				Opens: declaredPatterns(
					typesv1.PatternObject{Exact: "/etc/passwd"},
					typesv1.PatternObject{Prefix: "/var/"},
					typesv1.PatternObject{Suffix: ".conf"},
					typesv1.PatternObject{Contains: "config"},
				),
				Execs:            declaredAll(),
				Capabilities:     declaredPatterns(typesv1.PatternObject{Exact: "NET_ADMIN"}),
				Syscalls:         declaredAll(),
				Endpoints:        declaredPatterns(typesv1.PatternObject{Prefix: "/api/"}),
				EgressDomains:    declaredAll(),
				EgressAddresses:  declaredAll(),
				IngressDomains:   declaredAll(),
				IngressAddresses: declaredAll(),
			},
		},
		{
			// A second rule narrows capabilities further and adds an opens
			// prefix, proving the union merge across rules.
			ID:   "RULE-B",
			Name: "extra-caps",
			ProfileDataRequired: &typesv1.ProfileDataRequired{
				Capabilities: declaredPatterns(typesv1.PatternObject{Exact: "SYS_PTRACE"}),
				Opens:        declaredPatterns(typesv1.PatternObject{Prefix: "/data/"}),
			},
		},
	}
}

// netAllRules declares the network surfaces as all-field so the network
// fixture projects every neighbour.
func netAllRules() []typesv1.Rule {
	return []typesv1.Rule{
		{
			ID:   "RULE-NET",
			Name: "net-all",
			ProfileDataRequired: &typesv1.ProfileDataRequired{
				EgressDomains:    declaredAll(),
				EgressAddresses:  declaredAll(),
				IngressDomains:   declaredAll(),
				IngressAddresses: declaredAll(),
			},
		},
	}
}

// --- the oracle ---

// goldenCase pairs a named fixture with the rules whose compiled spec drives
// its projection.
type goldenCase struct {
	name  string
	cp    *v1beta1.ContainerProfile
	rules []typesv1.Rule
}

func goldenCorpus() []goldenCase {
	return []goldenCase{
		// Rich profile under a filtering spec: every surface exercised, most
		// of them narrowed by selectors.
		{name: "rich_filtered", cp: richProfile(), rules: mixedFilterRules()},
		// Same rich profile under NO ProfileDataRequired: CompileSpec yields a
		// zero spec, so every surface is InUse=false → pass-through (All=true,
		// all raw data retained). Pins the back-compat path.
		{name: "rich_passthrough", cp: richProfile(), rules: nil},
		// Network-only profile under all-field network rules.
		{name: "network_all", cp: networkProfile(), rules: netAllRules()},
	}
}

// TestApply_Golden freezes the projected output of Apply across the corpus.
func TestApply_Golden(t *testing.T) {
	update := os.Getenv("UPDATE_GOLDEN") != ""

	for _, tc := range goldenCorpus() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			spec := CompileSpec(tc.rules)
			tree := buildTree(tc.cp)

			pcp := Apply(&spec, tc.cp, tree)
			require.NotNil(t, pcp)

			got, err := json.MarshalIndent(toGolden(pcp, tree), "", "  ")
			require.NoError(t, err, "projected profile must serialize")
			got = append(got, '\n')

			path := filepath.Join("testdata", "golden", tc.name+".json")

			if update {
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
				require.NoError(t, os.WriteFile(path, got, 0o644))
				t.Logf("wrote golden %s", path)
				return
			}

			want, err := os.ReadFile(path)
			require.NoError(t, err, "missing golden %s — regenerate with UPDATE_GOLDEN=1", path)
			assert.Equal(t, string(want), string(got),
				"projection drift for %q — if intentional, regenerate with UPDATE_GOLDEN=1 and review", tc.name)
		})
	}
}

// TestApply_Golden_Idempotent pins that Apply is a pure transform: applying
// the same spec + profile twice yields byte-identical projected output.
func TestApply_Golden_Idempotent(t *testing.T) {
	for _, tc := range goldenCorpus() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			spec := CompileSpec(tc.rules)
			tree := buildTree(tc.cp)

			first, err := json.MarshalIndent(toGolden(Apply(&spec, tc.cp, tree), tree), "", "  ")
			require.NoError(t, err)
			second, err := json.MarshalIndent(toGolden(Apply(&spec, tc.cp, tree), tree), "", "  ")
			require.NoError(t, err)

			assert.Equal(t, string(first), string(second),
				"Apply must be idempotent for %q", tc.name)
		})
	}
}

// TestApply_Golden_SpecHashStable pins that compiling the same rule set twice
// produces the same SpecHash, and that Apply copies it into the projection.
func TestApply_Golden_SpecHashStable(t *testing.T) {
	for _, tc := range goldenCorpus() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			specA := CompileSpec(tc.rules)
			specB := CompileSpec(tc.rules)
			assert.Equal(t, specA.Hash, specB.Hash,
				"CompileSpec must be deterministic for %q", tc.name)

			pcp := Apply(&specA, tc.cp, buildTree(tc.cp))
			assert.Equal(t, specA.Hash, pcp.SpecHash,
				"Apply must copy the spec hash into the projection for %q", tc.name)
		})
	}
}
