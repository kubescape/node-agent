// Lints tests/resources/ network fixtures (ContainerProfile egress/ingress, flat + grouped) against the v0.0.2 endpoint grammar. Catches malformed authoring fixtures before they reach a cluster.
//
// Runs as a regular `go test ./...` — no component tag, no kind cluster.
//
// LintNetworkProfileYAML is exported and returns []NetViolation rather than
// calling t.Errorf directly, so this file can be lifted verbatim into a bobctl
// subcommand `bobctl lint <profile.yaml>` with no testing-package dependency.
// The Test_* functions below are thin wrappers that turn violations into
// t.Errorf calls. Identifiers are net-prefixed so this coexists with
// aplint_test.go's Violation / templatePlaceholderRe in the same package.
package resources

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// netTemplatePlaceholderRe matches an unsubstituted template token such as
// {name} or {namespace}: a flow scalar {identifier} with no colon, which never
// appears in a concrete applied resource. Such fixtures are rendered at runtime
// via substitution and cannot be strict-parsed as-is, so the directory scan
// skips them. The linter itself stays strict for real callers like bobctl.
var netTemplatePlaceholderRe = regexp.MustCompile(`\{[a-zA-Z_][a-zA-Z0-9_]*\}`)

// dnsWildcardLabel is the one-label DynamicIdentifier ("⋯", U+22EF) and the
// leading/trailing RFC-4592 wildcard ("*"). Both are valid ONLY as a whole DNS
// label; embedded in a longer label (e.g. "**", "*foo", "⋯⋯") they are invalid.
// Mirrors storage/pkg/registry/file/dynamicpathdetector; duplicated so this
// linter has zero dependency on the storage module.
const (
	dnsDynamicLabel  = "⋯"
	dnsWildcardLabel = "*"
)

// netProfileLike captures only the network fields we lint. We do not import the
// storage v1beta1 types so the linter runs in isolation (bobctl, CI, etc).
// Both surfaces are accepted: ContainerProfile puts egress/ingress directly on
// spec; NetworkNeighborhood nests them under spec.containers[].
type netProfileLike struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Egress     []netEndpoint `json:"egress"`
		Ingress    []netEndpoint `json:"ingress"`
		Containers []struct {
			Name    string        `json:"name"`
			Egress  []netEndpoint `json:"egress"`
			Ingress []netEndpoint `json:"ingress"`
		} `json:"containers"`
	} `json:"spec"`
}

type netEndpoint struct {
	Identifier  string    `json:"identifier"`
	Type        string    `json:"type"`
	DNS         string    `json:"dns"`      // deprecated singular
	DNSNames    []string  `json:"dnsNames"` // v0.0.2 list form
	IPAddress   string    `json:"ipAddress"`
	IPAddresses []string  `json:"ipAddresses"`
	Ports       []netPort `json:"ports"`
	// Selector-based targets (translate to NetworkPolicy egress rules). Raw
	// so the linter needn't import metav1; presence (non-null) counts as a
	// declared target for R-NN-12.
	PodSelector       json.RawMessage `json:"podSelector"`
	NamespaceSelector json.RawMessage `json:"namespaceSelector"`
}

// hasSelector reports whether a raw selector field was set to a real object
// (not absent, not explicit null).
func hasSelector(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "null"
}

type netPort struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

// NetViolation is a single rule failure. Returned as data so callers can treat
// lint output however they like (CLI exit code, JSON, t.Errorf).
type NetViolation struct {
	Rule string
	Path string
	Msg  string
}

func (v NetViolation) String() string {
	if v.Path != "" {
		return fmt.Sprintf("[%s] %s: %s", v.Rule, v.Path, v.Msg)
	}
	return fmt.Sprintf("[%s] %s", v.Rule, v.Msg)
}

// LintNetworkProfileYAML parses one YAML doc as a network profile and runs all
// rules. Empty slice == clean. Pure function — no I/O, no testing coupling.
//
// Rule IDs:
//
//	R-NN-00 — yaml parse failure
//	R-NN-01 — kind must be ContainerProfile or NetworkNeighborhood
//	R-NN-02 — at least one endpoint (egress or ingress) declared
//	R-NN-10 — endpoint identifier non-empty
//	R-NN-11 — endpoint type in {internal, external} (or unset)
//	R-NN-12 — endpoint declares at least one target (dnsNames/ipAddresses/dns/ipAddress)
//	R-NN-13 — dnsNames wildcard tokens are whole-label; no recursive "**", no ascii "..."
//	R-NN-14 — an entry MUST NOT set both singular ipAddress and plural ipAddresses
//	R-NN-15 — ipAddresses entries are a literal IP, a CIDR, or the "*" sentinel
//	R-NN-20 — ports use TCP/UDP and a port in 1..65535
func LintNetworkProfileYAML(doc []byte, sourceLabel string) []NetViolation {
	var np netProfileLike
	if err := yaml.Unmarshal(doc, &np); err != nil {
		return []NetViolation{{Rule: "R-NN-00", Path: sourceLabel, Msg: fmt.Sprintf("yaml parse: %v", err)}}
	}
	return LintNetworkProfile(&np, sourceLabel)
}

// LintNetworkProfile runs every rule against an already-parsed profile.
func LintNetworkProfile(np *netProfileLike, src string) []NetViolation {
	var v []NetViolation
	add := func(rule, msg string) { v = append(v, NetViolation{Rule: rule, Path: src, Msg: msg}) }

	if np.Kind != "ContainerProfile" && np.Kind != "NetworkNeighborhood" {
		add("R-NN-01", fmt.Sprintf("kind is %q, expected ContainerProfile or NetworkNeighborhood", np.Kind))
	}

	// Gather endpoints from both surfaces, labelling direction.
	type dirEP struct {
		dir string
		ep  netEndpoint
	}
	var eps []dirEP
	for _, e := range np.Spec.Egress {
		eps = append(eps, dirEP{"egress", e})
	}
	for _, e := range np.Spec.Ingress {
		eps = append(eps, dirEP{"ingress", e})
	}
	for _, c := range np.Spec.Containers {
		for _, e := range c.Egress {
			eps = append(eps, dirEP{"containers[" + c.Name + "].egress", e})
		}
		for _, e := range c.Ingress {
			eps = append(eps, dirEP{"containers[" + c.Name + "].ingress", e})
		}
	}
	if len(eps) == 0 {
		add("R-NN-02", "no egress or ingress endpoints declared")
	}

	for _, de := range eps {
		lintEndpoint(de.dir, de.ep, add)
	}
	return v
}

func lintEndpoint(dir string, e netEndpoint, add func(rule, msg string)) {
	where := func(msg string) string { return fmt.Sprintf("%s[%s]: %s", dir, e.Identifier, msg) }

	if strings.TrimSpace(e.Identifier) == "" {
		add("R-NN-10", dir+": endpoint has empty identifier")
	}
	if e.Type != "" && e.Type != "internal" && e.Type != "external" {
		add("R-NN-11", where(fmt.Sprintf("type %q is not internal|external", e.Type)))
	}
	if len(e.DNSNames) == 0 && len(e.IPAddresses) == 0 && e.DNS == "" && e.IPAddress == "" &&
		!hasSelector(e.PodSelector) && !hasSelector(e.NamespaceSelector) {
		add("R-NN-12", where("endpoint declares no target (dnsNames/ipAddresses/dns/ipAddress/selector)"))
	}
	if e.IPAddress != "" && len(e.IPAddresses) > 0 {
		add("R-NN-14", where("sets both singular ipAddress and plural ipAddresses — pick one"))
	}

	if e.DNS != "" {
		if msg := dnsNameProblem(e.DNS); msg != "" {
			add("R-NN-13", where(fmt.Sprintf("dns %q: %s", e.DNS, msg)))
		}
	}
	for _, d := range e.DNSNames {
		if msg := dnsNameProblem(d); msg != "" {
			add("R-NN-13", where(fmt.Sprintf("dnsName %q: %s", d, msg)))
		}
	}
	if e.IPAddress != "" && !validIPEntry(e.IPAddress) {
		add("R-NN-15", where(fmt.Sprintf("ipAddress %q is not an IP, CIDR, or \"*\" sentinel", e.IPAddress)))
	}
	for _, ip := range e.IPAddresses {
		if !validIPEntry(ip) {
			add("R-NN-15", where(fmt.Sprintf("ipAddresses entry %q is not an IP, CIDR, or \"*\" sentinel", ip)))
		}
	}
	for _, p := range e.Ports {
		if p.Protocol != "TCP" && p.Protocol != "UDP" {
			add("R-NN-20", where(fmt.Sprintf("port %q protocol %q is not TCP|UDP", p.Name, p.Protocol)))
		}
		// Port 0 is the any-port wildcard (matches R0011/R0012 port semantics).
		if p.Port != 0 && (p.Port < 1 || p.Port > 65535) {
			add("R-NN-20", where(fmt.Sprintf("port %q value %d out of range 1..65535 (0 = any)", p.Name, p.Port)))
		}
	}
}

// dnsNameProblem returns "" if the DNS name is well-formed, else a reason.
// Trailing-dot is NOT required (it is normalised on read; fixtures 12/13 omit
// it deliberately). Wildcard tokens must be whole labels.
func dnsNameProblem(d string) string {
	if d == "" {
		return "empty"
	}
	if strings.Contains(d, "...") {
		return `contains "..." — use the single-codepoint ellipsis "⋯" (U+22EF) for a mid-label wildcard`
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" {
			continue // apex / trailing-dot slot
		}
		if strings.Contains(label, dnsWildcardLabel) && label != dnsWildcardLabel {
			return fmt.Sprintf("label %q — %q is valid only as a whole label (no %q, %q, etc.)",
				label, dnsWildcardLabel, "**", "*foo")
		}
		if strings.Contains(label, dnsDynamicLabel) && label != dnsDynamicLabel {
			return fmt.Sprintf("label %q — %q is valid only as a whole label", label, dnsDynamicLabel)
		}
	}
	return ""
}

// validIPEntry accepts a literal IP, a CIDR (a.b.c.d/n or v6), or "*" (the
// any-IP sentinel = 0.0.0.0/0 ∪ ::/0).
func validIPEntry(s string) bool {
	if s == "*" {
		return true
	}
	if net.ParseIP(s) != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return false
}

// --- Test wrappers over the fixture directories ---

// netFixtureGlobs are the user-authored network surfaces to lint, relative to
// this package directory (tests/resources).
var netFixtureGlobs = []string{
	"network-wildcards/*.yaml",
	"containerprofile-*-network.yaml",
}

// intentionallyInvalid maps a fixture basename to the rule its doc MUST trip —
// the mirror of aplint's malformed-variant assertions. Everything else must be
// clean.
var intentionallyInvalid = map[string]string{
	"14-recursive-star-rejected.yaml": "R-NN-13",
}

// Test_NN_LinterCatches feeds one deliberately-broken doc per rule and asserts
// the matching rule fires — proving the fixture-clean pass above is meaningful.
func Test_NN_LinterCatches(t *testing.T) {
	const head = "apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1\nkind: ContainerProfile\nmetadata:\n  name: bad\nspec:\n"
	cases := []struct {
		rule string
		doc  string
	}{
		{"R-NN-01", "kind: Pod\nmetadata:\n  name: x\nspec:\n  egress:\n  - {identifier: a, dnsNames: [\"x.io.\"]}"},
		{"R-NN-02", head + "  matchLabels: {app: x}"},
		{"R-NN-10", head + "  egress:\n  - {dnsNames: [\"x.io.\"]}"},
		{"R-NN-11", head + "  egress:\n  - {identifier: a, type: sideways, dnsNames: [\"x.io.\"]}"},
		{"R-NN-12", head + "  egress:\n  - {identifier: a}"},
		{"R-NN-13", head + "  egress:\n  - {identifier: a, dnsNames: [\"**.example.com.\"]}"},
		{"R-NN-13", head + "  egress:\n  - {identifier: a, dnsNames: [\"svc.*foo.local.\"]}"},
		{"R-NN-13", head + "  egress:\n  - {identifier: a, dnsNames: [\"svc...local.\"]}"},
		{"R-NN-14", head + "  egress:\n  - {identifier: a, ipAddress: \"1.2.3.4\", ipAddresses: [\"1.2.3.4\"]}"},
		{"R-NN-15", head + "  egress:\n  - {identifier: a, ipAddresses: [\"not-an-ip\"]}"},
		{"R-NN-20", head + "  egress:\n  - {identifier: a, dnsNames: [\"x.io.\"], ports: [{name: p, protocol: SCTP, port: 80}]}"},
		{"R-NN-20", head + "  egress:\n  - {identifier: a, dnsNames: [\"x.io.\"], ports: [{name: p, protocol: TCP, port: 70000}]}"},
	}
	for _, c := range cases {
		vs := LintNetworkProfileYAML([]byte(c.doc), c.rule)
		found := false
		for _, v := range vs {
			if v.Rule == c.rule {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %s to fire, got %v\n--- doc ---\n%s", c.rule, vs, c.doc)
		}
	}
}

func Test_NN_FixturesLintClean(t *testing.T) {
	var files []string
	for _, g := range netFixtureGlobs {
		m, err := filepath.Glob(g)
		if err != nil {
			t.Fatalf("glob %q: %v", g, err)
		}
		files = append(files, m...)
	}
	if len(files) == 0 {
		t.Fatal("no network fixtures matched — wrong working dir?")
	}

	for _, f := range files {
		base := filepath.Base(f)
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Errorf("%s: read: %v", base, err)
			continue
		}
		if netTemplatePlaceholderRe.Match(raw) {
			t.Logf("%s: skipped (unrendered template placeholder)", base)
			continue
		}
		for i, doc := range strings.Split(string(raw), "\n---") {
			if strings.TrimSpace(doc) == "" {
				continue
			}
			vs := LintNetworkProfileYAML([]byte(doc), fmt.Sprintf("%s#%d", base, i))
			if wantRule, bad := intentionallyInvalid[base]; bad {
				found := false
				for _, v := range vs {
					if v.Rule == wantRule {
						found = true
					}
				}
				if !found {
					t.Errorf("%s: expected a %s violation (fixture is deliberately invalid), got %v", base, wantRule, vs)
				}
				continue
			}
			for _, v := range vs {
				t.Errorf("%s", v)
			}
		}
	}
}
