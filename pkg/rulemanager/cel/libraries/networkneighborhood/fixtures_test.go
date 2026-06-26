package networkneighborhood

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

// TestFixturesParse validates that every YAML fixture under
// tests/resources/network-wildcards/ parses against the v1beta1
// NetworkNeighborhood schema. This is the user-facing-examples gate:
// the fixtures double as authoritative syntax documentation, so a
// fixture that fails to parse is a documentation bug.
//
// Fixture 14 (recursive-star-rejected) parses but its dnsNames entry
// '**' is rejected at admission time — see the storage REST strategy
// validation test (TestValidate_NetworkProfileEntries).
func TestFixturesParse(t *testing.T) {
	fixturesDir := findFixturesDir(t)
	entries, err := os.ReadDir(fixturesDir)
	require.NoError(t, err)

	if len(entries) == 0 {
		t.Fatalf("no fixtures found under %s", fixturesDir)
	}

	parsed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(fixturesDir, name))
			require.NoError(t, err)

			// Strip the literal "{{NAMESPACE}}" placeholder; the fixtures
			// are templates, runtime substitutes a real namespace.
			data = []byte(strings.ReplaceAll(string(data), "{{NAMESPACE}}", "test-ns"))

			var nn v1beta1.NetworkNeighborhood
			// Strict mode: any unknown field in a fixture is a typo
			// against the v1beta1 schema. Documentation must not drift
			// from the runtime types.
			err = yaml.UnmarshalStrict(data, &nn)
			require.NoError(t, err, "fixture %s must parse against v1beta1 schema (strict)", name)
			require.Equal(t, "NetworkNeighborhood", nn.Kind, "fixture %s wrong kind", name)
			require.NotEmpty(t, nn.Spec.Containers, "fixture %s should declare at least one container", name)
		})
		parsed++
	}
	if parsed < 20 {
		t.Errorf("expected ≥ 20 fixtures, parsed %d", parsed)
	}
}

// TestFixturesMatchExpectedBehaviour walks a curated subset of fixtures
// through the actual CEL library matchers, asserting the documented
// observed→match behaviour from each fixture's header comment.
//
// This is the contract pin between the user-facing examples and the
// runtime: if a fixture says "10.1.2.3 → match" and the matcher
// disagrees, ONE of them is wrong. Today both are pinned by this test.
//
// Coverage: representative cases for each major edge case. Not every
// (fixture × observation) is exercised — that would be brittle as
// the fixtures evolve.
func TestFixturesMatchExpectedBehaviour(t *testing.T) {
	cases := []struct {
		name      string
		neighbors []v1beta1.NetworkNeighbor
		ingress   []v1beta1.NetworkNeighbor
		// ipChecks verifies wasAddressInEgress only (back-compat for cases
		// with no ingress declared; runs only the egress matcher).
		ipChecks []ipCheck
		// ipBothChecks verifies BOTH wasAddressInEgress and wasAddressInIngress
		// — used for direction-isolation cases so the assertion goes both ways.
		ipBothChecks []ipBothCheck
		dnsChecks    []dnsCheck
	}{
		{
			name: "fixture-01-literal-ipv4",
			neighbors: []v1beta1.NetworkNeighbor{
				{IPAddresses: []string{"10.1.2.3"}},
			},
			ipChecks: []ipCheck{
				{"10.1.2.3", true},
				{"10.1.2.4", false},
			},
		},
		{
			name: "fixture-03-cidr-ipv4",
			neighbors: []v1beta1.NetworkNeighbor{
				{IPAddresses: []string{"10.0.0.0/8"}},
			},
			ipChecks: []ipCheck{
				{"10.0.0.0", true},
				{"10.255.255.255", true},
				{"11.0.0.1", false},
			},
		},
		{
			name: "fixture-05-any-ip-sentinel",
			neighbors: []v1beta1.NetworkNeighbor{
				{IPAddresses: []string{"*"}},
			},
			ipChecks: []ipCheck{
				{"1.2.3.4", true},
				{"::1", true},
			},
		},
		{
			name: "fixture-08-deprecated-ipaddress",
			neighbors: []v1beta1.NetworkNeighbor{
				{IPAddress: "10.1.2.3"}, // singular, deprecated form
			},
			ipChecks: []ipCheck{
				{"10.1.2.3", true},
				{"10.1.2.4", false},
			},
		},
		{
			name: "fixture-10-dns-leading-wildcard",
			neighbors: []v1beta1.NetworkNeighbor{
				{DNSNames: []string{"*.example.com."}},
			},
			dnsChecks: []dnsCheck{
				{"api.example.com.", true},
				{"v1.api.example.com.", false}, // RFC 4592: exactly one label
				{"example.com.", false},        // zero labels
			},
		},
		{
			name: "fixture-18-cluster-dns-mid-ellipsis",
			neighbors: []v1beta1.NetworkNeighbor{
				{DNSNames: []string{"kubernetes.⋯.svc.cluster.local."}},
			},
			dnsChecks: []dnsCheck{
				{"kubernetes.default.svc.cluster.local.", true},
				{"kubernetes.kube-system.svc.cluster.local.", true},
				{"redis.default.svc.cluster.local.", false},
			},
		},
		{
			name: "fixture-15-egress-and-ingress-direction-isolation",
			neighbors: []v1beta1.NetworkNeighbor{
				{IPAddresses: []string{"8.8.8.8"}},
			},
			ingress: []v1beta1.NetworkNeighbor{
				{IPAddresses: []string{"10.244.0.0/16"}},
			},
			// Direction isolation: each address MUST hit only the direction
			// it was declared on. CR (node-agent#41) flagged that the prior
			// version only checked egress; this asserts ingress too.
			ipBothChecks: []ipBothCheck{
				{observed: "8.8.8.8", wantEgress: true, wantIngress: false},      // egress-only
				{observed: "10.244.5.5", wantEgress: false, wantIngress: true},   // ingress-only
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lib := buildLibWithContainer(t, tc.neighbors, tc.ingress)
			for _, c := range tc.ipChecks {
				res := lib.wasAddressInEgress(types.String("cid"), types.String(c.observed))
				res = cache.ConvertProfileNotAvailableErrToBool(res, false)
				if res != types.Bool(c.want) {
					t.Errorf("egress ip %q: got %v, want %v", c.observed, res, c.want)
				}
			}
			for _, c := range tc.ipBothChecks {
				eg := lib.wasAddressInEgress(types.String("cid"), types.String(c.observed))
				eg = cache.ConvertProfileNotAvailableErrToBool(eg, false)
				if eg != types.Bool(c.wantEgress) {
					t.Errorf("egress ip %q: got %v, want %v", c.observed, eg, c.wantEgress)
				}
				in := lib.wasAddressInIngress(types.String("cid"), types.String(c.observed))
				in = cache.ConvertProfileNotAvailableErrToBool(in, false)
				if in != types.Bool(c.wantIngress) {
					t.Errorf("ingress ip %q: got %v, want %v", c.observed, in, c.wantIngress)
				}
			}
			for _, c := range tc.dnsChecks {
				res := lib.isDomainInEgress(types.String("cid"), types.String(c.observed))
				res = cache.ConvertProfileNotAvailableErrToBool(res, false)
				if res != types.Bool(c.want) {
					t.Errorf("dns %q: got %v, want %v", c.observed, res, c.want)
				}
			}
		})
	}
}

type ipCheck struct {
	observed string
	want     bool
}

type ipBothCheck struct {
	observed    string
	wantEgress  bool
	wantIngress bool
}

type dnsCheck struct {
	observed string
	want     bool
}

// findFixturesDir walks up from the test's working directory to locate
// tests/resources/network-wildcards/. The package's own working dir
// when `go test` runs is its source dir, so we walk up to find the
// repo root.
func findFixturesDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for i := 0; i < 10; i++ {
		candidate := filepath.Join(dir, "tests", "resources", "network-wildcards")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not find tests/resources/network-wildcards/ from %s", dir)
	return ""
}
