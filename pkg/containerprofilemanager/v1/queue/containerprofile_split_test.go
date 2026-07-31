package queue

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/names"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// tsRow is the reduced shape of storage's TimeSeriesContainers that
// consolidateContinuousTimeSeries actually branches on.
type tsRow struct {
	PreviousReportTimestamp string
	ReportTimestamp         string
}

// consolidateGolden is a line-by-line port of storage's consolidateContinuousTimeSeries
// (kubescape/storage@v0.0.290/pkg/registry/file/containerprofile_processor.go:631-659),
// reduced to the (previousReportTimestamp, reportTimestamp) pairs it actually branches on.
// Tests assert against this rather than against our own understanding of the algorithm, so a
// future storage change that invalidates the chaining shows up as a diff against a citable
// source rather than as a silent production hang.
func consolidateGolden(rows []tsRow) []tsRow {
	if len(rows) == 0 {
		return nil
	}

	// Storage mutates its slice in place; do the same over a copy so callers keep their rows.
	rows = append([]tsRow(nil), rows...)

	j := 0
	var result []tsRow

	for i := 0; i < len(rows)-1; i++ {
		// rows are in reverse chronological order
		if rows[j].PreviousReportTimestamp == rows[i+1].ReportTimestamp {
			rows[j].PreviousReportTimestamp = rows[i+1].PreviousReportTimestamp
		} else {
			result = append(result, rows[j])
			j = i + 1
		}
	}
	result = append(result, rows[j])

	return result
}

// assertChainIsLinear asserts that rows form exactly one path from origPrev to origRt: no two
// rows share a previousReportTimestamp, no two share a reportTimestamp, and following the
// links from origPrev visits every row exactly once and terminates at origRt.
func assertChainIsLinear(t *testing.T, rows []tsRow, origPrev, origRt string) {
	t.Helper()
	require.NotEmpty(t, rows)

	byPrev := make(map[string]tsRow, len(rows))
	seenRt := make(map[string]bool, len(rows))
	for _, r := range rows {
		_, dup := byPrev[r.PreviousReportTimestamp]
		require.False(t, dup, "two rows share previousReportTimestamp %q - the chain is forked", r.PreviousReportTimestamp)
		byPrev[r.PreviousReportTimestamp] = r

		require.False(t, seenRt[r.ReportTimestamp], "two rows share reportTimestamp %q - the chain is forked", r.ReportTimestamp)
		seenRt[r.ReportTimestamp] = true
	}

	cur := origPrev
	visited := 0
	for {
		row, ok := byPrev[cur]
		if !ok {
			break
		}
		cur = row.ReportTimestamp
		visited++
	}

	assert.Equal(t, len(rows), visited, "the chain must visit every row exactly once")
	assert.Equal(t, origRt, cur, "the chain must terminate at the original reportTimestamp")
}

// richProfile builds a ContainerProfile with at least two elements in every partitionable
// field, plus non-empty non-partitionable fields, so tests can assert both halving and
// verbatim-copy behaviour against a single realistic fixture.
func richProfile() *v1beta1.ContainerProfile {
	p := testProfile()
	p.Labels = map[string]string{"app": "test-app"}
	p.Spec = v1beta1.ContainerProfileSpec{
		Architectures: []string{"amd64"},
		Capabilities:  []string{"cap-a", "cap-b"},
		Execs: []v1beta1.ExecCalls{
			{Path: "/bin/a"},
			{Path: "/bin/b"},
		},
		Opens: []v1beta1.OpenCalls{
			{Path: "/etc/a"},
			{Path: "/etc/b"},
		},
		Syscalls:       []string{"read", "write"},
		SeccompProfile: v1beta1.SingleSeccompProfile{Name: "seccomp-test"},
		Endpoints: []v1beta1.HTTPEndpoint{
			{Endpoint: "/a"},
			{Endpoint: "/b"},
		},
		ImageID:  "sha256:abc",
		ImageTag: "v1",
		PolicyByRuleId: map[string]v1beta1.RulePolicy{
			"rule-a": {AllowedProcesses: []string{"p1"}},
			"rule-b": {AllowedProcesses: []string{"p2"}},
		},
		IdentifiedCallStacks: []v1beta1.IdentifiedCallStack{
			{CallID: "cs-a"},
			{CallID: "cs-b"},
		},
		LabelSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{"k": "v"},
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "k", Operator: metav1.LabelSelectorOpExists},
			},
		},
		Ingress: []v1beta1.NetworkNeighbor{{Identifier: "in-a"}, {Identifier: "in-b"}},
		Egress:  []v1beta1.NetworkNeighbor{{Identifier: "eg-a"}, {Identifier: "eg-b"}},
	}
	return p
}

// elementSignatures returns one string per partitionable element, tagged by field, so tests
// can assert the union/no-overlap invariant across splitProfile's halves.
func elementSignatures(spec *v1beta1.ContainerProfileSpec) []string {
	var out []string
	for _, c := range spec.Capabilities {
		out = append(out, "cap:"+c)
	}
	for _, e := range spec.Execs {
		out = append(out, "exec:"+e.Path)
	}
	for _, o := range spec.Opens {
		out = append(out, "open:"+o.Path)
	}
	for _, s := range spec.Syscalls {
		out = append(out, "syscall:"+s)
	}
	for _, e := range spec.Endpoints {
		out = append(out, "endpoint:"+e.Endpoint)
	}
	for _, c := range spec.IdentifiedCallStacks {
		out = append(out, "callstack:"+string(c.CallID))
	}
	for _, n := range spec.Ingress {
		out = append(out, "ingress:"+n.Identifier)
	}
	for _, n := range spec.Egress {
		out = append(out, "egress:"+n.Identifier)
	}
	for k := range spec.PolicyByRuleId {
		out = append(out, "policy:"+k)
	}
	return out
}

func TestSplitProfile_PartitionsWithoutLossOrDuplication(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(p *v1beta1.ContainerProfile)
	}{
		{"capabilities", func(p *v1beta1.ContainerProfile) {
			p.Spec.Capabilities = []string{"a", "b", "c", "d"}
		}},
		{"execs", func(p *v1beta1.ContainerProfile) {
			p.Spec.Execs = []v1beta1.ExecCalls{{Path: "/a"}, {Path: "/b"}, {Path: "/c"}}
		}},
		{"opens", func(p *v1beta1.ContainerProfile) {
			p.Spec.Opens = []v1beta1.OpenCalls{{Path: "/a"}, {Path: "/b"}, {Path: "/c"}}
		}},
		{"syscalls", func(p *v1beta1.ContainerProfile) {
			p.Spec.Syscalls = []string{"read", "write", "openat"}
		}},
		{"endpoints", func(p *v1beta1.ContainerProfile) {
			p.Spec.Endpoints = []v1beta1.HTTPEndpoint{{Endpoint: "/a"}, {Endpoint: "/b"}, {Endpoint: "/c"}}
		}},
		{"identifiedCallStacks", func(p *v1beta1.ContainerProfile) {
			p.Spec.IdentifiedCallStacks = []v1beta1.IdentifiedCallStack{{CallID: "a"}, {CallID: "b"}, {CallID: "c"}}
		}},
		{"ingress", func(p *v1beta1.ContainerProfile) {
			p.Spec.Ingress = []v1beta1.NetworkNeighbor{{Identifier: "a"}, {Identifier: "b"}, {Identifier: "c"}}
		}},
		{"egress", func(p *v1beta1.ContainerProfile) {
			p.Spec.Egress = []v1beta1.NetworkNeighbor{{Identifier: "a"}, {Identifier: "b"}, {Identifier: "c"}}
		}},
		{"policyByRuleId", func(p *v1beta1.ContainerProfile) {
			p.Spec.PolicyByRuleId = map[string]v1beta1.RulePolicy{
				"a": {AllowedProcesses: []string{"x"}},
				"b": {AllowedProcesses: []string{"y"}},
				"c": {AllowedProcesses: []string{"z"}},
			}
		}},
		{"fully populated", func(p *v1beta1.ContainerProfile) {
			*p = *richProfile()
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := testProfile()
			tt.mutate(p)

			original := elementSignatures(&p.Spec)
			require.GreaterOrEqual(t, len(original), 2)

			a, b, ok := splitProfile(p)
			require.True(t, ok)

			combined := append(elementSignatures(&a.Spec), elementSignatures(&b.Spec)...)
			assert.ElementsMatch(t, original, combined)

			seen := make(map[string]bool, len(combined))
			for _, s := range combined {
				assert.False(t, seen[s], "element %q duplicated across halves", s)
				seen[s] = true
			}
		})
	}
}

// TestSplitProfile_CopiesSharedFieldsVerbatim is inverted from an early draft, which asserted
// the two timestamp annotations were equal across halves - that would have locked in the C1
// chain fork. Every other shared field must be deep-equal; the two timestamp keys must NOT.
func TestSplitProfile_CopiesSharedFieldsVerbatim(t *testing.T) {
	p := richProfile()

	a, b, ok := splitProfile(p)
	require.True(t, ok)

	for _, half := range []*v1beta1.ContainerProfile{a, b} {
		assert.Equal(t, p.Labels, half.Labels)
		assert.Equal(t, p.Spec.Architectures, half.Spec.Architectures)
		assert.Equal(t, p.Spec.ImageID, half.Spec.ImageID)
		assert.Equal(t, p.Spec.ImageTag, half.Spec.ImageTag)
		assert.Equal(t, p.Spec.SeccompProfile, half.Spec.SeccompProfile)
		assert.Equal(t, p.Spec.LabelSelector, half.Spec.LabelSelector)

		for k, v := range p.Annotations {
			if k == helpersv1.ReportTimestampMetadataKey || k == helpersv1.PreviousReportTimestampMetadataKey {
				continue
			}
			assert.Equal(t, v, half.Annotations[k], "annotation %q must be copied verbatim", k)
		}
	}

	assert.NotEqual(t, a.Annotations[helpersv1.ReportTimestampMetadataKey], b.Annotations[helpersv1.ReportTimestampMetadataKey],
		"halves must not share a reportTimestamp - a shared pair forks storage's report chain (C1)")
	assert.NotEqual(t, a.Annotations[helpersv1.PreviousReportTimestampMetadataKey], b.Annotations[helpersv1.PreviousReportTimestampMetadataKey],
		"halves must not share a previousReportTimestamp")
}

func TestSplitProfile_FreshSlugPreservesBaseName(t *testing.T) {
	p := testProfile()
	p.Name = "cattle-cluster-agent-0123456789abcdef0123456789abcdef"
	p.Spec.Capabilities = []string{"a", "b", "c"}

	a, b, ok := splitProfile(p)
	require.True(t, ok)

	baseName, _ := file.SplitProfileName(p.Name)
	aBase, aSuffix := file.SplitProfileName(a.Name)
	bBase, bSuffix := file.SplitProfileName(b.Name)

	assert.Equal(t, baseName, aBase)
	assert.Equal(t, baseName, bBase)
	assert.Len(t, aSuffix, 32)
	assert.Len(t, bSuffix, 32)

	assert.NotEqual(t, a.Name, b.Name)
	assert.NotEqual(t, a.Name, p.Name)
	assert.NotEqual(t, b.Name, p.Name)

	assert.LessOrEqual(t, len(a.Name), names.MaxDNSSubdomainLength)
	assert.LessOrEqual(t, len(b.Name), names.MaxDNSSubdomainLength)
}

func TestSplitProfile_FloorCase(t *testing.T) {
	for _, n := range []int{0, 1} {
		t.Run(fmt.Sprintf("%d elements", n), func(t *testing.T) {
			p := testProfile()
			if n == 1 {
				p.Spec.Capabilities = []string{"only"}
			}

			_, _, ok := splitProfile(p)
			assert.False(t, ok)
		})
	}
}

func TestSplitProfile_NoEmptyHalf(t *testing.T) {
	p := testProfile()
	p.Spec.Capabilities = []string{"cap-1"}
	p.Spec.Syscalls = []string{"read"}

	a, b, ok := splitProfile(p)
	require.True(t, ok)

	assert.Greater(t, countPartitionableElements(&a.Spec), 0)
	assert.Greater(t, countPartitionableElements(&b.Spec), 0)
	assert.Equal(t, 2, countPartitionableElements(&a.Spec)+countPartitionableElements(&b.Spec))
}

// TestSplitProfile_Deterministic guards the sorted-key map partition against Go's randomised
// map iteration order: two splits of the same input must produce identical field partitions.
func TestSplitProfile_Deterministic(t *testing.T) {
	p := richProfile()

	a1, b1, ok := splitProfile(p.DeepCopy())
	require.True(t, ok)
	a2, b2, ok := splitProfile(p.DeepCopy())
	require.True(t, ok)

	assert.Equal(t, a1.Spec.PolicyByRuleId, a2.Spec.PolicyByRuleId)
	assert.Equal(t, b1.Spec.PolicyByRuleId, b2.Spec.PolicyByRuleId)
	assert.Equal(t, a1.Spec.Capabilities, a2.Spec.Capabilities)
	assert.Equal(t, b1.Spec.Capabilities, b2.Spec.Capabilities)
	assert.Equal(t, a1.Spec.Ingress, a2.Spec.Ingress)
	assert.Equal(t, b1.Spec.Ingress, b2.Spec.Ingress)
}

func TestFreshOneTimeSlug_MalformedName(t *testing.T) {
	t.Run("no hyphen suffix", func(t *testing.T) {
		got := freshOneTimeSlug("noHyphenName")
		base, suffix := file.SplitProfileName(got)
		assert.Equal(t, "noHyphenName", base)
		assert.Len(t, suffix, 32)
	})

	t.Run("at the DNS subdomain length limit", func(t *testing.T) {
		longBase := strings.Repeat("a", names.MaxDNSSubdomainLength)
		got := freshOneTimeSlug(longBase + "-deadbeef")

		assert.LessOrEqual(t, len(got), names.MaxDNSSubdomainLength)
		_, suffix := file.SplitProfileName(got)
		assert.Len(t, suffix, 32)
	})
}

// manyCapabilities returns n distinct, reasonably-sized capability strings, so a split has
// enough payload to make genuine byte progress even when the timestamp annotations themselves
// grow (e.g. a zero or whole-second timestamp being replaced by a manufactured one).
func manyCapabilities(n int) []string {
	caps := make([]string, n)
	for i := range caps {
		caps[i] = fmt.Sprintf("capability-%02d", i)
	}
	return caps
}

func rowOf(p *v1beta1.ContainerProfile) tsRow {
	return tsRow{
		PreviousReportTimestamp: p.Annotations[helpersv1.PreviousReportTimestampMetadataKey],
		ReportTimestamp:         p.Annotations[helpersv1.ReportTimestampMetadataKey],
	}
}

func sortRowsDesc(rows []tsRow) {
	sort.Slice(rows, func(i, j int) bool { return rows[i].ReportTimestamp > rows[j].ReportTimestamp })
}

func TestChainHalves_ConsolidatesToParentInterval(t *testing.T) {
	p := testProfile()
	p.Spec.Capabilities = []string{"a", "b", "c"}

	a, b, ok := splitProfile(p)
	require.True(t, ok)

	rows := []tsRow{rowOf(a), rowOf(b)}
	sortRowsDesc(rows)

	result := consolidateGolden(rows)
	require.Len(t, result, 1)
	assert.Equal(t, p.Annotations[helpersv1.PreviousReportTimestampMetadataKey], result[0].PreviousReportTimestamp)
	assert.Equal(t, p.Annotations[helpersv1.ReportTimestampMetadataKey], result[0].ReportTimestamp)
}

func TestChainHalves_ZeroPreviousTimestamp(t *testing.T) {
	p := testProfile()
	p.Annotations[helpersv1.PreviousReportTimestampMetadataKey] = time.Time{}.String()
	rt := time.Now()
	p.Annotations[helpersv1.ReportTimestampMetadataKey] = rt.String()
	// A zero previousReportTimestamp is a short string ("0001-01-01 00:00:00 +0000 UTC"),
	// shorter than the manufactured X it gets replaced with, so a tiny payload would be
	// dwarfed by that formatting growth alone; use enough elements for genuine progress.
	p.Spec.Capabilities = manyCapabilities(10)

	a, b, ok := splitProfile(p)
	require.True(t, ok)

	x, xok := parseReportTimestamp(a.Annotations[helpersv1.ReportTimestampMetadataKey])
	require.True(t, xok)

	assert.WithinDuration(t, rt, x, time.Second, "X must stay near T, never a year-1013 midpoint")

	cutoff := time.Now().Add(-24 * time.Hour).String()
	assert.Greater(t, x.String(), cutoff,
		"X must not look expired under ListTimeSeriesExpired's raw string comparison (sqlite.go:352-356)")

	rows := []tsRow{rowOf(a), rowOf(b)}
	sortRowsDesc(rows)
	result := consolidateGolden(rows)
	require.Len(t, result, 1)
	assert.True(t, isZeroTimeString(result[0].PreviousReportTimestamp))
}

func TestChainHalves_TimestampRoundTrip(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		prev time.Time
		rt   time.Time
	}{
		{"whole second", now.Truncate(time.Second).Add(-time.Hour), now.Truncate(time.Second)},
		{"sub-millisecond interval", now, now.Add(500 * time.Microsecond)},
		{"time.Now()", time.Now().Add(-time.Hour), time.Now()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testProfile()
			p.Annotations[helpersv1.PreviousReportTimestampMetadataKey] = tc.prev.String()
			p.Annotations[helpersv1.ReportTimestampMetadataKey] = tc.rt.String()
			// Whole-second timestamps carry no monotonic suffix, so the manufactured X (which
			// always has a fractional component) can be longer than the originals; use enough
			// elements that halving still makes genuine byte progress.
			p.Spec.Capabilities = manyCapabilities(10)

			a, b, ok := splitProfile(p)
			require.True(t, ok)

			x, xok := parseReportTimestamp(a.Annotations[helpersv1.ReportTimestampMetadataKey])
			require.True(t, xok)
			assert.Equal(t, a.Annotations[helpersv1.ReportTimestampMetadataKey], x.String())

			assert.True(t, tc.prev.Before(x))
			assert.True(t, x.Before(tc.rt))

			// Lexicographic, mirroring sqlite.go's ORDER BY reportTimestamp DESC string sort.
			assert.Less(t, p.Annotations[helpersv1.PreviousReportTimestampMetadataKey], a.Annotations[helpersv1.ReportTimestampMetadataKey])
			assert.Less(t, a.Annotations[helpersv1.ReportTimestampMetadataKey], p.Annotations[helpersv1.ReportTimestampMetadataKey])

			_ = b
		})
	}
}

// TestParseReportTimestamp_MonotonicSuffix is the B1 regression guard: it asserts why the
// " m=" cut exists, so a future reader cannot delete it as redundant.
func TestParseReportTimestamp_MonotonicSuffix(t *testing.T) {
	now := time.Now()
	s := now.String()
	require.Contains(t, s, " m=", "time.Now().String() must carry a monotonic reading for this test to be meaningful")

	_, err := time.Parse(goTimeLayout, s)
	require.Error(t, err, "a raw goTimeLayout parse must fail on the monotonic suffix - this is why parseReportTimestamp cuts it first")

	parsed, ok := parseReportTimestamp(s)
	require.True(t, ok)
	assert.NotContains(t, parsed.String(), " m=")

	x, xok := interposeTimestamp(time.Time{}, parsed, splitDelta)
	require.True(t, xok)
	assert.NotContains(t, x.String(), " m=", "a manufactured timestamp derived from a parsed time must never carry a monotonic reading")
}

// TestChainHalves_OnRealProductionAnnotations builds annotations exactly the way
// saveContainerProfile does (monitoring.go:170-171, 184-185): real time.Now() values, not
// time.Date fixtures. Do not "fix" this test by switching to time.Date - that would hide the
// monotonic-suffix bug (B1) on every run, exactly as an earlier plan revision did.
func TestChainHalves_OnRealProductionAnnotations(t *testing.T) {
	prev := time.Now()
	time.Sleep(time.Millisecond)
	rt := time.Now()

	p := testProfile()
	p.Annotations[helpersv1.PreviousReportTimestampMetadataKey] = prev.String()
	p.Annotations[helpersv1.ReportTimestampMetadataKey] = rt.String()
	p.Annotations[helpersv1.ReportSeriesIdMetadataKey] = "series-real"
	p.Spec.Capabilities = []string{"a", "b", "c"}

	a, b, ok := splitProfile(p)
	require.True(t, ok, "splitting must succeed against real production-shaped timestamps")

	assert.NotContains(t, a.Annotations[helpersv1.ReportTimestampMetadataKey], " m=")
	assert.NotContains(t, b.Annotations[helpersv1.PreviousReportTimestampMetadataKey], " m=")
}

func TestParseReportTimestamp_NumericZoneAbbreviation(t *testing.T) {
	zones := []string{
		"Asia/Kathmandu", "Asia/Tehran", "Asia/Kabul", "Asia/Colombo", "Asia/Yangon",
		"Australia/Eucla", "Australia/Lord_Howe", "Pacific/Chatham", "Pacific/Marquesas",
		"Asia/Bangkok",  // whole-hour numeric zone control - parses under goTimeLayout directly
		"Europe/Zurich", // letter-abbreviation zone control
	}

	for _, zoneName := range zones {
		t.Run(zoneName, func(t *testing.T) {
			loc, err := time.LoadLocation(zoneName)
			if err != nil {
				t.Skipf("zone database unavailable for %s: %v", zoneName, err)
			}

			rt := time.Now().In(loc)
			prev := rt.Add(-time.Hour)

			parsedRt, ok := parseReportTimestamp(rt.String())
			require.True(t, ok, "must parse a %s timestamp", zoneName)

			x, ok := interposeTimestamp(prev, parsedRt, splitDelta)
			require.True(t, ok)

			reparsedX, ok := parseReportTimestamp(x.String())
			require.True(t, ok, "manufactured X must itself re-parse")
			assert.Equal(t, x.String(), reparsedX.String())

			assert.Less(t, x.String(), rt.String())
		})
	}
}

func TestChainHalves_RefusesInvalidInterval(t *testing.T) {
	t.Run("unparseable reportTimestamp", func(t *testing.T) {
		p := testProfile()
		p.Annotations[helpersv1.ReportTimestampMetadataKey] = "not-a-real-timestamp"
		p.Spec.Capabilities = []string{"a", "b", "c"}

		_, _, ok := splitProfile(p)
		assert.False(t, ok)
	})

	t.Run("reportTimestamp not after previousReportTimestamp", func(t *testing.T) {
		p := testProfile()
		now := time.Now()
		p.Annotations[helpersv1.PreviousReportTimestampMetadataKey] = now.String()
		p.Annotations[helpersv1.ReportTimestampMetadataKey] = now.Add(-time.Hour).String()
		p.Spec.Capabilities = []string{"a", "b", "c"}

		_, _, ok := splitProfile(p)
		assert.False(t, ok)
	})

	t.Run("interval too narrow to subdivide", func(t *testing.T) {
		p := testProfile()
		rt := time.Now()
		prev := rt.Add(-time.Nanosecond)
		p.Annotations[helpersv1.PreviousReportTimestampMetadataKey] = prev.String()
		p.Annotations[helpersv1.ReportTimestampMetadataKey] = rt.String()
		p.Spec.Capabilities = []string{"a", "b", "c"}

		_, _, ok := splitProfile(p)
		assert.False(t, ok)
	})
}

// TestSplitProfile_RecursiveChainStaysLinear pins the "interior nodes are only inserted, never
// removed" invariant from the plan's §5.2a: splitting one half of an already-split pair must
// still consolidate back to the original (P, T] interval.
func TestSplitProfile_RecursiveChainStaysLinear(t *testing.T) {
	p := testProfile()
	p.Spec.Capabilities = []string{"a", "b", "c", "d", "e"}

	a, b, ok := splitProfile(p)
	require.True(t, ok)

	b1, b2, ok := splitProfile(b)
	require.True(t, ok)

	rows := []tsRow{rowOf(a), rowOf(b1), rowOf(b2)}
	sortRowsDesc(rows)

	assertChainIsLinear(t, rows,
		p.Annotations[helpersv1.PreviousReportTimestampMetadataKey],
		p.Annotations[helpersv1.ReportTimestampMetadataKey])

	result := consolidateGolden(rows)
	require.Len(t, result, 1)
	assert.Equal(t, p.Annotations[helpersv1.PreviousReportTimestampMetadataKey], result[0].PreviousReportTimestamp)
	assert.Equal(t, p.Annotations[helpersv1.ReportTimestampMetadataKey], result[0].ReportTimestamp)
}

func TestSplitProfile_NoProgressGuard(t *testing.T) {
	t.Run("no progress when the fresh name outweighs a tiny payload", func(t *testing.T) {
		p := testProfile()
		// A one-character name means freshOneTimeSlug's 32-hex suffix adds far more bytes to
		// each half than halving these two single-character capabilities ever removes.
		p.Name = "p"
		p.Spec.Capabilities = []string{"a", "b"}

		_, _, ok := splitProfile(p)
		assert.False(t, ok, "halves whose regenerated name outweighs the halved payload must be refused")
	})

	t.Run("revision-3 regression: must still split one round from success", func(t *testing.T) {
		p := testProfile()
		// K ~ 2.2MB baseline, P ~ 0.5MB partitionable payload - the shape the old 0.9
		// threshold false-dropped, per the plan's worked example (K > 4P but halves still
		// land under a realistic cap).
		p.Spec.SeccompProfile = v1beta1.SingleSeccompProfile{Name: strings.Repeat("k", 2_200_000)}
		caps := make([]string, 500)
		for i := range caps {
			caps[i] = fmt.Sprintf("capability-%d-%s", i, strings.Repeat("p", 1000))
		}
		p.Spec.Capabilities = caps

		_, _, ok := splitProfile(p)
		assert.True(t, ok, "a chunk one round from fitting under the cap must still split")
	})
}

// TestStitchChunk_PreservesAssignmentMergedScalars is the M-a regression guard. Storage's
// mergeContainerProfileTS assigns (not appends) SeccompProfile, ImageID and ImageTag
// (containerprofile_processor.go:863-866), and rows merge oldest-last, so an empty-Spec
// stitch would zero those three on the aggregate.
func TestStitchChunk_PreservesAssignmentMergedScalars(t *testing.T) {
	p := richProfile()

	stitch := stitchChunk(p)

	assert.Equal(t, p.Spec.SeccompProfile, stitch.Spec.SeccompProfile)
	assert.Equal(t, p.Spec.ImageID, stitch.Spec.ImageID)
	assert.Equal(t, p.Spec.ImageTag, stitch.Spec.ImageTag)

	assert.Empty(t, stitch.Spec.Capabilities)
	assert.Empty(t, stitch.Spec.Execs)
	assert.Empty(t, stitch.Spec.Opens)
	assert.Empty(t, stitch.Spec.Syscalls)
	assert.Empty(t, stitch.Spec.Endpoints)
	assert.Empty(t, stitch.Spec.IdentifiedCallStacks)
	assert.Empty(t, stitch.Spec.Ingress)
	assert.Empty(t, stitch.Spec.Egress)
	assert.Empty(t, stitch.Spec.PolicyByRuleId)
	assert.Empty(t, stitch.Spec.Architectures)
	assert.Empty(t, stitch.Spec.LabelSelector.MatchLabels)
	assert.Empty(t, stitch.Spec.LabelSelector.MatchExpressions)

	assert.Equal(t, p.Annotations[helpersv1.ReportTimestampMetadataKey], stitch.Annotations[helpersv1.ReportTimestampMetadataKey])
	assert.Equal(t, p.Annotations[helpersv1.PreviousReportTimestampMetadataKey], stitch.Annotations[helpersv1.PreviousReportTimestampMetadataKey])
	assert.Equal(t, p.Annotations[helpersv1.ReportSeriesIdMetadataKey], stitch.Annotations[helpersv1.ReportSeriesIdMetadataKey])

	assert.NotEqual(t, p.Name, stitch.Name)
	base, _ := file.SplitProfileName(p.Name)
	stitchBase, _ := file.SplitProfileName(stitch.Name)
	assert.Equal(t, base, stitchBase)
}
