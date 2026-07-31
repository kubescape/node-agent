package queue

import (
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/names"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file"
)

// DefaultMaxSplitDepth bounds how many times a single original chunk may be halved.
//
// With the byte-progress guard in splitProfile this is a tripwire rather than the primary
// bound: needing depth > 4 implies the chunk overshot storage's cap by more than 16x (a
// ~40MB delta against a 2.5MB cap), which is a node-agent estimator bug that should surface
// as a Warning promptly instead of being absorbed by split storms. It also caps one
// lineage's peak queue occupancy at 16 leaves; enforceMaxSize evicts FIFO from the head
// while splits append to the tail, so an unbounded lineage would silently evict the oldest
// in-flight halves of *other* lineages.
const DefaultMaxSplitDepth = 4

// goTimeLayout is time.Time.String()'s layout. node-agent writes report timestamps with
// .String() (monitoring.go:184-185) and storage compares and sorts them as raw strings, so
// any manufactured timestamp must round-trip through exactly this layout - RFC3339 would
// silently break both the chain match and the ORDER BY.
//
// Note this layout does NOT cover the trailing monotonic-clock reading that time.Now().String()
// appends; parseReportTimestamp cuts that first.
const goTimeLayout = "2006-01-02 15:04:05.999999999 -0700 MST"

// goTimeLayoutNumeric is the same layout for zones whose UTC offset is not a whole number of
// hours. For those, String() renders the abbreviation as a bare numeric offset - Kathmandu
// prints "+0545 +0545", not "+0545 NPT" - which the MST element above cannot parse. Whole-hour
// numeric zones ("+0700 +07") still parse under goTimeLayout, so this is a fallback, not a
// replacement. Affected zones include Asia/Kathmandu, Asia/Tehran, Asia/Kabul, Asia/Colombo,
// Asia/Yangon, Australia/Eucla, Australia/Lord_Howe, Pacific/Chatham and Pacific/Marquesas.
const goTimeLayoutNumeric = "2006-01-02 15:04:05.999999999 -0700 -0700"

// splitDelta is how far chainHalves steps back from the parent's report timestamp to place the
// interposed one. It is capped again at half the parent's interval, so it never leaves the
// parent's span.
const splitDelta = time.Millisecond

// splitProfile partitions p into two profiles that together carry exactly p's data and
// no duplicates, and interposes a fresh report timestamp so the two halves form a linear
// two-link chain across p's original reporting interval (see chainHalves).
//
// Every non-partitionable field, and every annotation and label other than the two report
// timestamps, is copied verbatim into both halves. ObjectMeta.Name is freshly generated per
// half over the same base name.
//
// It reports false - meaning "this chunk cannot usefully be split, drop it" - when any of:
//   - p carries at most one partitionable element (the floor case);
//   - a valid interposed timestamp cannot be constructed (see chainHalves);
//   - neither half is meaningfully smaller than p (the byte-progress guard below).
func splitProfile(p *v1beta1.ContainerProfile) (*v1beta1.ContainerProfile, *v1beta1.ContainerProfile, bool) {
	if p == nil || countPartitionableElements(&p.Spec) <= 1 {
		return nil, nil, false
	}

	// The generated deep copy carries Architectures, ImageID, ImageTag, SeccompProfile, the
	// embedded LabelSelector and every annotation and label into both halves for free, and
	// stays correct if storage adds a scalar field.
	a, b := p.DeepCopy(), p.DeepCopy()

	// Per-field (rather than global-index) halving guarantees that whichever field dominates
	// the byte size is itself halved on the very first round.
	a.Spec.Capabilities, b.Spec.Capabilities = halve(p.Spec.Capabilities)
	a.Spec.Execs, b.Spec.Execs = halve(p.Spec.Execs)
	a.Spec.Opens, b.Spec.Opens = halve(p.Spec.Opens)
	a.Spec.Syscalls, b.Spec.Syscalls = halve(p.Spec.Syscalls)
	a.Spec.Endpoints, b.Spec.Endpoints = halve(p.Spec.Endpoints)
	a.Spec.IdentifiedCallStacks, b.Spec.IdentifiedCallStacks = halve(p.Spec.IdentifiedCallStacks)
	a.Spec.Ingress, b.Spec.Ingress = halve(p.Spec.Ingress)
	a.Spec.Egress, b.Spec.Egress = halve(p.Spec.Egress)
	a.Spec.PolicyByRuleId, b.Spec.PolicyByRuleId = halvePolicies(p.Spec.PolicyByRuleId)

	// Every field with len <= 1 leaves its single element in a, so b can come out empty even
	// though p had two or more elements. Move one element across, otherwise recursion on a
	// would not strictly reduce and the split would make no progress.
	if countPartitionableElements(&b.Spec) == 0 {
		moveOneElement(&a.Spec, &b.Spec)
	}

	a.Name, b.Name = freshOneTimeSlug(p.Name), freshOneTimeSlug(p.Name)

	if !chainHalves(p, a, b) {
		return nil, nil, false
	}

	// Splitting has to actually shrink something. This catches only literal non-progress: a
	// tighter, cap-aware threshold would false-drop chunks one round from success, and
	// node-agent cannot know storage's cap.
	parentSize := serializedSize(p)
	if serializedSize(a) >= parentSize || serializedSize(b) >= parentSize {
		return nil, nil, false
	}

	return a, b, true
}

// chainHalves rewrites the report-timestamp annotations of a and b so that, given a parent
// spanning (P, T], a spans (P, X] and b spans (X, T] for some P < X < T.
//
// This exists because storage's consolidateContinuousTimeSeries walks a strictly linear
// chain, matching each row's previousReportTimestamp against the next row's
// reportTimestamp. Two rows sharing an identical (P, T] pair fork that chain permanently,
// and updateProfileStatus then early-returns on
//
//	len(newTimeSeries) != 1 || !isZeroTime(newTimeSeries[0].PreviousReportTimestamp)
//
// leaving the profile in Learning forever. Note the second clause: completion requires the
// consolidated chain to trace all the way back to the container's first report, so a single
// missing link is permanently disqualifying.
//
// Only X is manufactured. a keeps the parent's previousReportTimestamp string and b keeps the
// parent's reportTimestamp string byte-for-byte, and the single manufactured X.String() is
// written to both a's reportTimestamp and b's previousReportTimestamp - so storage's chain
// match compares that string against itself and cannot fail for formatting reasons.
//
// TEMPORARY SHIM. Delete this function, and revert splitProfile to leaving both timestamp
// annotations untouched, once storage's consolidateContinuousTimeSeries collapses rows that
// share a (previousReportTimestamp, reportTimestamp) pair within a series. This is the ONLY
// place in the queue package that knows the report chain exists; keep it that way.
//
// It reports false if no valid X can be constructed, in which case the caller must not split.
func chainHalves(parent, a, b *v1beta1.ContainerProfile) bool {
	rt, ok := parseReportTimestamp(parent.Annotations[helpersv1.ReportTimestampMetadataKey])
	if !ok {
		return false
	}

	// P is the zero time on a container's very first report, which is a common, valid state.
	var prev time.Time
	prevRaw := parent.Annotations[helpersv1.PreviousReportTimestampMetadataKey]
	if !isZeroTimeString(prevRaw) {
		if prev, ok = parseReportTimestamp(prevRaw); !ok {
			return false
		}
	}

	x, ok := interposeTimestamp(prev, rt, splitDelta)
	if !ok {
		return false
	}

	interposed := x.String()
	a.Annotations[helpersv1.ReportTimestampMetadataKey] = interposed
	b.Annotations[helpersv1.PreviousReportTimestampMetadataKey] = interposed

	return true
}

// interposeTimestamp returns a time strictly between prev and rt.
//
// prev is the zero time on a container's very first report, so a true midpoint of
// (year 1, now) lands near year 1013 - and ListTimeSeriesExpired compares reportTimestamp
// as a raw string, so such a row matches "expired" unconditionally and the profile is
// marked Completed/Partial. That is the very outcome the split exists to prevent, on what is
// likely the most common split case (the initial learning burst). So this never takes a
// midpoint: it steps back from rt by at most delta, and by at most half the interval.
func interposeTimestamp(prev, rt time.Time, delta time.Duration) (time.Time, bool) {
	step := delta
	if !prev.IsZero() {
		if half := rt.Sub(prev) / 2; half < step {
			step = half
		}
	}

	x := rt.Add(-step)
	if !prev.Before(x) || !x.Before(rt) {
		return x, false
	}

	return x, true
}

// parseReportTimestamp parses a report-timestamp annotation written by saveContainerProfile
// (monitoring.go:184-185).
//
// Those strings come from time.Now().String(), and time.Now() carries a monotonic clock
// reading which String() appends as a trailing " m=+0.000012034". goTimeLayout cannot parse
// that - time.Parse fails with `extra text: " m=+0.000012034"` - so the suffix MUST be cut
// before parsing. Skipping this makes every production chainHalves call fail, which silently
// turns every split into a floor-case drop.
//
// Cutting the suffix has a second, load-bearing effect: the returned time.Time carries no
// monotonic reading, so any timestamp derived from it formats cleanly. Deriving X from a
// monotonic-carrying time instead would emit a stale, negative reading
// (time.Now().Add(-time.Millisecond).String() ends in " m=-0.000980993"), which is
// meaningless as a persisted value.
func parseReportTimestamp(s string) (time.Time, bool) {
	s, _, _ = strings.Cut(s, " m=")

	if t, err := time.Parse(goTimeLayout, s); err == nil {
		return t, true
	}

	// Zones whose offset is not a whole number of hours render a bare numeric abbreviation
	// that the MST element cannot parse. Do not "simplify" this away.
	if t, err := time.Parse(goTimeLayoutNumeric, s); err == nil {
		return t, true
	}

	return time.Time{}, false
}

// isZeroTimeString mirrors storage's isZeroTime (containerprofile_processor.go:839-846), so a
// zero previousReportTimestamp is recognised without depending on it parsing.
func isZeroTimeString(s string) bool {
	switch s {
	case "", "0001-01-01 00:00:00 +0000 UTC", "0001-01-01T00:00:00Z":
		return true
	default:
		return false
	}
}

// countPartitionableElements returns the total number of elements across every list and
// map field that splitProfile partitions.
func countPartitionableElements(spec *v1beta1.ContainerProfileSpec) int {
	return len(spec.Capabilities) +
		len(spec.Execs) +
		len(spec.Opens) +
		len(spec.Syscalls) +
		len(spec.Endpoints) +
		len(spec.IdentifiedCallStacks) +
		len(spec.Ingress) +
		len(spec.Egress) +
		len(spec.PolicyByRuleId)
}

// moveOneElement transfers a single element from the first non-empty partitionable field of
// from into to, so that a split of a spec with at least two elements never yields an empty half.
func moveOneElement(from, to *v1beta1.ContainerProfileSpec) {
	switch {
	case moveLast(&from.Capabilities, &to.Capabilities):
	case moveLast(&from.Execs, &to.Execs):
	case moveLast(&from.Opens, &to.Opens):
	case moveLast(&from.Syscalls, &to.Syscalls):
	case moveLast(&from.Endpoints, &to.Endpoints):
	case moveLast(&from.IdentifiedCallStacks, &to.IdentifiedCallStacks):
	case moveLast(&from.Ingress, &to.Ingress):
	case moveLast(&from.Egress, &to.Egress):
	default:
		moveOnePolicy(&from.PolicyByRuleId, &to.PolicyByRuleId)
	}
}

// moveLast pops the last element of *from into *to, reporting whether there was one to move.
func moveLast[T any](from, to *[]T) bool {
	if len(*from) == 0 {
		return false
	}

	last := len(*from) - 1
	*to = append(*to, (*from)[last])
	*from = (*from)[:last]

	return true
}

// moveOnePolicy transfers the lowest-keyed policy from *from into *to.
func moveOnePolicy(from, to *map[string]v1beta1.RulePolicy) {
	keys := sortedKeys(*from)
	if len(keys) == 0 {
		return
	}

	if *to == nil {
		*to = map[string]v1beta1.RulePolicy{}
	}
	(*to)[keys[0]] = (*from)[keys[0]]
	delete(*from, keys[0])
}

// serializedSize returns p's JSON-encoded byte length.
//
// This is an APPROXIMATION and is only ever used as a ratio between a parent and its halves.
// It is NOT comparable to storage's Content-Length cap: node-agent's client forces protobuf
// (pkg/storage/v1/storage.go:56-57), so the bytes actually weighed by QueueManager are
// protobuf-encoded, not JSON. Never treat this number as ground truth against the cap.
func serializedSize(p *v1beta1.ContainerProfile) int {
	encoded, err := json.Marshal(p)
	if err != nil {
		return 0
	}

	return len(encoded)
}

// freshOneTimeSlug replaces the trailing one-time UUID suffix of name with a newly
// generated one, mirroring InstanceID.GetOneTimeSlug. The base name is recovered with
// storage's own file.SplitProfileName - the same function the server uses to key the
// aggregate - so agreement with the aggregation key is true by construction rather than by
// a reimplemented heuristic.
func freshOneTimeSlug(name string) string {
	base, _ := file.SplitProfileName(name)

	u := uuid.New()
	suffix := "-" + hex.EncodeToString(u[:])

	if len(base)+len(suffix) > names.MaxDNSSubdomainLength {
		base = base[:names.MaxDNSSubdomainLength-len(suffix)]
	}

	return base + suffix
}

// halve returns the first ceil(len(s)/2) elements of s and the rest.
func halve[T any](s []T) ([]T, []T) {
	if len(s) == 0 {
		return nil, nil
	}

	mid := (len(s) + 1) / 2

	return s[:mid], s[mid:]
}

// halvePolicies partitions m by sorted key, so the partition is deterministic across runs.
func halvePolicies(m map[string]v1beta1.RulePolicy) (map[string]v1beta1.RulePolicy, map[string]v1beta1.RulePolicy) {
	if len(m) == 0 {
		return nil, nil
	}

	keys := sortedKeys(m)
	firstKeys, secondKeys := halve(keys)

	first := make(map[string]v1beta1.RulePolicy, len(firstKeys))
	for _, k := range firstKeys {
		first[k] = m[k]
	}

	second := make(map[string]v1beta1.RulePolicy, len(secondKeys))
	for _, k := range secondKeys {
		second[k] = m[k]
	}

	return first, second
}

func sortedKeys(m map[string]v1beta1.RulePolicy) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	return keys
}

// stitchChunk returns a stand-in for a chunk that is being dropped: the same annotations
// (crucially the same previousReportTimestamp/reportTimestamp pair) and labels, a fresh
// one-time slug, and a Spec with only the size-bearing collections cleared. Its only job is
// to keep the report chain linear; it is a couple of KB and cannot itself be rejected with a 413.
//
// It is deliberately NOT an empty-Spec profile. Storage's AfterCreate hardcodes hasData=true,
// so the stitch is merged like any other row, and mergeContainerProfileTS *assigns* rather
// than appends SeccompProfile, ImageID and ImageTag (containerprofile_processor.go:863-866).
// Rows merge oldest-last, so an empty stitch would zero those three on the aggregate.
// Everything else is append- or map-merged, so clearing it contributes nothing - including
// Architectures, which would otherwise be duplicated on every stitch.
func stitchChunk(dropped *v1beta1.ContainerProfile) *v1beta1.ContainerProfile {
	stitch := dropped.DeepCopy()
	stitch.Name = freshOneTimeSlug(dropped.Name)
	stitch.Spec = v1beta1.ContainerProfileSpec{
		SeccompProfile: stitch.Spec.SeccompProfile,
		ImageID:        stitch.Spec.ImageID,
		ImageTag:       stitch.Spec.ImageTag,
	}

	return stitch
}
