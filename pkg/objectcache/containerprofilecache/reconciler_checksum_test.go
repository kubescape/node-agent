package containerprofilecache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// recordedFetch is one observed GetContainerProfile call: the object name asked
// for, and the conditional-fetch validator the caller attached to that call's
// context (empty when none was attached).
type recordedFetch struct {
	name     string
	checksum string
}

// checksumRecordingClient is a storage.ProfileClient that records the known
// checksum carried by EACH call's context. Recording per call (rather than per
// client) is what makes the negative assertions possible: the authored-CP fetch
// and the learned-CP fetch derive from the same parent context, so a design that
// attached the checksum to that shared context instead of per call would show up
// here as the authored fetch seeing a non-empty value.
type checksumRecordingClient struct {
	mu sync.Mutex

	// learned is served for any name not present in authored. learnedErr, when
	// set, is returned instead (still after recording the call).
	learned    *v1beta1.ContainerProfile
	learnedErr error

	// authored maps an object name to the authored CP served for it. Names in
	// this map are never served the learned CP.
	authored map[string]*v1beta1.ContainerProfile

	fetches []recordedFetch
}

var _ storage.ProfileClient = (*checksumRecordingClient)(nil)

func (c *checksumRecordingClient) GetContainerProfile(ctx context.Context, _, name string) (*v1beta1.ContainerProfile, error) {
	c.mu.Lock()
	c.fetches = append(c.fetches, recordedFetch{name: name, checksum: storage.KnownChecksumFromContext(ctx)})
	authored, isAuthored := c.authored[name]
	c.mu.Unlock()

	if isAuthored {
		return authored, nil
	}
	if c.learnedErr != nil {
		return nil, c.learnedErr
	}
	if c.learned != nil {
		return c.learned, nil
	}
	return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "containerprofiles"}, name)
}

// checksumsFor returns the validators observed on every call for `name`, in
// call order. A name never fetched yields an empty slice.
func (c *checksumRecordingClient) checksumsFor(name string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, f := range c.fetches {
		if f.name == name {
			out = append(out, f.checksum)
		}
	}
	return out
}

func (c *checksumRecordingClient) fetchCount(name string) int {
	return len(c.checksumsFor(name))
}

// assertNoChecksumOnAuthoredFetches is the standing per-call-site invariant: no
// fetch of a name registered as an authored CP may ever carry a validator. The
// learned CP's checksum describes the learned object only; offering it on an
// authored fetch would let a source answer "unchanged" for the wrong object.
func (c *checksumRecordingClient) assertNoChecksumOnAuthoredFetches(t *testing.T) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range c.fetches {
		if _, isAuthored := c.authored[f.name]; isAuthored {
			assert.Empty(t, f.checksum, "authored-CP fetch of %q must never carry a known checksum", f.name)
		}
	}
}

// learnedCPWithChecksum builds a terminal-status learned ContainerProfile
// carrying `checksum` under the cross-repo checksum annotation key. A checksum
// of "" produces a profile with no checksum annotation at all (the shape the
// in-cluster CRD-backed client always returns).
func learnedCPWithChecksum(name, rv, checksum string) *v1beta1.ContainerProfile {
	annotations := map[string]string{
		helpersv1.StatusMetadataKey:     helpersv1.Completed,
		helpersv1.CompletionMetadataKey: helpersv1.Full,
	}
	if checksum != "" {
		annotations[storage.ContainerProfileChecksumAnnotationKey] = checksum
	}
	return &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "default", ResourceVersion: rv,
			Annotations: annotations,
		},
		Spec: v1beta1.ContainerProfileSpec{Execs: []v1beta1.ExecCalls{{Path: "/bin/learned"}}},
	}
}

// authoredCPWithChecksum is authoredCP plus a checksum annotation, used to prove
// the adoption path never adopts the AUTHORED object's checksum as the entry's
// validator.
func authoredCPWithChecksum(name, execPath, rv, checksum string) *v1beta1.ContainerProfile {
	cp := authoredCP(name, execPath, rv)
	cp.Annotations[storage.ContainerProfileChecksumAnnotationKey] = checksum
	return cp
}

// seedChecksumEntry installs a cache entry directly, bypassing addContainer, so
// each conjunct of the conditional-fetch guard can be varied independently.
func seedChecksumEntry(c *ContainerProfileCacheImpl, id string, cp *v1beta1.ContainerProfile, checksum, specHash string) *CachedContainerProfile {
	e := &CachedContainerProfile{
		Projected: Apply(nil, cp, nil),
		// Mirrors what both real construction sites store, so a test can tell
		// whether the cached State was re-derived from a fresh body.
		State: &objectcache.ProfileState{
			Name:       cp.Name,
			Status:     cp.Annotations[helpersv1.StatusMetadataKey],
			Completion: cp.Annotations[helpersv1.CompletionMetadataKey],
		},
		ContainerName: "nginx",
		PodName:       "nginx-abc",
		Namespace:     "default",
		PodUID:        "uid-1",
		CPName:        cp.Name,
		RV:            cp.ResourceVersion,
		Checksum:      checksum,
		SpecHash:      specHash,
	}
	c.entries.Set(id, e)
	return e
}

// ---------------------------------------------------------------------------
// D4 — anti-inertness: the population path must store a validator
// ---------------------------------------------------------------------------

// TestPopulatePathStoresChecksum_AntiInertness is the test that proves the
// optimization is not dead code.
//
// A profile that never changes is built ONCE by tryPopulateEntry/buildEntry and
// thereafter always returns at refreshOneEntry's fast-skip, so it never reaches
// rebuildEntryFromSources. If only rebuildEntryFromSources populated Checksum,
// such an entry would hold "" forever, the guard's `e.Checksum != ""` conjunct
// would never hold, and no conditional fetch would EVER be requested for exactly
// the steady-state population this work targets — while every test stayed green.
//
// This test therefore asserts both halves: (a) the entry carries a validator
// immediately after population, and (b) the very next reconcile tick actually
// offers it. It fails if buildEntry's Checksum population is reverted.
func TestPopulatePathStoresChecksum_AntiInertness(t *testing.T) {
	learned := learnedCPWithChecksum("learned-cp", "1", "sum-learned")
	client := &checksumRecordingClient{learned: learned}
	c, k8s := newTestCache(t, client)

	id := "cid-antiinert"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))

	entry, ok := c.entries.Load(id)
	require.True(t, ok, "container must be promoted out of pending")
	require.Equal(t, 0, c.pending.Len())

	// (a) populated without any rebuild ever having run.
	assert.Equal(t, "sum-learned", entry.Checksum,
		"an entry built only via tryPopulateEntry/buildEntry must carry the learned CP's checksum")

	// (b) eligible on the next tick: unchanged profile, unchanged spec.
	client.mu.Lock()
	client.fetches = nil
	client.mu.Unlock()

	c.refreshAllEntries(context.Background())

	sent := client.checksumsFor(entry.CPName)
	require.Len(t, sent, 1, "exactly one learned-CP fetch on the tick")
	assert.Equal(t, "sum-learned", sent[0],
		"the tick after population must offer the stored validator; an empty value here means the optimization is inert")

	// Nothing changed, so the entry must have been fast-skipped, not rebuilt.
	after, ok := c.entries.Load(id)
	require.True(t, ok)
	assert.Same(t, entry, after, "an unchanged profile must fast-skip, not rebuild")
}

// TestPopulatePathStoresNoChecksumWhenSourceSuppliesNone pins the best-effort
// contract: a source that stamps no annotation (every in-cluster CRD client)
// leaves the validator empty, and the guard then declines to request a
// conditional fetch rather than sending "".
func TestPopulatePathStoresNoChecksumWhenSourceSuppliesNone(t *testing.T) {
	learned := learnedCPWithChecksum("learned-cp", "1", "")
	client := &checksumRecordingClient{learned: learned}
	c, k8s := newTestCache(t, client)

	id := "cid-nosum"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))

	entry, ok := c.entries.Load(id)
	require.True(t, ok)
	assert.Empty(t, entry.Checksum, "no annotation on the object means no stored validator")

	client.mu.Lock()
	client.fetches = nil
	client.mu.Unlock()
	c.refreshAllEntries(context.Background())

	for _, sum := range client.checksumsFor(entry.CPName) {
		assert.Empty(t, sum, "no validator held means none offered")
	}
}

// TestAdoptionPathStoresLearnedChecksumNotAuthored covers the correction that
// mirrors the existing entry.RV = learnedRV fix. On the adoption path
// tryPopulateEntry repoints cp at the authored profile BEFORE calling
// buildEntry, so buildEntry's literal sees the authored object. entry.Checksum
// is offered back on a GET of the LEARNED slug, so adopting the authored
// object's checksum would plant a validator describing the wrong object.
func TestAdoptionPathStoresLearnedChecksumNotAuthored(t *testing.T) {
	learned := learnedCPWithChecksum("learned-cp", "1", "sum-learned")
	authored := authoredCPWithChecksum("authored-cp-nginx", "/bin/authored", "a1", "sum-authored")
	client := &checksumRecordingClient{
		learned:  learned,
		authored: map[string]*v1beta1.ContainerProfile{"authored-cp-nginx": authored},
	}
	c, k8s := newTestCache(t, client)

	id := "cid-adopt"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	ev := eventContainer(id)
	ev.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "authored-cp"}
	require.NoError(t, c.addContainer(ev, context.Background()))

	entry, ok := c.entries.Load(id)
	require.True(t, ok)
	require.NotNil(t, entry.UserCPRef, "the authored CP must have been adopted for this test to mean anything")
	assert.Equal(t, "a1", entry.UserCPRV)
	assert.Equal(t, "sum-learned", entry.Checksum,
		"the validator must describe the LEARNED CP (the object CPName points at), never the adopted authored one")
	assert.Equal(t, "1", entry.RV, "the existing learned-RV correction still holds")
}

// TestAdoptionPathWithNoLearnedCPStoresEmptyChecksum is the same correction in
// its other shape: learning is suppressed for user-defined containers, so there
// is often no learned CP at all. The validator must then be empty rather than
// falling back to the authored object's.
func TestAdoptionPathWithNoLearnedCPStoresEmptyChecksum(t *testing.T) {
	authored := authoredCPWithChecksum("authored-cp-nginx", "/bin/authored", "a1", "sum-authored")
	client := &checksumRecordingClient{
		learnedErr: apierrors.NewNotFound(schema.GroupResource{Resource: "containerprofiles"}, "learned"),
		authored:   map[string]*v1beta1.ContainerProfile{"authored-cp-nginx": authored},
	}
	c, k8s := newTestCache(t, client)

	id := "cid-adopt-nolearned"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	ev := eventContainer(id)
	ev.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "authored-cp"}
	require.NoError(t, c.addContainer(ev, context.Background()))

	entry, ok := c.entries.Load(id)
	require.True(t, ok)
	require.NotNil(t, entry.UserCPRef)
	assert.Empty(t, entry.Checksum, "no learned CP means no learned validator")
	assert.Empty(t, entry.RV, "matches the existing learned-RV invariant")
}

// ---------------------------------------------------------------------------
// The guard — each conjunct must independently suppress the offer
// ---------------------------------------------------------------------------

// TestGuardOffersChecksumWhenAllConjunctsHold is the positive control the four
// negative tests below are read against.
func TestGuardOffersChecksumWhenAllConjunctsHold(t *testing.T) {
	learned := learnedCPWithChecksum("learned-cp", "1", "sum-1")
	client := &checksumRecordingClient{learned: learned}
	c := newReconcilerCache(t, client, newControllableK8sCache(), newCountingMetrics())
	seedChecksumEntry(c, "cid", learned, "sum-1", "")

	c.refreshAllEntries(context.Background())

	assert.Equal(t, []string{"sum-1"}, client.checksumsFor("learned-cp"))
}

// TestGuardDeclinesWhenAuthoredCPPresent — UserCPRef != nil. The body is needed
// regardless (the authored CP is re-fetched and re-adopted this tick), so no
// conditional fetch is requested even though a validator is held. The authored
// CP must still be refreshed.
func TestGuardDeclinesWhenAuthoredCPPresent(t *testing.T) {
	learned := learnedCPWithChecksum("learned-cp", "1", "sum-1")
	authored := authoredCP("authored-cp", "/bin/authored", "a1")
	client := &checksumRecordingClient{
		learned:  learned,
		authored: map[string]*v1beta1.ContainerProfile{"authored-cp": authored},
	}
	c := newReconcilerCache(t, client, newControllableK8sCache(), newCountingMetrics())
	e := seedChecksumEntry(c, "cid", learned, "sum-1", "")
	e.UserCPRef = &namespacedName{Namespace: "default", Name: "authored-cp"}

	c.refreshAllEntries(context.Background())

	for _, sum := range client.checksumsFor("learned-cp") {
		assert.Empty(t, sum, "an entry with an authored CP needs the body anyway; it must not ask for a conditional fetch")
	}
	assert.Equal(t, 1, client.fetchCount("authored-cp"), "the authored CP must still be refreshed on this tick")
	client.assertNoChecksumOnAuthoredFetches(t)
}

// TestGuardDeclinesWhenAuthoredRVRecordedButNoAuthoredCP — UserCPRV != "" with
// UserCPRef == nil, the authoredJustDropped shape. UserCPRef == nil alone does
// NOT establish the fast-skip's rvsMatchCP(userDefinedCP, e.UserCPRV) conjunct:
// with no authored CP present that call reduces to rvsMatchCP(nil, e.UserCPRV),
// which is true only for "". Without this conjunct such an entry could take the
// unchanged path and skip its authoredJustDropped handling.
func TestGuardDeclinesWhenAuthoredRVRecordedButNoAuthoredCP(t *testing.T) {
	learned := learnedCPWithChecksum("learned-cp", "1", "sum-1")
	client := &checksumRecordingClient{learned: learned}
	c := newReconcilerCache(t, client, newControllableK8sCache(), newCountingMetrics())
	e := seedChecksumEntry(c, "cid", learned, "sum-1", "")
	e.UserCPRV = "a1" // recorded from a previous tick; UserCPRef is nil now

	c.refreshAllEntries(context.Background())

	for _, sum := range client.checksumsFor("learned-cp") {
		assert.Empty(t, sum, "the authoredJustDropped shape must not request a conditional fetch")
	}
}

// TestGuardDeclinesWhenSpecHashChanged — the projection spec moved, so the entry
// must be re-projected from a real body regardless of whether the content
// changed. No validator is offered, and the rebuild still happens.
func TestGuardDeclinesWhenSpecHashChanged(t *testing.T) {
	learned := learnedCPWithChecksum("learned-cp", "1", "sum-1")
	client := &checksumRecordingClient{learned: learned}
	c := newReconcilerCache(t, client, newControllableK8sCache(), newCountingMetrics())
	c.SetProjectionSpec(execsAllSpec("spec-v2"))
	seedChecksumEntry(c, "cid", learned, "sum-1", "spec-v1")

	c.refreshAllEntries(context.Background())

	for _, sum := range client.checksumsFor("learned-cp") {
		assert.Empty(t, sum, "a changed projection spec needs the body; no conditional fetch")
	}
	after, ok := c.entries.Load("cid")
	require.True(t, ok)
	assert.Equal(t, "spec-v2", after.SpecHash, "the rebuild must still happen and adopt the new spec")
}

// TestGuardDeclinesWhenNoStoredChecksum — nothing to validate against. An empty
// value must not be sent: to a source, "" means "send unconditionally", and
// answering "unchanged" to it would be a protocol violation.
func TestGuardDeclinesWhenNoStoredChecksum(t *testing.T) {
	learned := learnedCPWithChecksum("learned-cp", "1", "sum-1")
	client := &checksumRecordingClient{learned: learned}
	c := newReconcilerCache(t, client, newControllableK8sCache(), newCountingMetrics())
	seedChecksumEntry(c, "cid", learned, "", "")

	c.refreshAllEntries(context.Background())

	assert.Equal(t, []string{""}, client.checksumsFor("learned-cp"))
}

// TestChecksumIsAttachedPerCallSiteNotToSharedContext proves R2's defense.
//
// Both GetContainerProfile call sites in refreshOneEntry derive from the same
// parent context; attaching the validator to that context instead of to the
// learned call would send the learned CP's checksum on the authored CP's fetch,
// and a source could legitimately answer "unchanged" for the wrong object.
//
// The guard makes the literal "same entry, both call sites, one
// carrying a checksum" shape unreachable — an entry with an authored CP never
// offers a validator at all. The reachable equivalent is asserted instead: two
// entries refreshed in ONE tick, one offering a validator and one performing an
// authored fetch. If the validator lived on shared state rather than a per-call
// context, it would leak onto the authored fetch here.
func TestChecksumIsAttachedPerCallSiteNotToSharedContext(t *testing.T) {
	learnedA := learnedCPWithChecksum("learned-a", "1", "sum-a")
	learnedB := learnedCPWithChecksum("learned-b", "1", "sum-b")
	authored := authoredCP("authored-b", "/bin/authored", "a1")
	client := &checksumRecordingClient{
		learned:  learnedA, // served for any non-authored name, including learned-b
		authored: map[string]*v1beta1.ContainerProfile{"authored-b": authored},
	}
	c := newReconcilerCache(t, client, newControllableK8sCache(), newCountingMetrics())

	seedChecksumEntry(c, "cid-a", learnedA, "sum-a", "") // guard passes
	eB := seedChecksumEntry(c, "cid-b", learnedB, "sum-b", "")
	eB.UserCPRef = &namespacedName{Namespace: "default", Name: "authored-b"} // guard fails

	c.refreshAllEntries(context.Background())

	assert.Equal(t, []string{"sum-a"}, client.checksumsFor("learned-a"),
		"the guard-passing entry's learned fetch carries its own validator")
	for _, sum := range client.checksumsFor("learned-b") {
		assert.Empty(t, sum, "the authored-CP entry's learned fetch must carry nothing")
	}
	require.Equal(t, 1, client.fetchCount("authored-b"))
	client.assertNoChecksumOnAuthoredFetches(t)
}

// conditionalChecksumClient behaves like a real conditional source: when the
// caller offers a validator equal to the profile's CURRENT content checksum it
// answers ErrProfileUnchanged and sends no body; otherwise it returns the
// profile. This is what makes the state-freeze regression observable — a
// recording-only client would hand back a body regardless and hide it.
type conditionalChecksumClient struct {
	mu       sync.Mutex
	cp       *v1beta1.ContainerProfile
	offered  []string
	unchange int
}

var _ storage.ProfileClient = (*conditionalChecksumClient)(nil)

func (c *conditionalChecksumClient) GetContainerProfile(ctx context.Context, _, _ string) (*v1beta1.ContainerProfile, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	offered := storage.KnownChecksumFromContext(ctx)
	c.offered = append(c.offered, offered)
	if offered != "" && offered == c.cp.Annotations[storage.ContainerProfileChecksumAnnotationKey] {
		c.unchange++
		return nil, storage.ErrProfileUnchanged
	}
	return c.cp, nil
}

func (c *conditionalChecksumClient) lastOffered() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.offered) == 0 {
		return ""
	}
	return c.offered[len(c.offered)-1]
}

// TestGuardDeclinesWhileStateNotYetTerminal is the regression test for the
// cached-state freeze.
//
// e.State comes from the status/completion ANNOTATIONS, which sit outside the
// content checksum. So a profile finishing its learning period — partial ->
// full, byte-identical content — presents a checksum that still matches. If the
// guard ignored the cached state, that tick would be answered "unchanged", the
// rebuild that refreshes e.State would never run, and because the checksum stays
// valid the SAME thing would happen on every later tick: the state freezes at
// partial permanently, and rulemanager keeps reporting a completed profile as
// incomplete.
//
// The walkthrough below covers all three phases: declined while learning,
// state correctly picked up when it terminalizes, and the shortcut engaging
// afterwards so the steady-state win is genuinely preserved.
func TestGuardDeclinesWhileStateNotYetTerminal(t *testing.T) {
	// A profile still learning: non-terminal state, but a validator already
	// stored from a previous fetch.
	learning := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "learned-cp", Namespace: "default", ResourceVersion: "1",
			Annotations: map[string]string{
				helpersv1.StatusMetadataKey:                   helpersv1.Completed,
				helpersv1.CompletionMetadataKey:               helpersv1.Partial,
				storage.ContainerProfileChecksumAnnotationKey: "sum-1",
			},
		},
		Spec: v1beta1.ContainerProfileSpec{Execs: []v1beta1.ExecCalls{{Path: "/bin/learned"}}},
	}
	client := &conditionalChecksumClient{cp: learning}
	c := newReconcilerCache(t, client, newControllableK8sCache(), newCountingMetrics())
	seedChecksumEntry(c, "cid", learning, "sum-1", "")

	// Phase 1 — still partial: no validator offered, so a body is fetched.
	c.refreshAllEntries(context.Background())
	assert.Empty(t, client.lastOffered(), "a non-terminal cached state must not take the conditional shortcut")
	assert.Zero(t, client.unchange)

	// Phase 2 — the learning period completes. This is a METADATA-ONLY write:
	// the RV moves and the completion flips, but the content checksum is
	// unchanged, which is exactly what makes the freeze possible.
	learning.ResourceVersion = "2"
	learning.Annotations[helpersv1.CompletionMetadataKey] = helpersv1.Full

	c.refreshAllEntries(context.Background())
	assert.Empty(t, client.lastOffered(), "the cached state is still partial at guard time; the body is still needed")

	after, ok := c.entries.Load("cid")
	require.True(t, ok)
	assert.Equal(t, helpersv1.Full, after.State.Completion,
		"the completion flip MUST reach the cache; freezing here is what rulemanager would report as a permanently-partial profile")
	assert.Equal(t, helpersv1.Completed, after.State.Status)

	// Phase 3 — now genuinely terminal, so the shortcut engages and the source
	// gets to answer "unchanged". The optimization is preserved, not disabled.
	c.refreshAllEntries(context.Background())
	assert.Equal(t, "sum-1", client.lastOffered(), "a Completed+Full entry must still use the conditional shortcut")
	assert.Equal(t, 1, client.unchange, "the source answered unchanged exactly once, on the terminal tick")

	final, ok := c.entries.Load("cid")
	require.True(t, ok)
	assert.Same(t, after, final, "the unchanged answer keeps the entry as-is")
}

// TestGuardDeclinesForTooLargeState pins the deliberate narrowness of the state
// conjunct: TooLarge is terminal for the learned-status gate, but it is not the
// Completed+Full predicate rulemanager treats as final, so such an entry keeps
// fetching bodies rather than risking a frozen state.
func TestGuardDeclinesForTooLargeState(t *testing.T) {
	learned := learnedCPWithChecksum("learned-cp", "1", "sum-1")
	learned.Annotations[helpersv1.StatusMetadataKey] = helpersv1.TooLarge
	learned.Annotations[helpersv1.CompletionMetadataKey] = helpersv1.Partial
	client := &checksumRecordingClient{learned: learned}
	c := newReconcilerCache(t, client, newControllableK8sCache(), newCountingMetrics())
	seedChecksumEntry(c, "cid", learned, "sum-1", "")

	c.refreshAllEntries(context.Background())

	for _, sum := range client.checksumsFor("learned-cp") {
		assert.Empty(t, sum, "a TooLarge/partial entry must not take the conditional shortcut")
	}
}

// ---------------------------------------------------------------------------
// Sentinel handling
// ---------------------------------------------------------------------------

// TestSentinelKeepsEntryPointerIdentical — on ErrProfileUnchanged the entry the
// caller already holds is known-good, so refreshOneEntry must leave it entirely
// alone. Identity, not equality, is the assertion that discriminates:
// rebuildEntryFromSources always constructs a FRESH literal, so an equal-but-new
// pointer would mean a rebuild happened.
func TestSentinelKeepsEntryPointerIdentical(t *testing.T) {
	learned := learnedCPWithChecksum("learned-cp", "1", "sum-1")
	client := &checksumRecordingClient{learnedErr: storage.ErrProfileUnchanged}
	c := newReconcilerCache(t, client, newControllableK8sCache(), newCountingMetrics())
	before := seedChecksumEntry(c, "cid", learned, "sum-1", "")

	c.refreshAllEntries(context.Background())

	after, ok := c.entries.Load("cid")
	require.True(t, ok, "the entry must not be evicted")
	assert.Same(t, before, after, "the sentinel must not rebuild the entry")
	assert.Equal(t, "sum-1", after.Checksum, "the stored validator is left untouched")
	assert.Equal(t, []string{"sum-1"}, client.checksumsFor("learned-cp"),
		"the sentinel is only legitimate in reply to a request that carried a validator")
}

// TestSentinelLeavesResourceVersionIntentionallyStale pins the one accepted
// divergence of the conditional path from the body-fetching path.
//
// A checksum match proves the CONTENT is byte-identical; it says nothing about
// ResourceVersion. RV can bump on a metadata-only write (e.g. a status-annotation
// flip), and annotations are outside the content checksum — so on a sentinel
// response the client never sees the new RV and e.RV stays at its old value.
//
// This is deliberate, not a bug: every consumer downstream of this cache reads
// the projected CONTENT, and e.RV only serves as a change detector for the next
// tick, where a stale-but-lower RV is conservative (it can cause an extra
// rebuild, never a missed one). Asserted POSITIVELY so the behavior is pinned as
// intended rather than rediscovered later as a defect.
func TestSentinelLeavesResourceVersionIntentionallyStale(t *testing.T) {
	learned := learnedCPWithChecksum("learned-cp", "1", "sum-1")
	client := &checksumRecordingClient{learnedErr: storage.ErrProfileUnchanged}
	c := newReconcilerCache(t, client, newControllableK8sCache(), newCountingMetrics())
	before := seedChecksumEntry(c, "cid", learned, "sum-1", "")

	// Simulate a metadata-only write on the server: the object's RV moved but
	// its content checksum did not, so the source still answers "unchanged".
	learned.ResourceVersion = "2"
	learned.Annotations[helpersv1.StatusMetadataKey] = helpersv1.TooLarge

	c.refreshAllEntries(context.Background())

	after, ok := c.entries.Load("cid")
	require.True(t, ok)
	assert.Same(t, before, after)
	assert.Equal(t, "1", after.RV,
		"e.RV is INTENDED to lag a metadata-only write until the next unconditional fetch")
	assert.Equal(t, helpersv1.Completed, after.State.Status,
		"the learned-status gate is likewise not re-evaluated on the sentinel path")
}

// TestSentinelIsNotSwallowedByTheNotFoundPath pins that the sentinel is handled
// EXPLICITLY rather than left to the pre-existing error handling (D3).
//
// Scope, stated precisely, because it is narrower than "the branch is first":
// verified by deliberately breaking the code, this test fails when the sentinel
// branch is absent (the error's not-found shape then sets cp = nil, no authored
// CP is found either, and the entry is EVICTED), and it passes with the branch
// present. It does NOT distinguish the branch sitting before the IsNotFound
// check from it sitting just after — both return early with the entry intact.
// Ordering is kept as written for clarity, not because this test enforces it.
//
// Note also that a bare storage.ErrProfileUnchanged would NOT be caught by this
// test's mechanism at all: it falls into the generic transient-error path, which
// also keeps the entry, so the two are indistinguishable by behavior alone (they
// differ only in the log line emitted). That is exactly why the fixture below is
// built to satisfy the not-found predicate too — it is the one shape where the
// missing branch has a visible consequence.
func TestSentinelIsNotSwallowedByTheNotFoundPath(t *testing.T) {
	learned := learnedCPWithChecksum("learned-cp", "1", "sum-1")
	both := fmt.Errorf("%w: %w",
		storage.ErrProfileUnchanged,
		apierrors.NewNotFound(schema.GroupResource{Resource: "containerprofiles"}, "learned-cp"))
	require.True(t, errors.Is(both, storage.ErrProfileUnchanged), "fixture must satisfy the sentinel predicate")
	require.True(t, apierrors.IsNotFound(both), "fixture must also satisfy the not-found predicate")

	client := &checksumRecordingClient{learnedErr: both}
	c := newReconcilerCache(t, client, newControllableK8sCache(), newCountingMetrics())
	before := seedChecksumEntry(c, "cid", learned, "sum-1", "")

	c.refreshAllEntries(context.Background())

	after, ok := c.entries.Load("cid")
	require.True(t, ok, "not-found won the ordering: the entry was evicted instead of kept")
	assert.Same(t, before, after)
}

// TestNonSentinelErrorIsNotMistakenForUnchanged — an unrelated transport failure
// must fall through to the existing transient-error handling, which also keeps
// the entry. Guards against a too-broad match (e.g. a string comparison).
func TestNonSentinelErrorIsNotMistakenForUnchanged(t *testing.T) {
	learned := learnedCPWithChecksum("learned-cp", "1", "sum-1")
	client := &checksumRecordingClient{learnedErr: errors.New("container profile unchanged-ish: connection reset")}
	c := newReconcilerCache(t, client, newControllableK8sCache(), newCountingMetrics())
	before := seedChecksumEntry(c, "cid", learned, "sum-1", "")

	c.refreshAllEntries(context.Background())

	after, ok := c.entries.Load("cid")
	require.True(t, ok)
	assert.Same(t, before, after, "a transient error also keeps the entry, by the pre-existing path")
}

// ---------------------------------------------------------------------------
// Rebuild path
// ---------------------------------------------------------------------------

// TestRebuildRefreshesStoredChecksum — a genuine content change must roll the
// stored validator forward, or the next tick would offer a checksum describing
// the previous body.
func TestRebuildRefreshesStoredChecksum(t *testing.T) {
	learned := learnedCPWithChecksum("learned-cp", "1", "sum-1")
	client := &checksumRecordingClient{learned: learned}
	c := newReconcilerCache(t, client, newControllableK8sCache(), newCountingMetrics())
	seedChecksumEntry(c, "cid", learned, "sum-1", "")

	// Content changed on the server: new RV, new checksum, new body.
	learned.ResourceVersion = "2"
	learned.Annotations[storage.ContainerProfileChecksumAnnotationKey] = "sum-2"

	c.refreshAllEntries(context.Background())

	after, ok := c.entries.Load("cid")
	require.True(t, ok)
	assert.Equal(t, "sum-2", after.Checksum, "a rebuild must adopt the fresh validator")
	assert.Equal(t, "2", after.RV)
}

// TestRebuildStoresLearnedChecksumNotAuthored — the rebuild path's counterpart
// to the adoption-path correction: Checksum tracks the learned CP even when an
// authored CP replaces it as the projection base.
func TestRebuildStoresLearnedChecksumNotAuthored(t *testing.T) {
	learned := learnedCPWithChecksum("learned-cp", "1", "sum-learned")
	authored := authoredCPWithChecksum("authored-cp", "/bin/authored", "a1", "sum-authored")
	client := &checksumRecordingClient{
		learned:  learned,
		authored: map[string]*v1beta1.ContainerProfile{"authored-cp": authored},
	}
	c := newReconcilerCache(t, client, newControllableK8sCache(), newCountingMetrics())
	e := seedChecksumEntry(c, "cid", learned, "", "")
	e.UserCPRef = &namespacedName{Namespace: "default", Name: "authored-cp"}

	c.refreshAllEntries(context.Background())

	after, ok := c.entries.Load("cid")
	require.True(t, ok)
	assert.NotSame(t, e, after, "an authored CP appearing must rebuild the entry")
	assert.Equal(t, "sum-learned", after.Checksum,
		"the validator tracks the learned CP even when an authored CP is the projection base")
}

// ---------------------------------------------------------------------------
// Context vocabulary
// ---------------------------------------------------------------------------

func TestKnownChecksumContextRoundTrip(t *testing.T) {
	assert.Empty(t, storage.KnownChecksumFromContext(context.Background()),
		"a bare context must report no validator, never panic")

	ctx := storage.WithKnownChecksum(context.Background(), "sum-1")
	assert.Equal(t, "sum-1", storage.KnownChecksumFromContext(ctx))

	// The parent is not mutated: attaching per call is what keeps the authored
	// fetch clean.
	assert.Empty(t, storage.KnownChecksumFromContext(context.Background()))
}
