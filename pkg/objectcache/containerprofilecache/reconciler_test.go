package containerprofilecache

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// controllableK8sCache is a K8sObjectCache stub whose GetPod can be scripted
// per (namespace, podName) and whose invocation count is observable for the
// cancellation test. The unexported methods required by the interface are
// implemented as no-ops.
type controllableK8sCache struct {
	pods    map[string]*corev1.Pod
	podHook func(namespace, podName string) *corev1.Pod // optional override
	calls   atomic.Int64
}

var _ objectcache.K8sObjectCache = (*controllableK8sCache)(nil)

func newControllableK8sCache() *controllableK8sCache {
	return &controllableK8sCache{pods: map[string]*corev1.Pod{}}
}

func (k *controllableK8sCache) setPod(namespace, podName string, pod *corev1.Pod) {
	k.pods[namespace+"/"+podName] = pod
}

func (k *controllableK8sCache) GetPod(namespace, podName string) *corev1.Pod {
	k.calls.Add(1)
	if k.podHook != nil {
		return k.podHook(namespace, podName)
	}
	if p, ok := k.pods[namespace+"/"+podName]; ok {
		return p
	}
	return nil
}
func (k *controllableK8sCache) GetPodSpec(_, _ string) *corev1.PodSpec     { return nil }
func (k *controllableK8sCache) GetPodStatus(_, _ string) *corev1.PodStatus { return nil }
func (k *controllableK8sCache) GetApiServerIpAddress() string              { return "" }
func (k *controllableK8sCache) GetPods() []*corev1.Pod                     { return nil }
func (k *controllableK8sCache) SetSharedContainerData(_ string, _ *objectcache.WatchedContainerData) {
}
func (k *controllableK8sCache) GetSharedContainerData(_ string) *objectcache.WatchedContainerData {
	return nil
}
func (k *controllableK8sCache) DeleteSharedContainerData(_ string) {}

// countingProfileClient tracks per-method RPC counts so tests can assert
// fast-skip behavior. It is name-aware: the base/learned CP is served for its
// own name, an optional authored CP for its own name, and every other name
// returns NotFound. This lets refresh tests distinguish the learned slug from
// the authored/overlay CP instead of returning the same object for any name.
type countingProfileClient struct {
	cp     *v1beta1.ContainerProfile // learned/base CP, keyed by cp.Name
	userCP *v1beta1.ContainerProfile // authored CP, keyed by userCP.Name

	cpCalls atomic.Int64
}

var _ storage.ProfileClient = (*countingProfileClient)(nil)

func (f *countingProfileClient) GetContainerProfile(_ context.Context, _, name string) (*v1beta1.ContainerProfile, error) {
	f.cpCalls.Add(1)
	if f.userCP != nil && name == f.userCP.Name {
		return f.userCP, nil
	}
	if f.cp != nil && name == f.cp.Name {
		return f.cp, nil
	}
	return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "containerprofiles"}, name)
}

// countingMetrics tallies reconciler eviction + entry-count signals so tests
// can assert eviction behavior.
type countingMetrics struct {
	metricsmanager.MetricsMock
	mu           sync.Mutex
	evictions    map[string]int
	entriesByKnd map[string]float64
}

func newCountingMetrics() *countingMetrics {
	return &countingMetrics{
		evictions:    map[string]int{},
		entriesByKnd: map[string]float64{},
	}
}
func (m *countingMetrics) ReportContainerProfileReconcilerEviction(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictions[reason]++
}
func (m *countingMetrics) SetContainerProfileCacheEntries(kind string, count float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entriesByKnd[kind] = count
}
func (m *countingMetrics) eviction(reason string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.evictions[reason]
}

// newReconcilerCache returns a cache wired with a controllable k8s cache and
// a counting profile client. Tests drive reconcileOnce / refreshAllEntries
// directly.
func newReconcilerCache(t *testing.T, client storage.ProfileClient, k8s objectcache.K8sObjectCache, metrics metricsmanager.MetricsManager) *ContainerProfileCacheImpl {
	t.Helper()
	cfg := config.Config{ProfilesCacheRefreshRate: 30 * time.Second}
	return NewContainerProfileCache(cfg, client, k8s, metrics)
}

// newEntry makes a CachedContainerProfile for tests without going through
// addContainer (which requires priming shared data + instance-id machinery).
func newEntry(cp *v1beta1.ContainerProfile, containerName, podName, namespace, podUID string) *CachedContainerProfile {
	return &CachedContainerProfile{
		Projected:     Apply(nil, cp, nil),
		State:         &objectcache.ProfileState{Name: cp.Name},
		ContainerName: containerName,
		PodName:       podName,
		Namespace:     namespace,
		PodUID:        podUID,
		CPName:        cp.Name,
		RV:            cp.ResourceVersion,
	}
}

// TestReconcilerKeepsEntryWhenPodMissing — entry whose pod returns nil is
// retained (not evicted). The k8s pod cache routinely lags container events
// on busy nodes; evicting on "pod not found" churned every entry per tick.
// Cleanup for terminated containers flows through deleteContainer.
func TestReconcilerKeepsEntryWhenPodMissing(t *testing.T) {
	cp := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "cp", Namespace: "default", ResourceVersion: "1"}}
	client := &countingProfileClient{cp: cp}
	k8s := newControllableK8sCache() // GetPod returns nil for everything
	metrics := newCountingMetrics()
	c := newReconcilerCache(t, client, k8s, metrics)

	id := "c1"
	c.entries.Set(id, newEntry(cp, "nginx", "nginx-abc", "default", "uid-1"))

	c.reconcileOnce(context.Background())

	assert.NotNil(t, c.GetProjectedContainerProfile(id), "entry must be retained when pod is missing from cache")
	assert.Equal(t, 0, metrics.eviction("pod_stopped"), "no eviction when pod is absent")
}

// TestReconcilerEvictsTerminatedContainer — entry whose container has
// clearly transitioned to Terminated state IS evicted.
func TestReconcilerEvictsTerminatedContainer(t *testing.T) {
	cp := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "cp", Namespace: "default", ResourceVersion: "1"}}
	client := &countingProfileClient{cp: cp}
	k8s := newControllableK8sCache()
	id := "terminated123"
	k8s.setPod("default", "nginx-abc", &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "nginx-abc", Namespace: "default", UID: types.UID("uid-1")},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name:        "nginx",
			ContainerID: "containerd://" + id,
			State:       corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}},
		}}},
	})
	metrics := newCountingMetrics()
	c := newReconcilerCache(t, client, k8s, metrics)
	c.entries.Set(id, newEntry(cp, "nginx", "nginx-abc", "default", "uid-1"))

	c.reconcileOnce(context.Background())

	assert.Nil(t, c.GetProjectedContainerProfile(id), "terminated container entry must be evicted")
	assert.Equal(t, 1, metrics.eviction("pod_stopped"), "should report one eviction")
}

// TestReconcilerKeepsWaitingContainer — entry whose container is in Waiting
// state (e.g. newly-started or pre-running init container with empty ID)
// must NOT be evicted.
func TestReconcilerKeepsWaitingContainer(t *testing.T) {
	cp := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "cp", Namespace: "default", ResourceVersion: "1"}}
	client := &countingProfileClient{cp: cp}
	k8s := newControllableK8sCache()
	id := "waitingabc"
	k8s.setPod("default", "nginx-abc", &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "nginx-abc", Namespace: "default", UID: types.UID("uid-1")},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name:        "nginx",
			ContainerID: "containerd://" + id,
			State:       corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}},
		}}},
	})
	metrics := newCountingMetrics()
	c := newReconcilerCache(t, client, k8s, metrics)
	c.entries.Set(id, newEntry(cp, "nginx", "nginx-abc", "default", "uid-1"))

	c.reconcileOnce(context.Background())

	assert.NotNil(t, c.GetProjectedContainerProfile(id), "waiting container entry must be retained")
	assert.Equal(t, 0, metrics.eviction("pod_stopped"), "no eviction for Waiting state")
}

// TestReconcilerKeepsRunningContainer — entry is kept when pod has a Running
// container status matching `id`.
func TestReconcilerKeepsRunningContainer(t *testing.T) {
	cp := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "cp", Namespace: "default", ResourceVersion: "1"}}
	client := &countingProfileClient{cp: cp}
	k8s := newControllableK8sCache()
	id := "abc123"
	k8s.setPod("default", "nginx-abc", &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "nginx-abc", Namespace: "default", UID: types.UID("uid-1")},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name:        "nginx",
			ContainerID: "containerd://" + id,
			State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
		}}},
	})
	metrics := newCountingMetrics()
	c := newReconcilerCache(t, client, k8s, metrics)
	c.entries.Set(id, newEntry(cp, "nginx", "nginx-abc", "default", "uid-1"))

	c.reconcileOnce(context.Background())

	assert.NotNil(t, c.GetProjectedContainerProfile(id), "running container entry must remain")
	assert.Equal(t, 0, metrics.eviction("pod_stopped"), "should not evict a running entry")
}

// TestIsContainerRunning_PreRunningInitWithEmptyContainerID — T2c from the
// plan risks. Pre-running init container publishes an empty ContainerID, so
// we fall back to (Name, PodUID) matching.
func TestIsContainerRunning_PreRunningInitWithEmptyContainerID(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: types.UID("pod-uid-123")},
		Status: corev1.PodStatus{InitContainerStatuses: []corev1.ContainerStatus{{
			Name:        "init-1",
			ContainerID: "", // not published yet
			State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
		}}},
	}
	entry := &CachedContainerProfile{ContainerName: "init-1", PodUID: "pod-uid-123"}
	assert.True(t, isContainerRunning(pod, entry, "init-cid"),
		"pre-running init container with empty ContainerID must match on (Name, PodUID)")
}

// TestIsContainerRunning_ContainerIDMatchTakesPriority — the containerd:// etc
// prefix is stripped before comparing against the cache key.
func TestIsContainerRunning_ContainerIDMatchTakesPriority(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: types.UID("pod-uid-123")},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name:        "nginx",
			ContainerID: "docker://abc",
			State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
		}}},
	}
	entry := &CachedContainerProfile{ContainerName: "nginx", PodUID: "pod-uid-123"}
	assert.True(t, isContainerRunning(pod, entry, "abc"), "docker:// prefix should be stripped")
	assert.False(t, isContainerRunning(pod, entry, "zzz"), "id mismatch should return false")
}

// TestIsContainerRunning_NotRunning — container exists but is Terminated.
func TestIsContainerRunning_NotRunning(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: types.UID("pod-uid-123")},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name:        "nginx",
			ContainerID: "containerd://abc",
			State:       corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}},
		}}},
	}
	entry := &CachedContainerProfile{ContainerName: "nginx", PodUID: "pod-uid-123"}
	assert.False(t, isContainerRunning(pod, entry, "abc"))
}

// TestReconcilerExitsOnCtxCancel — R2 from plan risks, delta #3. Cancelling
// ctx mid-Range stops iteration early.
func TestReconcilerExitsOnCtxCancel(t *testing.T) {
	cp := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "cp", Namespace: "default", ResourceVersion: "1"}}
	client := &countingProfileClient{cp: cp}
	k8s := newControllableK8sCache()
	ctx, cancel := context.WithCancel(context.Background())
	// Hook: cancel ctx on the 3rd GetPod call, return nil to drive the
	// Range's continuation. After cancel(), ctx.Err() is set and subsequent
	// Range iterations should short-circuit.
	var visits atomic.Int64
	k8s.podHook = func(_, _ string) *corev1.Pod {
		visits.Add(1)
		if visits.Load() == 3 {
			cancel()
		}
		return nil
	}
	metrics := newCountingMetrics()
	c := newReconcilerCache(t, client, k8s, metrics)

	// Populate 100 entries.
	for i := 0; i < 100; i++ {
		id := "c-" + itoa(i)
		c.entries.Set(id, newEntry(cp, "nginx", "pod-"+itoa(i), "default", "uid-"+itoa(i)))
	}

	c.reconcileOnce(ctx)

	got := visits.Load()
	assert.Less(t, got, int64(100), "ctx cancel should short-circuit the Range well before 100 iterations")
	assert.GreaterOrEqual(t, got, int64(3), "should observe at least the iterations up to cancel")
	// We do NOT assert a specific eviction count: entries visited before the
	// cancel were appended to toEvict and DO get evicted. The invariant under
	// test is only that iteration stopped early.
}

// TestRefreshRebuildsOnCPChange — CP RV changed; entry rebuilds with fresh CP.
func TestRefreshRebuildsOnCPChange(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cp", Namespace: "default", ResourceVersion: "101",
			Annotations: map[string]string{helpersv1.StatusMetadataKey: helpersv1.Completed},
		},
		Spec: v1beta1.ContainerProfileSpec{Capabilities: []string{"SYS_ADMIN"}},
	}
	client := &countingProfileClient{cp: cp}
	k8s := newControllableK8sCache()
	metrics := newCountingMetrics()
	c := newReconcilerCache(t, client, k8s, metrics)

	oldCP := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "cp", Namespace: "default", ResourceVersion: "100"},
	}
	id := "c1"
	entry := newEntry(oldCP, "nginx", "nginx-abc", "default", "uid-1")
	c.entries.Set(id, entry)

	c.refreshAllEntries(context.Background())

	stored, ok := c.entries.Load(id)
	require.True(t, ok)
	assert.Equal(t, "101", stored.RV, "RV must update to the fresh CP's version")
}

// TestRefreshNoEntryWhenCPGetFails — storage error on CP keeps the existing
// entry unchanged (no deletion).
func TestRefreshNoEntryWhenCPGetFails(t *testing.T) {
	cp := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "cp", Namespace: "default", ResourceVersion: "100"}}
	failing := &failingProfileClient{cpErr: assertErr{}}
	k8s := newControllableK8sCache()
	metrics := newCountingMetrics()
	c := newReconcilerCache(t, failing, k8s, metrics)

	id := "c1"
	entry := newEntry(cp, "nginx", "nginx-abc", "default", "uid-1")
	c.entries.Set(id, entry)

	c.refreshAllEntries(context.Background())

	stored, ok := c.entries.Load(id)
	require.True(t, ok, "CP fetch error must not delete the entry")
	assert.Same(t, entry, stored, "entry pointer must not change when CP fetch fails")
}

// TestRefreshPreservesEntryOnTransientUserCPError — a transient error fetching
// the user-defined (label-referenced) ContainerProfile must not strip the
// authored overlay from the cache. When refreshOneEntry re-fetches the
// user-defined CP (because entry.UserCPRef is set) and the GET returns an error
// while the entry already holds a non-empty UserCPRV, refreshOneEntry must keep
// the old entry unchanged (same pointer) rather than rebuilding without the
// authored profile and clearing its RV. Regression test for the refreshRPC
// timeout → silent nil → spurious rebuild path, migrated from the removed
// legacy "ug-" user-managed overlay to the user-defined CP mechanism.
func TestRefreshPreservesEntryOnTransientUserCPError(t *testing.T) {
	// Base (learned) CP is terminal (Completed) and its RV matches the entry, so
	// the base fetch succeeds without an early return and refreshOneEntry reaches
	// the user-defined CP fetch.
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cp", Namespace: "default", ResourceVersion: "100",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Full,
				helpersv1.StatusMetadataKey:     helpersv1.Completed,
			},
		},
		Spec: v1beta1.ContainerProfileSpec{Capabilities: []string{"SYS_PTRACE"}},
	}

	// The user-defined CP fetch (by UserCPRef.Name) fails transiently.
	client := &userCPErrorClient{cp: cp, userName: "override", userCPErr: assertErr{}}
	k8s := newControllableK8sCache()
	c := newReconcilerCache(t, client, k8s, nil)

	id := "c1"
	entry := &CachedContainerProfile{
		Projected:     Apply(nil, cp, nil),
		State:         &objectcache.ProfileState{Name: cp.Name},
		ContainerName: "nginx",
		PodName:       "nginx-abc",
		Namespace:     "default",
		PodUID:        "uid-1",
		CPName:        "cp",
		RV:            "100",
		WorkloadName:  "nginx",
		UserCPRef:     &namespacedName{Namespace: "default", Name: "override"},
		UserCPRV:      "9",
	}
	c.entries.Set(id, entry)

	c.refreshAllEntries(context.Background())

	stored, ok := c.entries.Load(id)
	require.True(t, ok, "user-defined CP error must not delete the entry")
	assert.Same(t, entry, stored, "entry pointer must not change when user-defined CP fetch fails transiently")
	// The authored RV must be unchanged (not cleared to "").
	assert.Equal(t, "9", stored.UserCPRV, "UserCPRV must be unchanged after a transient user-defined CP fetch error")
}

// userCPErrorClient returns a valid base CP for any name except userName, whose
// fetch fails with userCPErr. Used to test user-defined CP error-preservation:
// the base/learned CP fetch succeeds while the label-referenced authored CP GET
// fails transiently.
type userCPErrorClient struct {
	cp        *v1beta1.ContainerProfile
	userName  string
	userCPErr error
}

var _ storage.ProfileClient = (*userCPErrorClient)(nil)

func (o *userCPErrorClient) GetContainerProfile(_ context.Context, _, name string) (*v1beta1.ContainerProfile, error) {
	if name == o.userName {
		return nil, o.userCPErr
	}
	return o.cp, nil
}

// --- helpers ---

// itoa is a local int-to-string so tests don't pull in strconv just for one
// call site.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	buf := [20]byte{}
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// assertErr is a trivial error sentinel used in a few negative tests.
type assertErr struct{}

func (assertErr) Error() string { return "synthetic error" }

// failingProfileClient always returns cpErr from GetContainerProfile.
type failingProfileClient struct {
	cpErr error
}

var _ storage.ProfileClient = (*failingProfileClient)(nil)

func (f *failingProfileClient) GetContainerProfile(_ context.Context, _, _ string) (*v1beta1.ContainerProfile, error) {
	return nil, f.cpErr
}

// silence unused-import linter: helpersv1 is referenced only via the const in
// containerprofilecache.go (used by some entries). Import explicitly so the
// file compiles without the import when those constants aren't dereferenced.
var _ = helpersv1.CompletionMetadataKey

// TestRefreshHonorsContextCancellationMidRPC verifies that a context
// cancellation while refreshOneEntry is blocked in GetContainerProfile
// causes the refresh to return within the rpcBudget, not hang for the
// full reconciler timeout.
func TestRefreshHonorsContextCancellationMidRPC(t *testing.T) {
	// Buffered so the signal is stored even if the test's <-blocked read is
	// slightly delayed — prevents a lossy non-blocking send from dropping it.
	blocked := make(chan struct{}, 1)
	unblock := make(chan struct{})
	blocking := &blockingProfileClient{
		blocked: blocked,
		unblock: unblock,
	}
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "cp-1", Namespace: "default", ResourceVersion: "42"},
	}
	// Seed an existing entry so refreshOneEntry attempts a CP re-fetch.
	k8s := newControllableK8sCache()
	cfg := config.Config{
		ProfilesCacheRefreshRate: 30 * time.Second,
		StorageRPCBudget:         100 * time.Millisecond,
	}
	cache := NewContainerProfileCache(cfg, blocking, k8s, nil)
	cache.SeedEntryForTest("id1", &CachedContainerProfile{
		Projected:     Apply(nil, cp, nil),
		State:         &objectcache.ProfileState{Name: cp.Name},
		ContainerName: "c1",
		PodName:       "pod1",
		Namespace:     "default",
		PodUID:        "uid1",
		CPName:        "cp-1",
		RV:            "old-rv", // differs from cp.RV so fast-skip is skipped
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		cache.refreshAllEntries(ctx)
	}()

	// Wait for the RPC to block, then cancel the context.
	<-blocked
	cancel()

	// The refresh must return within 2s of cancellation (well above the
	// 100ms rpcBudget; the generous budget accommodates loaded CI runners).
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("refreshAllEntries did not return after context cancellation")
	}
	close(unblock)
}

// blockingProfileClient blocks GetContainerProfile until unblocked.
type blockingProfileClient struct {
	blocked chan struct{}
	unblock chan struct{}
}

var _ storage.ProfileClient = (*blockingProfileClient)(nil)

func (b *blockingProfileClient) GetContainerProfile(ctx context.Context, _, _ string) (*v1beta1.ContainerProfile, error) {
	b.blocked <- struct{}{} // buffered(1): stored if reader hasn't arrived yet
	select {
	case <-b.unblock:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TestRetryPendingEntries_CPCreatedAfterAdd exercises the bug that slipped
// through PR #788 component tests: at EventTypeAddContainer the CP may not
// yet be in storage (it is created asynchronously by containerprofilemanager
// after observing the container). The new cache must retry per reconciler
// tick; otherwise the container is permanently absent from the cache and
// rule evaluation short-circuits as "no profile".
func TestRetryPendingEntries_CPCreatedAfterAdd(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cp-pending",
			Namespace:       "default",
			ResourceVersion: "1",
			Annotations:     map[string]string{helpersv1.StatusMetadataKey: helpersv1.Completed},
		},
	}

	// Start with storage returning 404 for the initial GET.
	client := &fakeProfileClient{cp: nil, cpErr: assertErrNotFound("cp-pending")}
	c, k8s := newTestCache(t, client)

	id := "container-pending"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")

	// addContainer: sees 404 -> pending bookkeeping, not an entry.
	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))
	assert.Nil(t, c.GetProjectedContainerProfile(id), "no entry before CP exists in storage")
	assert.Equal(t, 1, c.pending.Len(), "container recorded as pending")

	// Storage creates the CP asynchronously (60s after start in real runs).
	client.cp = cp
	client.cpErr = nil

	// Simulate one reconciler tick. retryPendingEntries iterates pending and
	// promotes on successful GET.
	c.retryPendingEntries(context.Background())

	assert.NotNil(t, c.GetProjectedContainerProfile(id), "entry promoted after CP appears")
	assert.Equal(t, 0, c.pending.Len(), "pending drained on successful promotion")
	// Two GETs total: this container carries no user-defined-profile label, so
	// each populate attempt issues exactly one GetContainerProfile call for the
	// base CP (there is no legacy "ug-" overlay fetch anymore). addContainer
	// performs one attempt (base 404), the retry performs the second (base 200).
	assert.Equal(t, 2, client.getCPCalls, "each tick re-GETs the base CP exactly once")
}

// TestPendingEntriesAreNotGCedBeforeRetry verifies we no longer drop pending
// entries from reconcileOnce. The component-tests regression (CI run
// 24781030436 on ce329196) showed the k8s pod cache and container statuses
// lag the containerwatcher Add event by tens of seconds on busy nodes, so a
// pod-state-driven GC dropped every pending entry before retries had a
// chance to succeed. Cleanup now flows exclusively through deleteContainer.
func TestPendingEntriesAreNotGCedBeforeRetry(t *testing.T) {
	client := &fakeProfileClient{cp: nil, cpErr: assertErrNotFound("cp-missing")}
	c, k8s := newTestCache(t, client)
	_ = k8s

	id := "container-pending"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))
	require.Equal(t, 1, c.pending.Len())

	// Several reconciler passes with nil-returning GetPod must leave the
	// pending entry in place so retry has a chance to succeed once profile
	// data shows up in storage.
	for range 3 {
		c.reconcileOnce(context.Background())
	}
	assert.Equal(t, 1, c.pending.Len(), "pending entry retained across reconcile ticks")

	// Only deleteContainer clears pending.
	c.deleteContainer(id)
	assert.Equal(t, 0, c.pending.Len(), "deleteContainer clears pending")
}

// assertErrNotFound is a minimal non-nil error for GET failures in tests.
// Using a sentinel keeps the test readable without pulling in apierrors.
func assertErrNotFound(name string) error {
	return &testNotFoundErr{name: name}
}

type testNotFoundErr struct{ name string }

func (e *testNotFoundErr) Error() string { return "container profile " + e.name + ": not found" }

// TestPartialCP_Accepted verifies that a CP with Status=Completed is cached
// regardless of its Completion value (Partial or Full). Completion describes
// data coverage, not caching eligibility — only Status matters.
func TestPartialCP_Accepted(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cp-partial",
			Namespace:       "default",
			ResourceVersion: "1",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Partial,
				helpersv1.StatusMetadataKey:     helpersv1.Completed,
			},
		},
	}
	client := &fakeProfileClient{cp: cp}
	c, k8s := newTestCache(t, client)

	id := "container-partial"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")

	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))
	assert.NotNil(t, c.GetProjectedContainerProfile(id), "Partial+Completed CP must be accepted into cache")
	assert.Equal(t, 0, c.pending.Len(), "not pending when Status=Completed")
}

// TestPartialCP_PreRunning_Accepted verifies that PreRunning containers also
// accept a partial CP when Status=Completed (same rule as non-PreRunning).
func TestPartialCP_PreRunning_Accepted(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cp-partial-prerunning",
			Namespace:       "default",
			ResourceVersion: "1",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Partial,
				helpersv1.StatusMetadataKey:     helpersv1.Completed,
			},
		},
	}
	client := &fakeProfileClient{cp: cp}
	c, k8s := newTestCache(t, client)

	id := "container-partial-prerunning"
	// Mark PreRunning so the partial is accepted.
	primePreRunningSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")

	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))
	assert.NotNil(t, c.GetProjectedContainerProfile(id), "partial CP accepted for PreRunning container")
	assert.Equal(t, 0, c.pending.Len(), "not pending when accepted")
}

// TestRefreshDoesNotResurrectDeletedEntry verifies the Phase-4 reviewer race:
// refreshAllEntries snapshots entries without a lock; if deleteContainer
// removes the entry before refreshOneEntry takes the lock, the refresh must
// NOT re-insert it.
func TestRefreshDoesNotResurrectDeletedEntry(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cp-resurrect", Namespace: "default", ResourceVersion: "1",
			Annotations: map[string]string{helpersv1.StatusMetadataKey: helpersv1.Completed},
		},
	}
	client := &fakeProfileClient{cp: cp}
	c, k8s := newTestCache(t, client)

	id := "container-resurrect"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))
	require.NotNil(t, c.GetProjectedContainerProfile(id))

	// Simulate the race: snapshot the entry, delete, then call refreshOneEntry.
	entry, ok := c.entries.Load(id)
	require.True(t, ok)
	c.deleteContainer(id)
	require.Nil(t, c.GetProjectedContainerProfile(id), "entry gone after delete")

	// Refresh for the deleted id must bail instead of resurrecting.
	c.containerLocks.WithLock(id, func() {
		c.refreshOneEntry(context.Background(), id, entry)
	})

	assert.Nil(t, c.GetProjectedContainerProfile(id), "refresh must not resurrect deleted entry")
}

// primePreRunningSharedData is a variant of primeSharedData that sets the
// PreRunningContainer flag.
func primePreRunningSharedData(t *testing.T, k8s *objectcache.K8sObjectCacheMock, containerID, wlid string) {
	t.Helper()
	primeSharedData(t, k8s, containerID, wlid)
	existing := k8s.GetSharedContainerData(containerID)
	require.NotNil(t, existing)
	existing.PreRunningContainer = true
	k8s.SetSharedContainerData(containerID, existing)
}

// TestRefreshUpdatesCPStatus exercises the refresh path: at addContainer
// time the consolidated CP may still be in Status="ready"; the cache must
// re-fetch it on each tick so a later "ready" -> "completed" transition
// propagates to the cached ProfileState, which in turn flips fail_on_profile
// from false to true (Test_17 / Test_19 semantics).
func TestRefreshUpdatesCPStatus(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cp-ready",
			Namespace:       "default",
			ResourceVersion: "1",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Full,
				helpersv1.StatusMetadataKey:     helpersv1.Learning, // not yet completed
			},
		},
	}
	client := &fakeProfileClient{cp: cp}
	c, k8s := newTestCache(t, client)

	id := "container-cp-ready"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))

	// A CP with a non-Completed status must not be accepted into the cache;
	// the container stays pending until the CP transitions to Completed.
	_, ok := c.entries.Load(id)
	assert.False(t, ok, "non-completed CP must not populate cache entry")
	assert.Equal(t, 1, c.pending.Len(), "container stays pending while CP status is learning")

	// Storage transitions CP to Status=completed.
	client.cp = &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cp-ready",
			Namespace:       "default",
			ResourceVersion: "2",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Full,
				helpersv1.StatusMetadataKey:     helpersv1.Completed,
			},
		},
	}

	c.retryPendingEntries(context.Background())

	stored, ok := c.entries.Load(id)
	require.True(t, ok, "entry populated after CP becomes completed")
	require.NotNil(t, stored.State)
	assert.Equal(t, helpersv1.Completed, stored.State.Status,
		"ProfileState reflects Completed status")
	assert.Equal(t, "2", stored.RV, "RV recorded from the completed CP")
}

// TestTooLargeCP_Accepted verifies that a CP with Status=TooLarge is treated
// as a terminal state and cached immediately, not kept in the pending queue.
// TooLarge profiles have truncated but valid data that the rule engine should
// use for detection; rejecting them would leave the container permanently
// pending since the manager never transitions TooLarge → Completed.
func TestTooLargeCP_Accepted(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cp-too-large",
			Namespace:       "default",
			ResourceVersion: "1",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Partial,
				helpersv1.StatusMetadataKey:     helpersv1.TooLarge,
			},
		},
		Spec: v1beta1.ContainerProfileSpec{
			Execs: []v1beta1.ExecCalls{{Path: "/bin/sh"}},
		},
	}
	client := &fakeProfileClient{cp: cp}
	c, k8s := newTestCache(t, client)

	id := "container-too-large"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))

	stored, ok := c.entries.Load(id)
	require.True(t, ok, "TooLarge CP must populate cache entry immediately")
	assert.Equal(t, 0, c.pending.Len(), "no pending entry when Status=TooLarge")
	require.NotNil(t, stored.State)
	assert.Equal(t, helpersv1.TooLarge, stored.State.Status, "ProfileState reflects TooLarge status")
	assert.Equal(t, "1", stored.RV, "RV recorded from the too-large CP")

	// refreshOneEntry must also accept TooLarge on subsequent ticks.
	cp2 := cp.DeepCopy()
	cp2.ResourceVersion = "2"
	cp2.Spec.Execs = append(cp2.Spec.Execs, v1beta1.ExecCalls{Path: "/usr/bin/id"})
	client.cp = cp2
	c.refreshAllEntries(context.Background())

	stored2, ok := c.entries.Load(id)
	require.True(t, ok, "entry survives refresh with TooLarge status")
	assert.Equal(t, "2", stored2.RV, "RV updated on refresh")
}

// TestNotifyContainerTerminal_TooLarge verifies the fast-path promotion for a
// container whose CP becomes TooLarge. Without waiting for the 30s reconciler
// tick, NotifyContainerCompleted must promote the pending entry immediately once
// the TooLarge CP is visible in storage.
func TestNotifyContainerTerminal_TooLarge(t *testing.T) {
	// Start with no CP in storage so the container stays pending.
	client := &fakeProfileClient{cp: nil}
	c, k8s := newTestCache(t, client)

	id := "container-too-large-notify"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))

	assert.Equal(t, 1, c.pending.Len(), "container is pending while CP absent")
	_, ok := c.entries.Load(id)
	assert.False(t, ok, "no entry while CP absent")

	// Storage now has a TooLarge terminal CP.
	client.cp = &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cp-too-large",
			Namespace:       "default",
			ResourceVersion: "1",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Partial,
				helpersv1.StatusMetadataKey:     helpersv1.TooLarge,
			},
		},
		Spec: v1beta1.ContainerProfileSpec{
			Execs: []v1beta1.ExecCalls{{Path: "/bin/sh"}},
		},
	}

	// Simulate the notification fired by containerprofilemanager on TooLarge.
	// The goroutine launched by NotifyContainerCompleted must promote the entry
	// without the caller needing to wait for the 30s periodic tick.
	c.NotifyContainerCompleted(id)

	// Allow the notification goroutine to run (first attempt is immediate).
	assert.Eventually(t, func() bool {
		_, ok := c.entries.Load(id)
		return ok
	}, 2*time.Second, 10*time.Millisecond, "entry promoted via notification, no 30s tick needed")

	assert.Equal(t, 0, c.pending.Len(), "pending cleared after TooLarge promotion")
	stored, ok := c.entries.Load(id)
	require.True(t, ok)
	assert.Equal(t, helpersv1.TooLarge, stored.State.Status)
}

// TestNotifyContainerTerminal_Completed verifies the fast-path promotion for a
// container that exits normally (ContainerHasTerminatedError with
// Status=Completed). The notification goroutine must promote the pending entry
// without waiting for the 30s reconciler tick.
func TestNotifyContainerTerminal_Completed(t *testing.T) {
	// No CP yet — container stays pending.
	client := &fakeProfileClient{cp: nil}
	c, k8s := newTestCache(t, client)

	id := "container-normal-exit"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))

	assert.Equal(t, 1, c.pending.Len(), "container pending while CP absent")

	// Simulate the lifecycle: container exits → CP written with Status=Completed.
	client.cp = &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cp-exited",
			Namespace:       "default",
			ResourceVersion: "1",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Full,
				helpersv1.StatusMetadataKey:     helpersv1.Completed,
			},
		},
	}

	// Simulate what monitorContainer now does on ContainerHasTerminatedError.
	c.NotifyContainerCompleted(id)

	assert.Eventually(t, func() bool {
		_, ok := c.entries.Load(id)
		return ok
	}, 2*time.Second, 10*time.Millisecond, "entry promoted via notification without 30s tick")

	assert.Equal(t, 0, c.pending.Len(), "pending cleared after normal-exit promotion")
	stored, ok := c.entries.Load(id)
	require.True(t, ok)
	assert.Equal(t, helpersv1.Completed, stored.State.Status)
}

// TestSpecChange_TriggersReprojection — T5 nudge integration.
//
// After SetProjectionSpec is called with a new spec, RefreshAllEntriesForTest
// re-projects existing entries under the new spec. Without the nudge mechanism
// tests cannot wait for the background goroutine, so we drive it explicitly.
func TestSpecChange_TriggersReprojection(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cp", Namespace: "default", ResourceVersion: "1",
			Annotations: map[string]string{helpersv1.StatusMetadataKey: helpersv1.Completed},
		},
		Spec: v1beta1.ContainerProfileSpec{
			Capabilities: []string{"SYS_PTRACE", "NET_ADMIN"},
		},
	}
	client := &countingProfileClient{cp: cp}
	k8s := newControllableK8sCache()
	metrics := newCountingMetrics()
	c := newReconcilerCache(t, client, k8s, metrics)

	id := "c-reproj"
	// Seed with nil spec — InUse=false means pass-through: all entries retained.
	entry := newEntry(cp, "nginx", "nginx-abc", "default", "uid-1")
	c.entries.Set(id, entry)

	before := c.GetProjectedContainerProfile(id)
	require.NotNil(t, before)
	assert.Empty(t, before.SpecHash, "nil spec → SpecHash is empty")
	assert.Contains(t, before.Capabilities.Values, "SYS_PTRACE", "nil spec → pass-through, capabilities retained")
	assert.Contains(t, before.Capabilities.Values, "NET_ADMIN", "nil spec → pass-through, capabilities retained")

	// Install a spec that accepts all capabilities.
	c.SetProjectionSpec(objectcache.RuleProjectionSpec{
		Capabilities: objectcache.FieldSpec{InUse: true, All: true},
		Hash:         "caps-all",
	})

	// Simulate what the nudge-triggered goroutine does.
	c.refreshAllEntries(context.Background())

	after := c.GetProjectedContainerProfile(id)
	require.NotNil(t, after)
	assert.Equal(t, "caps-all", after.SpecHash, "after spec change → SpecHash updated, proving reprojection occurred")
	assert.Contains(t, after.Capabilities.Values, "SYS_PTRACE", "after spec change → SYS_PTRACE projected")
	assert.Contains(t, after.Capabilities.Values, "NET_ADMIN", "after spec change → NET_ADMIN projected")
}
