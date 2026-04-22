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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
// fast-skip behavior.
type countingProfileClient struct {
	cp *v1beta1.ContainerProfile
	ap *v1beta1.ApplicationProfile
	nn *v1beta1.NetworkNeighborhood

	cpCalls atomic.Int64
	apCalls atomic.Int64
	nnCalls atomic.Int64
}

var _ storage.ProfileClient = (*countingProfileClient)(nil)

func (f *countingProfileClient) GetContainerProfile(_ context.Context, _, _ string) (*v1beta1.ContainerProfile, error) {
	f.cpCalls.Add(1)
	return f.cp, nil
}
func (f *countingProfileClient) GetApplicationProfile(_ context.Context, _, _ string) (*v1beta1.ApplicationProfile, error) {
	f.apCalls.Add(1)
	return f.ap, nil
}
func (f *countingProfileClient) GetNetworkNeighborhood(_ context.Context, _, _ string) (*v1beta1.NetworkNeighborhood, error) {
	f.nnCalls.Add(1)
	return f.nn, nil
}
func (f *countingProfileClient) ListApplicationProfiles(_ context.Context, _ string, _ int64, _ string) (*v1beta1.ApplicationProfileList, error) {
	return &v1beta1.ApplicationProfileList{}, nil
}
func (f *countingProfileClient) ListNetworkNeighborhoods(_ context.Context, _ string, _ int64, _ string) (*v1beta1.NetworkNeighborhoodList, error) {
	return &v1beta1.NetworkNeighborhoodList{}, nil
}

// countingMetrics tallies ReportContainerProfileLegacyLoad calls so the T8
// end-to-end test can assert the overlay refresh re-emits the full-load signal.
type countingMetrics struct {
	metricsmanager.MetricsMock
	mu           sync.Mutex
	legacyLoads  map[string]int // key = kind+"|"+completeness
	evictions    map[string]int
	entriesByKnd map[string]float64
}

func newCountingMetrics() *countingMetrics {
	return &countingMetrics{
		legacyLoads:  map[string]int{},
		evictions:    map[string]int{},
		entriesByKnd: map[string]float64{},
	}
}
func (m *countingMetrics) ReportContainerProfileLegacyLoad(kind, completeness string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.legacyLoads[kind+"|"+completeness]++
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
func (m *countingMetrics) legacyLoad(kind, completeness string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.legacyLoads[kind+"|"+completeness]
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
		Profile:       cp,
		State:         &objectcache.ProfileState{Name: cp.Name},
		ContainerName: containerName,
		PodName:       podName,
		Namespace:     namespace,
		PodUID:        podUID,
		CPName:        cp.Name,
		RV:            cp.ResourceVersion,
		Shared:        true,
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

	assert.NotNil(t, c.GetContainerProfile(id), "entry must be retained when pod is missing from cache")
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

	assert.Nil(t, c.GetContainerProfile(id), "terminated container entry must be evicted")
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

	assert.NotNil(t, c.GetContainerProfile(id), "waiting container entry must be retained")
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

	assert.NotNil(t, c.GetContainerProfile(id), "running container entry must remain")
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

// TestRefreshFastSkipWhenAllRVsMatch — delta #4. When CP RV and both overlay
// RVs match the cached values, refreshOneEntry returns without rebuilding.
func TestRefreshFastSkipWhenAllRVsMatch(t *testing.T) {
	cp := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "cp", Namespace: "default", ResourceVersion: "100"}}
	ap := &v1beta1.ApplicationProfile{ObjectMeta: metav1.ObjectMeta{Name: "override", Namespace: "default", ResourceVersion: "50"}}
	nn := &v1beta1.NetworkNeighborhood{ObjectMeta: metav1.ObjectMeta{Name: "override", Namespace: "default", ResourceVersion: "60"}}
	client := &countingProfileClient{cp: cp, ap: ap, nn: nn}
	k8s := newControllableK8sCache()
	metrics := newCountingMetrics()
	c := newReconcilerCache(t, client, k8s, metrics)

	id := "c1"
	entry := &CachedContainerProfile{
		Profile:       cp,
		State:         &objectcache.ProfileState{Name: cp.Name},
		ContainerName: "nginx",
		PodName:       "nginx-abc",
		Namespace:     "default",
		PodUID:        "uid-1",
		CPName:        "cp",
		UserAPRef:     &namespacedName{Namespace: "default", Name: "override"},
		UserNNRef:     &namespacedName{Namespace: "default", Name: "override"},
		Shared:        false,
		RV:            "100",
		UserAPRV:      "50",
		UserNNRV:      "60",
	}
	c.entries.Set(id, entry)
	beforeProfilePtr := entry.Profile

	c.refreshAllEntries(context.Background())

	// Fetched CP once + overlays once each to check RVs; then fast-skipped.
	assert.Equal(t, int64(1), client.cpCalls.Load(), "CP should be fetched once")
	assert.Equal(t, int64(1), client.apCalls.Load(), "AP should be fetched once for RV check")
	assert.Equal(t, int64(1), client.nnCalls.Load(), "NN should be fetched once for RV check")

	stored, ok := c.entries.Load(id)
	require.True(t, ok)
	// Same pointer: the entry was NOT rebuilt.
	assert.Same(t, entry, stored, "entry must not be replaced on fast-skip")
	assert.Same(t, beforeProfilePtr, stored.Profile, "Profile pointer must not change on fast-skip")
	// No legacy-load metric emitted on fast-skip.
	assert.Equal(t, 0, metrics.legacyLoad(kindApplication, completenessFull))
	assert.Equal(t, 0, metrics.legacyLoad(kindNetwork, completenessFull))
}

// TestRefreshRebuildsOnUserAPChange — entry has stale UserAPRV; refresh sees
// a newer AP RV and rebuilds.
func TestRefreshRebuildsOnUserAPChange(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "cp", Namespace: "default", ResourceVersion: "100"},
		Spec:       v1beta1.ContainerProfileSpec{Capabilities: []string{"SYS_PTRACE"}},
	}
	ap := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "override", Namespace: "default", ResourceVersion: "51"},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{{
				Name:         "nginx",
				Capabilities: []string{"NET_BIND_SERVICE"},
			}},
		},
	}
	client := &countingProfileClient{cp: cp, ap: ap}
	k8s := newControllableK8sCache()
	metrics := newCountingMetrics()
	c := newReconcilerCache(t, client, k8s, metrics)

	id := "c1"
	entry := &CachedContainerProfile{
		Profile:       cp,
		State:         &objectcache.ProfileState{Name: cp.Name},
		ContainerName: "nginx",
		PodName:       "nginx-abc",
		Namespace:     "default",
		PodUID:        "uid-1",
		CPName:        "cp",
		UserAPRef:     &namespacedName{Namespace: "default", Name: "override"},
		Shared:        false,
		RV:            "100",
		UserAPRV:      "50", // stale: storage now returns 51
	}
	c.entries.Set(id, entry)

	c.refreshAllEntries(context.Background())

	stored, ok := c.entries.Load(id)
	require.True(t, ok)
	assert.NotSame(t, entry, stored, "entry must be replaced when user-AP RV changes")
	assert.Equal(t, "51", stored.UserAPRV, "new UserAPRV must be recorded")
	assert.ElementsMatch(t, []string{"SYS_PTRACE", "NET_BIND_SERVICE"}, stored.Profile.Spec.Capabilities,
		"rebuilt projection must include merged overlay capabilities")
}

// TestRefreshRebuildsOnCPChange — CP RV changed; entry rebuilds with fresh CP.
func TestRefreshRebuildsOnCPChange(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "cp", Namespace: "default", ResourceVersion: "101"},
		Spec:       v1beta1.ContainerProfileSpec{Capabilities: []string{"SYS_ADMIN"}},
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
	assert.Same(t, cp, stored.Profile, "shared fast-path: fresh CP pointer stored directly")
}

// TestT8_EndToEndRefreshUpdatesProjection — delta #5. Mutate the user-AP in
// the stubbed storage so its RV + execs change; assert the cached projection
// reflects the new execs AND that the legacy-load metric was re-emitted.
func TestT8_EndToEndRefreshUpdatesProjection(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "cp", Namespace: "default", ResourceVersion: "100"},
		Spec: v1beta1.ContainerProfileSpec{
			Execs: []v1beta1.ExecCalls{{Path: "/bin/base", Args: []string{"a"}}},
		},
	}
	ap := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "override", Namespace: "default", ResourceVersion: "50"},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{{
				Name:  "nginx",
				Execs: []v1beta1.ExecCalls{{Path: "/bin/old", Args: []string{"x"}}},
			}},
		},
	}
	client := &countingProfileClient{cp: cp, ap: ap}
	k8s := newControllableK8sCache()
	metrics := newCountingMetrics()
	c := newReconcilerCache(t, client, k8s, metrics)

	// Initial entry built from base CP + overlay: use addContainer's private
	// buildEntry logic via projectUserProfiles directly, then seed.
	initialProjected, _ := projectUserProfiles(cp, ap, nil, nil, "nginx")
	id := "c1"
	entry := &CachedContainerProfile{
		Profile:       initialProjected,
		State:         &objectcache.ProfileState{Name: cp.Name},
		ContainerName: "nginx",
		PodName:       "nginx-abc",
		Namespace:     "default",
		PodUID:        "uid-1",
		CPName:        "cp",
		UserAPRef:     &namespacedName{Namespace: "default", Name: "override"},
		Shared:        false,
		RV:            "100",
		UserAPRV:      "50",
	}
	c.entries.Set(id, entry)

	// Mutate storage: new AP RV + new execs.
	client.ap = &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "override", Namespace: "default", ResourceVersion: "51"},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{{
				Name:  "nginx",
				Execs: []v1beta1.ExecCalls{{Path: "/bin/new", Args: []string{"y"}}},
			}},
		},
	}

	c.refreshAllEntries(context.Background())

	stored, ok := c.entries.Load(id)
	require.True(t, ok)
	assert.Equal(t, "51", stored.UserAPRV, "refresh must record the new user-AP RV")

	// The projection must include the new exec (merged on top of the base CP's exec).
	var paths []string
	for _, e := range stored.Profile.Spec.Execs {
		paths = append(paths, e.Path)
	}
	assert.Contains(t, paths, "/bin/base", "base CP exec must be preserved")
	assert.Contains(t, paths, "/bin/new", "new user-AP exec must be projected into the cache")
	assert.NotContains(t, paths, "/bin/old", "stale user-AP exec must NOT be in the projection")

	assert.GreaterOrEqual(t, metrics.legacyLoad(kindApplication, completenessFull), 1,
		"refresh with user-AP overlay must emit full-load metric")
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
func (f *failingProfileClient) GetApplicationProfile(_ context.Context, _, _ string) (*v1beta1.ApplicationProfile, error) {
	return nil, nil
}
func (f *failingProfileClient) GetNetworkNeighborhood(_ context.Context, _, _ string) (*v1beta1.NetworkNeighborhood, error) {
	return nil, nil
}
func (f *failingProfileClient) ListApplicationProfiles(_ context.Context, _ string, _ int64, _ string) (*v1beta1.ApplicationProfileList, error) {
	return &v1beta1.ApplicationProfileList{}, nil
}
func (f *failingProfileClient) ListNetworkNeighborhoods(_ context.Context, _ string, _ int64, _ string) (*v1beta1.NetworkNeighborhoodList, error) {
	return &v1beta1.NetworkNeighborhoodList{}, nil
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
		Profile:       cp,
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
func (b *blockingProfileClient) GetApplicationProfile(_ context.Context, _, _ string) (*v1beta1.ApplicationProfile, error) {
	return nil, nil
}
func (b *blockingProfileClient) GetNetworkNeighborhood(_ context.Context, _, _ string) (*v1beta1.NetworkNeighborhood, error) {
	return nil, nil
}
func (b *blockingProfileClient) ListApplicationProfiles(_ context.Context, _ string, _ int64, _ string) (*v1beta1.ApplicationProfileList, error) {
	return &v1beta1.ApplicationProfileList{}, nil
}
func (b *blockingProfileClient) ListNetworkNeighborhoods(_ context.Context, _ string, _ int64, _ string) (*v1beta1.NetworkNeighborhoodList, error) {
	return &v1beta1.NetworkNeighborhoodList{}, nil
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
		},
	}

	// Start with storage returning 404 for the initial GET.
	client := &fakeProfileClient{cp: nil, cpErr: assertErrNotFound("cp-pending")}
	c, k8s := newTestCache(t, client)

	id := "container-pending"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")

	// addContainer: sees 404 -> pending bookkeeping, not an entry.
	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))
	assert.Nil(t, c.GetContainerProfile(id), "no entry before CP exists in storage")
	assert.Equal(t, 1, c.pending.Len(), "container recorded as pending")

	// Storage creates the CP asynchronously (60s after start in real runs).
	client.cp = cp
	client.cpErr = nil

	// Simulate one reconciler tick. retryPendingEntries iterates pending and
	// promotes on successful GET.
	c.retryPendingEntries(context.Background())

	assert.NotNil(t, c.GetContainerProfile(id), "entry promoted after CP appears")
	assert.Equal(t, 0, c.pending.Len(), "pending drained on successful promotion")
	// Exactly two GETs: one from addContainer (404), one from retry (200).
	assert.Equal(t, 2, client.getCPCalls, "retry should only re-GET once per tick")
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

// TestPartialCP_NonPreRunning_StaysPending verifies that a CP marked partial
// is NOT cached when the container is not PreRunning (i.e. started after the
// agent was up). Legacy caches explicitly deleted partials on restart; we
// mirror that by staying pending until the CP becomes Full.
func TestPartialCP_NonPreRunning_StaysPending(t *testing.T) {
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

	id := "container-partial-restart"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	// sharedData.PreRunningContainer is false by default → this simulates a
	// fresh container start observed by a running agent.

	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))
	assert.Nil(t, c.GetContainerProfile(id), "partial CP must not populate cache on fresh container")
	assert.Equal(t, 1, c.pending.Len(), "partial-on-restart stays pending")

	// Simulate the CP becoming Full (new agent-side aggregation round).
	cp.Annotations[helpersv1.CompletionMetadataKey] = helpersv1.Full
	cp.ResourceVersion = "2"
	c.retryPendingEntries(context.Background())

	assert.NotNil(t, c.GetContainerProfile(id), "Full CP promotes pending entry")
	assert.Equal(t, 0, c.pending.Len(), "pending drained on Full")
}

// TestPartialCP_PreRunning_Accepted verifies the inverse: when the agent
// restarts (all containers become PreRunning), we accept even a partial CP so
// rule evaluation can still alert on out-of-profile behavior (Test_19
// semantics).
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
	assert.NotNil(t, c.GetContainerProfile(id), "partial CP accepted for PreRunning container")
	assert.Equal(t, 0, c.pending.Len(), "not pending when accepted")
}

// TestOverlayLabel_TransientFetchFailure_RefsRetained verifies that when
// UserDefinedProfileMetadataKey is set but the user-AP/NN fetch fails, the
// entry still records UserAPRef / UserNNRef so the refresh loop can re-fetch
// on subsequent ticks instead of permanently dropping the overlay.
func TestOverlayLabel_TransientFetchFailure_RefsRetained(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "cp-with-overlay", Namespace: "default", ResourceVersion: "1"},
	}
	// Overlay fetch returns an error; the base CP is fine.
	client := &fakeProfileClient{cp: cp, apErr: assertErrNotFound("override"), nnErr: assertErrNotFound("override")}
	c, k8s := newTestCache(t, client)

	id := "container-transient-overlay"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")

	// Build the container with the overlay label set.
	ct := eventContainer(id)
	ct.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "override"}

	require.NoError(t, c.addContainer(ct, context.Background()))

	entry, ok := c.entries.Load(id)
	require.True(t, ok, "entry stored with base CP even if overlay fetch failed")
	require.NotNil(t, entry.UserAPRef, "UserAPRef retained for refresh retry")
	require.NotNil(t, entry.UserNNRef, "UserNNRef retained for refresh retry")
	assert.Equal(t, "override", entry.UserAPRef.Name)
	assert.Equal(t, "override", entry.UserNNRef.Name)
}

// TestRefreshDoesNotResurrectDeletedEntry verifies the Phase-4 reviewer race:
// refreshAllEntries snapshots entries without a lock; if deleteContainer
// removes the entry before refreshOneEntry takes the lock, the refresh must
// NOT re-insert it.
func TestRefreshDoesNotResurrectDeletedEntry(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "cp-resurrect", Namespace: "default", ResourceVersion: "1"},
	}
	client := &fakeProfileClient{cp: cp}
	c, k8s := newTestCache(t, client)

	id := "container-resurrect"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))
	require.NotNil(t, c.GetContainerProfile(id))

	// Simulate the race: snapshot the entry, delete, then call refreshOneEntry.
	entry, ok := c.entries.Load(id)
	require.True(t, ok)
	c.deleteContainer(id)
	require.Nil(t, c.GetContainerProfile(id), "entry gone after delete")

	// Refresh for the deleted id must bail instead of resurrecting.
	c.containerLocks.WithLock(id, func() {
		c.refreshOneEntry(context.Background(), id, entry)
	})

	assert.Nil(t, c.GetContainerProfile(id), "refresh must not resurrect deleted entry")
}

// TestUserDefinedProfileOnly_NoBaseCP verifies that a container with only a
// user-defined AP/NN (no base CP yet) still gets a cache entry, mirroring the
// legacy behavior where user-defined profiles were stored directly.
func TestUserDefinedProfileOnly_NoBaseCP(t *testing.T) {
	userAP := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "user-override", Namespace: "default", ResourceVersion: "10"},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{
				{Name: "nginx", Capabilities: []string{"CAP_NET_ADMIN"}},
			},
		},
	}
	// Base CP fetch fails (404); only the overlay exists.
	client := &fakeProfileClient{cp: nil, cpErr: assertErrNotFound("no-base"), ap: userAP}
	c, k8s := newTestCache(t, client)

	id := "container-user-only"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	ct := eventContainer(id)
	ct.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "user-override"}

	require.NoError(t, c.addContainer(ct, context.Background()))

	cached := c.GetContainerProfile(id)
	require.NotNil(t, cached, "entry populated from user-AP even without base CP")
	// The synthesized CP + projection should carry the user AP's capabilities.
	assert.Contains(t, cached.Spec.Capabilities, "CAP_NET_ADMIN")
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
				helpersv1.StatusMetadataKey:     helpersv1.Learning, // "ready"
			},
		},
	}
	client := &fakeProfileClient{cp: cp}
	c, k8s := newTestCache(t, client)

	id := "container-cp-ready"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))

	entry, ok := c.entries.Load(id)
	require.True(t, ok, "entry populated from CP")
	require.NotNil(t, entry.State)
	assert.Equal(t, helpersv1.Learning, entry.State.Status,
		"Status reflects the CP at add time (ready / learning)")

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

	c.refreshAllEntries(context.Background())

	stored, ok := c.entries.Load(id)
	require.True(t, ok)
	require.NotNil(t, stored.State)
	assert.Equal(t, helpersv1.Completed, stored.State.Status,
		"refresh propagates CP Status=completed into ProfileState")
	assert.Equal(t, "2", stored.RV, "refresh records the new CP RV")
}

// TestUserManagedProfileMerged exercises the user-managed merge path
// (Test_12_MergingProfilesTest / Test_13_MergingNetworkNeighborhoodTest):
// a user-managed AP published at "ug-<workloadName>" is merged on top of
// the base CP. Anomalies NOT in the union of base + user-managed should
// produce alerts; anomalies present in either source should not.
func TestUserManagedProfileMerged(t *testing.T) {
	// Base CP has exec "/bin/X"; user-managed AP adds "/bin/Y".
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cp-base",
			Namespace:       "default",
			ResourceVersion: "1",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Full,
				helpersv1.StatusMetadataKey:     helpersv1.Completed,
			},
		},
		Spec: v1beta1.ContainerProfileSpec{
			Execs: []v1beta1.ExecCalls{{Path: "/bin/X"}},
		},
	}
	userManagedAP := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "ug-nginx",
			Namespace:       "default",
			ResourceVersion: "9",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Full,
				helpersv1.StatusMetadataKey:     helpersv1.Completed,
			},
		},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{{
				Name:  "nginx",
				Execs: []v1beta1.ExecCalls{{Path: "/bin/Y"}},
			}},
		},
	}
	client := &fakeProfileClient{
		cp:            cp,
		userManagedAP: userManagedAP,
	}
	c, k8s := newTestCache(t, client)

	id := "container-user-managed"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	require.NoError(t, c.addContainer(eventContainer(id), context.Background()))

	cached := c.GetContainerProfile(id)
	require.NotNil(t, cached, "entry populated")
	var paths []string
	for _, e := range cached.Spec.Execs {
		paths = append(paths, e.Path)
	}
	assert.Contains(t, paths, "/bin/X", "base workload AP exec must be present")
	assert.Contains(t, paths, "/bin/Y", "user-managed (ug-) AP exec must be merged in")

	// Verify the RV was captured so a later user-managed update would trigger
	// a refresh rebuild.
	entry, ok := c.entries.Load(id)
	require.True(t, ok)
	assert.Equal(t, "9", entry.UserManagedAPRV, "UserManagedAPRV recorded at add time")
}
