package containerwatcher

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulebindingmanager"
	"github.com/kubescape/workerpool"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestNamespaceFilterReconcilesRunningContainers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filter.json")
	write := func(contents string) { t.Helper(); require.NoError(t, os.WriteFile(path, []byte(contents), 0600)) }
	write(`{"includeNamespaces":[],"excludeNamespaces":["payments"]}`)
	cfg := config.Config{NamespaceFilterFile: path, NamespaceName: "kubescape", ExcludeLabels: map[string][]string{"skip": {"true"}}}
	require.NoError(t, cfg.InitializeNamespaceFilter())
	cc := &containercollection.ContainerCollection{}
	k8sCache := &countingK8sObjectCache{}
	cw := &ContainerWatcher{cfg: cfg, containerCollection: cc, objectCache: &countingObjectCache{k8sCache: k8sCache}}
	existing := makeTestContainer("existing", "default", "pod", "app", 1)
	payments := makeTestContainer("payments", "payments", "pay", "app", 2)
	// An otherwise eligible container whose profiling completed must not be replayed.
	completed := makeTestContainer("completed", "other", "done", "app", 3)
	excludedLabel := makeTestContainer("label", "payments", "skip", "app", 4)
	excludedLabel.SetPodLabels(map[string]string{"skip": "true"})
	host := makeTestContainer(armotypes.HostContainerID, "", "", "", 5)
	own := makeTestContainer("own", "kubescape", "agent", "app", 6)
	cc.AddContainer(existing)
	cc.AddContainer(host)
	k8sCache.SetSharedContainerData("existing", &objectcache.WatchedContainerData{})
	previous := cfg.NamespaceFilterSnapshot()
	write(`{"includeNamespaces":[],"excludeNamespaces":["default"]}`)
	changed, err := cfg.ReloadNamespaceFilter()
	require.NoError(t, err)
	require.True(t, changed)
	list := func(context.Context, *config.NamespaceFilter) ([]containercollection.Container, error) {
		return []containercollection.Container{*existing, *payments, *completed, *excludedLabel, *host, *own}, nil
	}
	// Exclusions take effect even when the API is temporarily unavailable.
	require.Error(t, cw.reconcileNamespaceFilter(t.Context(), previous, func(context.Context, *config.NamespaceFilter) ([]containercollection.Container, error) {
		return nil, errors.New("API unavailable")
	}))
	require.Nil(t, cc.GetContainer("existing"))
	require.Nil(t, k8sCache.GetSharedContainerData("existing"))
	require.NotNil(t, cc.GetContainer(armotypes.HostContainerID))
	require.NoError(t, cw.reconcileNamespaceFilter(t.Context(), previous, list))
	require.NotNil(t, cc.GetContainer("payments"))
	require.Nil(t, cc.GetContainer("completed"))
	require.Nil(t, cc.GetContainer("label"))
	require.Nil(t, cc.GetContainer("own"))
	// A retry neither duplicates nor replaces the admitted instance.
	admitted := cc.GetContainer("payments")
	require.NoError(t, cw.reconcileNamespaceFilter(t.Context(), previous, list))
	require.Same(t, admitted, cc.GetContainer("payments"))
	// Restore the initial policy, without restarting either workload.
	previous = cfg.NamespaceFilterSnapshot()
	write(`{"includeNamespaces":[],"excludeNamespaces":["payments"]}`)
	_, err = cfg.ReloadNamespaceFilter()
	require.NoError(t, err)
	require.NoError(t, cw.reconcileNamespaceFilter(t.Context(), previous, list))
	require.NotNil(t, cc.GetContainer("existing"))
	require.Nil(t, cc.GetContainer("payments"))
	require.NotNil(t, cc.GetContainer(armotypes.HostContainerID))
}

func TestNamespaceFilterPollingAndShutdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filter.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"includeNamespaces":[],"excludeNamespaces":[]}`), 0600))
	cfg := config.Config{NamespaceFilterFile: path}
	require.NoError(t, cfg.InitializeNamespaceFilter())
	cc := &containercollection.ContainerCollection{}
	cc.AddContainer(makeTestContainer("running", "payments", "pod", "app", 1))
	cw := &ContainerWatcher{
		cfg: cfg, containerCollection: cc,
		objectCache: &countingObjectCache{k8sCache: &countingK8sObjectCache{}},
		k8sClient:   &k8sinterface.KubernetesApi{KubernetesClient: fake.NewClientset()},
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ticks := make(chan time.Time)
	done := make(chan struct{})
	go func() { defer close(done); cw.watchNamespaceFilter(ctx, ticks) }()
	require.NoError(t, os.WriteFile(path, []byte(`{"includeNamespaces":[],"excludeNamespaces":["payments"]}`), 0600))
	ticks <- time.Now()
	require.Eventually(t, func() bool { return cc.GetContainer("running") == nil }, time.Second, time.Millisecond)
	require.True(t, cfg.SkipNamespace("payments"))
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reload loop did not stop")
	}
}

func TestNamespaceFilterRemovalCallbackIsDelivered(t *testing.T) {
	pool := workerpool.New(1)
	defer pool.StopWait()
	var mu sync.Mutex
	var removed []string
	cw := &ContainerWatcher{
		cfg: config.Config{ExcludeNamespaces: []string{"payments"}}, pool: pool,
		callbacks: []containercollection.FuncNotify{func(event containercollection.PubSubEvent) {
			mu.Lock()
			defer mu.Unlock()
			removed = append(removed, event.Container.Runtime.ContainerID)
		}},
	}
	cw.containerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeRemoveContainer, Container: makeTestContainer("cleanup", "payments", "pod", "app", 1)})
	require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(removed) == 1 }, time.Second, time.Millisecond)
}

func TestNamespaceFilterRetryAcceptsNewerEdits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filter.json")
	write := func(contents string) { t.Helper(); require.NoError(t, os.WriteFile(path, []byte(contents), 0600)) }
	write(`{"includeNamespaces":[],"excludeNamespaces":["payments"]}`)
	cfg := config.Config{NamespaceFilterFile: path}
	require.NoError(t, cfg.InitializeNamespaceFilter())
	cc := &containercollection.ContainerCollection{}
	cc.AddContainer(makeTestContainer("running", "default", "pod", "app", 1))
	client := fake.NewClientset()
	calls := make(chan struct{}, 4)
	client.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		calls <- struct{}{}
		return true, nil, errors.New("API unavailable")
	})
	cw := &ContainerWatcher{cfg: cfg, containerCollection: cc, k8sClient: &k8sinterface.KubernetesApi{KubernetesClient: client}, objectCache: &countingObjectCache{k8sCache: &countingK8sObjectCache{}}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ticks := make(chan time.Time)
	done := make(chan struct{})
	go func() { defer close(done); cw.watchNamespaceFilter(ctx, ticks) }()
	tick := func() {
		t.Helper()
		select {
		case ticks <- time.Now():
		case <-time.After(time.Second):
			t.Fatal("reload stalled")
		}
		select {
		case <-calls:
		case <-time.After(time.Second):
			t.Fatal("discovery was not retried")
		}
	}
	write(`{"includeNamespaces":[],"excludeNamespaces":[]}`)
	tick()
	require.False(t, cfg.SkipNamespace("payments"))
	// Discovery is still failing, but a newer exclusion must be honored.
	write(`{"includeNamespaces":[],"excludeNamespaces":["default"]}`)
	tick()
	require.True(t, cfg.SkipNamespace("default"))
	require.Nil(t, cc.GetContainer("running"))
	write(`{`)
	tick()
	require.True(t, cfg.SkipNamespace("default"), "bad edits do not discard the last valid filter or pending discovery")
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reload did not stop")
	}
}

func TestNamespaceFilterRetainsRuleBindingsWhileExcluded(t *testing.T) {
	cw := &ContainerWatcher{cfg: config.Config{NamespaceFilterFile: "/mounted/filter.json", ExcludeNamespaces: []string{"payments"}}, ruleManagedPods: mapset.NewSet[string]()}
	pod := corev1.Pod{Name: "pay", Namespace: "payments"}
	cw.addRunningContainers(&rulebindingmanager.RuleBindingNotify{Action: rulebindingmanager.Added, Pod: pod})
	require.True(t, cw.ruleManagedPods.Contains("payments/pay"))
	cw.addRunningContainers(&rulebindingmanager.RuleBindingNotify{Action: rulebindingmanager.Removed, Pod: pod})
	require.False(t, cw.ruleManagedPods.Contains("payments/pay"))
}
