package containerprofilemanager

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerinstance "github.com/kubescape/k8s-interface/instanceidhandler/v1/containerinstance"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNamespaceFilterRapidProfileReadmission(t *testing.T) {
	t.Setenv("QUEUE_DIR", t.TempDir())
	path := filepath.Join(t.TempDir(), "filter.json")
	write := func(excluded bool) {
		t.Helper()
		contents := `{"includeNamespaces":[],"excludeNamespaces":[]}`
		if excluded {
			contents = `{"includeNamespaces":[],"excludeNamespaces":["payments"]}`
		}
		require.NoError(t, os.WriteFile(path, []byte(contents), 0600))
	}
	write(false)
	cfg := config.Config{NamespaceFilterFile: path, InitialDelay: time.Hour, UpdateDataPeriod: time.Hour, MaxSniffingTime: time.Hour, MaxTsProfileSize: 10 * 1024 * 1024}
	require.NoError(t, cfg.InitializeNamespaceFilter())
	cache := &objectcache.K8sObjectCacheMock{}
	shared := func() *objectcache.WatchedContainerData {
		return &objectcache.WatchedContainerData{
			InstanceID:  &containerinstance.InstanceID{ApiVersion: "apps/v1", Namespace: "payments", Kind: "Pod", Name: "pay", ContainerName: "app"},
			ContainerID: "running", PodName: "pay", Namespace: "payments", ContainerType: objectcache.Container,
			ContainerInfos:         map[objectcache.ContainerType][]objectcache.ContainerInfo{objectcache.Container: {{Name: "running"}}},
			ParentWorkloadSelector: &metav1.LabelSelector{},
		}
	}
	cache.SetSharedContainerData("running", shared())
	manager, err := NewContainerProfileManager(t.Context(), cfg, &k8sclient.K8sClientMock{}, cache, &storage.StorageHttpClientMock{}, &dnsmanager.DNSManagerMock{}, &seccompmanager.SeccompManagerMock{}, nil, nil, nil)
	require.NoError(t, err)
	defer manager.Close()
	container := &containercollection.Container{}
	container.Runtime.ContainerID = "running"
	container.Runtime.ContainerPID = 1234
	container.K8s.Namespace = "payments"
	container.K8s.PodName = "pay"
	container.K8s.ContainerName = "app"
	notify := func(kind containercollection.EventType) {
		manager.ContainerCallback(containercollection.PubSubEvent{Type: kind, Container: container})
	}
	readyEntry := func(previous *ContainerEntry) *ContainerEntry {
		t.Helper()
		var result *ContainerEntry
		require.Eventually(t, func() bool {
			entry, ok := manager.getContainerEntry("running")
			if !ok || entry == previous {
				return false
			}
			select {
			case <-entry.ready:
				result = entry
				return true
			default:
				return false
			}
		}, 3*time.Second, time.Millisecond)
		return result
	}
	notify(containercollection.EventTypeAddContainer)
	initial := readyEntry(nil)
	write(true)
	_, err = cfg.ReloadNamespaceFilter()
	require.NoError(t, err)
	notify(containercollection.EventTypeRemoveContainer)
	// Restore inclusion immediately, while the old monitor is still cleaning up.
	write(false)
	_, err = cfg.ReloadNamespaceFilter()
	require.NoError(t, err)
	cache.SetSharedContainerData("running", shared())
	notify(containercollection.EventTypeAddContainer)
	readmitted := readyEntry(initial)
	require.NotSame(t, initial, readmitted)
	write(true)
	_, err = cfg.ReloadNamespaceFilter()
	require.NoError(t, err)
	notify(containercollection.EventTypeRemoveContainer)
	require.Eventually(t, func() bool { _, ok := manager.getContainerEntry("running"); return !ok }, 3*time.Second, time.Millisecond)
}

func TestNamespaceFilterLateAdmissionProducesPartialProfile(t *testing.T) {
	for _, tc := range []struct {
		name             string
		late, preRunning bool
		want             objectcache.WatchedContainerCompletionStatus
	}{
		{"ordinary", false, false, objectcache.WatchedContainerCompletionStatusFull},
		{"pre-running", false, true, objectcache.WatchedContainerCompletionStatusPartial},
		{"late namespace inclusion", true, false, objectcache.WatchedContainerCompletionStatusPartial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager := &ContainerProfileManager{cfg: config.Config{InitialDelay: time.Hour}}
			data := &objectcache.WatchedContainerData{PreRunningContainer: tc.preRunning, LateAdmission: tc.late}
			manager.setContainerData(&containercollection.Container{}, data)
			defer data.UpdateDataTicker.Stop()
			require.Equal(t, tc.want, data.GetCompletionStatus())
		})
	}
}
