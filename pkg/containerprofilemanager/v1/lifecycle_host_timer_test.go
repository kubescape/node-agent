package containerprofilemanager

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	containerinstance "github.com/kubescape/k8s-interface/instanceidhandler/v1/containerinstance"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// calculateSniffingTime/handleContainerMaxTime (lifecycle.go:174-226) used
// to apply a fixed cfg.MaxSniffingTime timer to every container, host included.
// Since the host pseudo-container runs indefinitely, that timer firing removed
// the host entry from the profile manager entirely, silently stopping host
// profile generation. The fix (addContainer, lifecycle.go) now skips arming
// that timer for utils.IsHostContainer, mirroring the existing IsHostContainer
// bypass convention (e.g. rule_manager.go:220-231).
//
// These two tests use a short MaxSniffingTime so the assertions do not have to
// wait for the real production default.

// newHostPseudoContainer builds the host pseudo-container event
// (ContainerPID == 1 is what utils.IsHostContainer keys on), shared by the
// host tests in this package that need to drive ContainerCallback.
func newHostPseudoContainer() *containercollection.Container {
	return &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
			ContainerID:   armotypes.HostContainerID,
			ContainerName: "host",
			ContainerPID:  1,
		}},
		K8s: containercollection.K8sMetadata{BasicK8sMetadata: eventtypes.BasicK8sMetadata{
			Namespace: "host",
			PodName:   "host-node-1",
		}},
	}
}

// TestHostContainerSurvivesMaxSniffingTime proves a host container is never
// finalized/deleted from the profile manager once the (short, for test speed)
// MaxSniffingTime deadline elapses.
func TestHostContainerSurvivesMaxSniffingTime(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "host-timer-queue-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	t.Setenv("QUEUE_DIR", tempDir)

	cfg := config.Config{
		InitialDelay:        time.Minute,
		UpdateDataPeriod:    time.Minute,
		MaxSniffingTime:     50 * time.Millisecond, // short deadline a normal container would be finalized at
		MaxJitterPercentage: 0,
		MaxTsProfileSize:    10 * 1024 * 1024,
	}

	k8sObjectCacheMock := &objectcache.K8sObjectCacheMock{}
	hostData := hostidentity.BuildHostWatchedContainerData("node-1")
	k8sObjectCacheMock.SetSharedContainerData(armotypes.HostContainerID, hostData)

	cpm, err := NewContainerProfileManager(
		context.Background(),
		cfg,
		&k8sclient.K8sClientMock{},
		k8sObjectCacheMock,
		&storage.StorageHttpClientMock{},
		&dnsmanager.DNSManagerMock{},
		&seccompmanager.SeccompManagerMock{},
		nil,
		nil,
		nil,
	)
	require.NoError(t, err)
	defer cpm.Close()

	cpm.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: newHostPseudoContainer(),
	})

	require.Eventually(t, func() bool {
		entry, ok := cpm.getContainerEntry(armotypes.HostContainerID)
		if !ok || entry.data == nil {
			return false
		}
		entry.mu.RLock()
		defer entry.mu.RUnlock()
		return entry.data.watchedContainerData != nil
	}, 2*time.Second, 10*time.Millisecond, "host container was never registered in the profile manager")

	entry, ok := cpm.getContainerEntry(armotypes.HostContainerID)
	require.True(t, ok)
	entry.mu.RLock()
	timerArmed := entry.data.timer != nil
	entry.mu.RUnlock()
	assert.False(t, timerArmed, "host container must not have the max-sniffing-time timer armed")

	// Wait well past what would be a normal container's MaxSniffingTime deadline.
	time.Sleep(10 * cfg.MaxSniffingTime)

	_, stillExists := cpm.getContainerEntry(armotypes.HostContainerID)
	assert.True(t, stillExists, "host container must survive past MaxSniffingTime, not be finalized/deleted")
}

// TestNonHostContainerStillFinalizesAtMaxSniffingTime proves the host bypass did
// not change finalization behavior for regular containers: a non-host container
// is still finalized and removed once its MaxSniffingTime deadline elapses.
func TestNonHostContainerStillFinalizesAtMaxSniffingTime(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "container-timer-queue-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	t.Setenv("QUEUE_DIR", tempDir)

	const containerID = "container-1"

	cfg := config.Config{
		InitialDelay:        time.Minute,
		UpdateDataPeriod:    time.Minute,
		MaxSniffingTime:     50 * time.Millisecond,
		MaxJitterPercentage: 0,
		MaxTsProfileSize:    10 * 1024 * 1024,
	}

	k8sObjectCacheMock := &objectcache.K8sObjectCacheMock{}
	k8sObjectCacheMock.SetSharedContainerData(containerID, &objectcache.WatchedContainerData{
		InstanceID: &containerinstance.InstanceID{
			ApiVersion:    "apps/v1",
			Namespace:     "default",
			Kind:          "Pod",
			Name:          "pod-1",
			ContainerName: "app",
		},
		ContainerID:   containerID,
		PodName:       "pod-1",
		Namespace:     "default",
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {{Name: containerID}},
		},
		ParentWorkloadSelector: &metav1.LabelSelector{},
		PreRunningContainer:    false,
	})

	cpm, err := NewContainerProfileManager(
		context.Background(),
		cfg,
		&k8sclient.K8sClientMock{},
		k8sObjectCacheMock,
		&storage.StorageHttpClientMock{},
		&dnsmanager.DNSManagerMock{},
		&seccompmanager.SeccompManagerMock{},
		nil,
		nil,
		nil,
	)
	require.NoError(t, err)
	defer cpm.Close()

	container := &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
			ContainerID:   containerID,
			ContainerName: "app",
			ContainerPID:  1234,
		}},
		K8s: containercollection.K8sMetadata{BasicK8sMetadata: eventtypes.BasicK8sMetadata{
			Namespace: "default",
			PodName:   "pod-1",
		}},
	}

	cpm.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: container,
	})

	require.Eventually(t, func() bool {
		entry, ok := cpm.getContainerEntry(containerID)
		if !ok {
			return false
		}
		entry.mu.RLock()
		defer entry.mu.RUnlock()
		return entry.data != nil && entry.data.watchedContainerData != nil
	}, 2*time.Second, 10*time.Millisecond, "container was never registered in the profile manager")

	entry, ok := cpm.getContainerEntry(containerID)
	require.True(t, ok)
	timerArmed := func() bool {
		entry.mu.RLock()
		defer entry.mu.RUnlock()
		// The timer's deadline is short enough (see MaxSniffingTime above) that
		// it could in principle have already fired and cleared entry.data by
		// the time this lock is acquired. require.NotNil calls t.FailNow(),
		// which exits via runtime.Goexit -- routing it through this closure
		// (rather than inline) ensures the deferred RUnlock still runs instead
		// of leaving the mutex held forever.
		require.NotNil(t, entry.data, "container entry data was cleared before the timer-armed assertion could run")
		return entry.data.timer != nil
	}()
	assert.True(t, timerArmed, "non-host container must still have the max-sniffing-time timer armed")

	// The timer fires, handleContainerMaxTime sends ContainerReachedMaxTime through
	// the monitoring goroutine, which then deletes the container entry.
	require.Eventually(t, func() bool {
		_, exists := cpm.getContainerEntry(containerID)
		return !exists
	}, 2*time.Second, 10*time.Millisecond, "non-host container must still be finalized/deleted once MaxSniffingTime elapses")
}
