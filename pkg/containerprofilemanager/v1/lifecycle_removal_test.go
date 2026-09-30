package containerprofilemanager

import (
	"context"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRemovalTestManager(t *testing.T, cfg config.Config) (*ContainerProfileManager, *objectcache.K8sObjectCacheMock) {
	t.Helper()
	t.Setenv("QUEUE_DIR", t.TempDir())
	k8s := &objectcache.K8sObjectCacheMock{}
	cpm, err := NewContainerProfileManager(context.Background(), cfg, &k8sclient.K8sClientMock{}, k8s,
		&storage.StorageHttpClientMock{}, &dnsmanager.DNSManagerMock{}, &seccompmanager.SeccompManagerMock{}, nil, nil, nil)
	require.NoError(t, err)
	t.Cleanup(cpm.Close)
	return cpm, k8s
}

func removalTestContainer(id string) *containercollection.Container {
	return &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
			ContainerID:   id,
			ContainerName: "init",
			ContainerPID:  42,
		}},
		K8s: containercollection.K8sMetadata{BasicK8sMetadata: eventtypes.BasicK8sMetadata{
			Namespace: "default",
			PodName:   "pod",
		}},
	}
}

// A container removed before its shared data exists must abort its pending
// registration right away instead of waiting out the timeout, on both the
// regular and the namespace-filter callback paths.
func TestContainerCallback_RemovalAbortsPendingRegistration(t *testing.T) {
	for name, cfg := range map[string]config.Config{
		"regular":          {MaxSniffingTime: time.Hour},
		"namespace filter": {MaxSniffingTime: time.Hour, NamespaceFilterFile: "filter.yaml"},
	} {
		t.Run(name, func(t *testing.T) {
			cpm, _ := newRemovalTestManager(t, cfg)
			container := removalTestContainer("short-lived")

			cpm.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeAddContainer, Container: container})
			require.Eventually(t, func() bool {
				_, ok := cpm.getContainerEntry("short-lived")
				return ok
			}, 2*time.Second, 5*time.Millisecond, "registration must be waiting for shared data")

			cpm.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeRemoveContainer, Container: container})
			require.Eventually(t, func() bool {
				_, ok := cpm.getContainerEntry("short-lived")
				return !ok && cpm.pendingAdds.Len("short-lived") == 0
			}, 2*time.Second, 5*time.Millisecond, "removal must abort the registration and clean up")
		})
	}
}

// Only a removal downgrades the failure; a live container whose shared data
// never arrives, or a failure with shared data present, stays an error.
func TestAddContainer_FailureClassification(t *testing.T) {
	cpm, k8s := newRemovalTestManager(t, config.Config{MaxSniffingTime: time.Hour})

	t.Run("removed while waiting for shared data", func(t *testing.T) {
		parent, release := cpm.pendingAdds.Track("removed")
		defer release()
		ctx, cancel := context.WithTimeout(parent, time.Minute)
		defer cancel()
		time.AfterFunc(20*time.Millisecond, func() { cpm.pendingAdds.Cancel("removed") })

		require.Error(t, cpm.addContainer(removalTestContainer("removed"), ctx))
		assert.True(t, utils.RemovedDuringAdd(ctx))
	})

	t.Run("live container without shared data", func(t *testing.T) {
		parent, release := cpm.pendingAdds.Track("live")
		defer release()
		ctx, cancel := context.WithTimeout(parent, 50*time.Millisecond)
		defer cancel()

		require.Error(t, cpm.addContainer(removalTestContainer("live"), ctx))
		assert.False(t, utils.RemovedDuringAdd(ctx))
	})

	t.Run("failure with shared data present", func(t *testing.T) {
		k8s.SetSharedContainerData("present", &objectcache.WatchedContainerData{ContainerID: "present"})
		parent, release := cpm.pendingAdds.Track("present")
		defer release()
		ctx, cancel := context.WithTimeout(parent, time.Minute)
		defer cancel()

		// No registered entry: addContainer fails after the shared-data wait.
		require.Error(t, cpm.addContainer(removalTestContainer("present"), ctx))
		assert.False(t, utils.RemovedDuringAdd(ctx))
	})
}
