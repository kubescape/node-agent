package containerprofilemanager

import (
	"context"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWaitForSharedContainerData_HostResolves tests
// pkg/containerprofilemanager/v1/lifecycle.go's waitForSharedContainerData.
//
// Disposition: no host guard is needed here — the site performs no live
// Kubernetes lookup, it only reads the shared-data cache. The read now
// SUCCEEDS for host, where it previously spun on
// exponential backoff until the 10-minute MaxWaitForSharedContainerData
// deadline and then dropped the host container entry entirely.
//
// The assertion is on the actual content, not just "it returned": the host
// must come back with its synthetic identity intact and, critically, with the
// two fields addContainer gates on (UserDefinedProfile, PreRunningContainer)
// set such that the host is NOT silently dropped right after the wait.
func TestWaitForSharedContainerData_HostResolves(t *testing.T) {
	cache := &objectcache.K8sObjectCacheMock{}
	cache.SetSharedContainerData(armotypes.HostContainerID, hostidentity.BuildHostWatchedContainerData("node-1"))
	cpm := &ContainerProfileManager{k8sObjectCache: cache}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	data, err := cpm.waitForSharedContainerData(armotypes.HostContainerID, ctx)

	require.NoError(t, err, "host must no longer stall out of this wait")
	require.NotNil(t, data)
	assert.Less(t, time.Since(start), time.Second, "host data is already present; the wait must return immediately")

	assert.Equal(t, armotypes.HostContainerID, data.ContainerID)
	assert.Equal(t, "host-node-1", data.PodName)
	assert.Equal(t, "host", data.Namespace)
	require.NotNil(t, data.InstanceID, "InstanceID is dereferenced downstream; it must be a real IInstanceID")

	// The two addContainer gates immediately after this wait: either one set the
	// wrong way silently removes the host entry and no profile is ever produced.
	assert.Equal(t, "", data.UserDefinedProfile, "a non-empty UserDefinedProfile would make addContainer drop host")
	assert.False(t, data.PreRunningContainer, "PreRunningContainer would gate host behind EnableRuntimeDetection/EnablePartialProfileGeneration")
}

// TestWaitForSharedContainerData_HostAbsentHonorsDeadline pins that the wait is
// still bounded: if the host injection point ever fails to publish the host
// entry, this site must give up at the context deadline rather than spin
// forever.
func TestWaitForSharedContainerData_HostAbsentHonorsDeadline(t *testing.T) {
	cpm := &ContainerProfileManager{k8sObjectCache: &objectcache.K8sObjectCacheMock{}}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	type result struct {
		data *objectcache.WatchedContainerData
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data, err := cpm.waitForSharedContainerData(armotypes.HostContainerID, ctx)
		done <- result{data, err}
	}()

	select {
	case r := <-done:
		assert.ErrorIs(t, r.err, context.DeadlineExceeded)
		assert.Nil(t, r.data)
	case <-time.After(3 * time.Second):
		t.Fatal("wait did not honor the context deadline")
	}
}
