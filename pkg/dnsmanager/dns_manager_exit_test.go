package dnsmanager

import (
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/require"
)

func newExitTestManager(t *testing.T, containerID string) *DNSManager {
	t.Helper()
	dm := CreateDNSManager(100)
	dm.exitGracePeriod = 50 * time.Millisecond
	dm.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{ContainerID: containerID}}},
	})
	return dm
}

func exitEvent(containerID string, pid, tid uint32) *utils.StructEvent {
	return &utils.StructEvent{EventType: utils.ExitEventType, ContainerID: containerID, Pid: pid, PID64: uint64(pid)<<32 | uint64(tid)}
}

func TestReportExitEvent_RecycledPidDoesNotInheritCloudServices(t *testing.T) {
	dm := newExitTestManager(t, "worker")
	dm.ReportEvent(&utils.StructEvent{ContainerID: "worker", Pid: 4242, DNSName: "s3.eu-west-1.amazonaws.com.", Addresses: []string{"52.218.0.1"}})

	dm.ReportExitEvent(exitEvent("worker", 4242, 4242))

	require.NotNil(t, dm.ResolveContainerProcessToCloudServices("worker", 4242), "alerts raised just before the exit must still get the cloud services")
	require.Eventually(t, func() bool {
		return dm.ResolveContainerProcessToCloudServices("worker", 4242) == nil
	}, time.Second, 10*time.Millisecond, "a recycled pid must not inherit cloud services")
}

func TestReportExitEvent_ThreadExitKeepsCloudServices(t *testing.T) {
	dm := newExitTestManager(t, "worker")
	dm.ReportEvent(&utils.StructEvent{ContainerID: "worker", Pid: 4242, DNSName: "s3.eu-west-1.amazonaws.com.", Addresses: []string{"52.218.0.1"}})

	dm.ReportExitEvent(exitEvent("worker", 4242, 4243))

	require.Never(t, func() bool {
		return dm.ResolveContainerProcessToCloudServices("worker", 4242) == nil
	}, 200*time.Millisecond, 10*time.Millisecond, "a thread exit must not drop the process's cloud services")
}

func TestReportExitEvent_ExitedPidsAreDropped(t *testing.T) {
	dm := newExitTestManager(t, "cron-runner")
	for pid := uint32(1000); pid < 6000; pid++ {
		dm.ReportEvent(&utils.StructEvent{ContainerID: "cron-runner", Pid: pid, DNSName: "sts.amazonaws.com.", Addresses: []string{"52.94.0.1"}})
		dm.ReportExitEvent(exitEvent("cron-runner", pid, pid))
	}
	pidToServices, found := dm.containerToCloudServices.Load("cron-runner")
	require.True(t, found, "container must be tracked")
	require.Eventually(t, func() bool {
		return pidToServices.Len() == 0
	}, 2*time.Second, 10*time.Millisecond, "exited pids must not stay in the map")
}
