package dnsmanager

import (
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/require"
)

type exitTimers struct {
	pending []func()
}

func (e *exitTimers) afterFunc(_ time.Duration, f func()) *time.Timer {
	e.pending = append(e.pending, f)
	return nil
}

func (e *exitTimers) fire() {
	for _, f := range e.pending {
		f()
	}
	e.pending = nil
}

func newExitTestManager(t *testing.T, containerID string) (*DNSManager, *exitTimers) {
	t.Helper()
	timers := &exitTimers{}
	dm := CreateDNSManager(100)
	dm.afterFunc = timers.afterFunc
	dm.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{ContainerID: containerID}}},
	})
	return dm, timers
}

func cloudDNSEvent(containerID string, pid uint32, name string) *utils.StructEvent {
	return &utils.StructEvent{ContainerID: containerID, Pid: pid, DNSName: name, Addresses: []string{"52.218.0.1"}}
}

func exitEvent(containerID string, pid, tid uint32) *utils.StructEvent {
	return &utils.StructEvent{EventType: utils.ExitEventType, ContainerID: containerID, Pid: pid, PID64: uint64(pid)<<32 | uint64(tid)}
}

func TestReportExitEvent_RecycledPidDoesNotInheritCloudServices(t *testing.T) {
	dm, timers := newExitTestManager(t, "worker")
	dm.ReportEvent(cloudDNSEvent("worker", 4242, "s3.eu-west-1.amazonaws.com."))

	dm.ReportExitEvent(exitEvent("worker", 4242, 4242))
	require.NotNil(t, dm.ResolveContainerProcessToCloudServices("worker", 4242), "alerts raised just before the exit must still get the cloud services")

	timers.fire()
	require.Nil(t, dm.ResolveContainerProcessToCloudServices("worker", 4242), "a recycled pid must not inherit cloud services")
}

func TestReportExitEvent_ReplacementKeepsItsCloudServices(t *testing.T) {
	dm, timers := newExitTestManager(t, "worker")
	dm.ReportEvent(cloudDNSEvent("worker", 4242, "s3.eu-west-1.amazonaws.com."))
	dm.ReportExitEvent(exitEvent("worker", 4242, 4242))

	dm.ReportEvent(cloudDNSEvent("worker", 4242, "sts.amazonaws.com."))
	timers.fire()

	got := dm.ResolveContainerProcessToCloudServices("worker", 4242)
	require.NotNil(t, got, "the replacement must keep its cloud services")
	require.ElementsMatch(t, []string{"sts.amazonaws.com."}, got.ToSlice(), "the replacement must not inherit the exited process's cloud services")
}

func TestReportExitEvent_ThreadExitKeepsCloudServices(t *testing.T) {
	dm, timers := newExitTestManager(t, "worker")
	dm.ReportEvent(cloudDNSEvent("worker", 4242, "s3.eu-west-1.amazonaws.com."))

	dm.ReportExitEvent(exitEvent("worker", 4242, 4243))

	require.Empty(t, timers.pending, "a thread exit must not schedule a cleanup")
	require.NotNil(t, dm.ResolveContainerProcessToCloudServices("worker", 4242), "a thread exit must not drop the process's cloud services")
}

func TestReportExitEvent_ExitedPidsAreDropped(t *testing.T) {
	dm, timers := newExitTestManager(t, "cron-runner")
	for pid := uint32(1000); pid < 6000; pid++ {
		dm.ReportEvent(cloudDNSEvent("cron-runner", pid, "sts.amazonaws.com."))
		dm.ReportExitEvent(exitEvent("cron-runner", pid, pid))
	}
	timers.fire()

	pidToServices, found := dm.containerToCloudServices.Load("cron-runner")
	require.True(t, found, "container must be tracked")
	require.Zero(t, pidToServices.Len(), "exited pids must not stay in the map")
	require.Empty(t, dm.exitedCloudServices, "exited pids must be dropped after the grace period")
}
