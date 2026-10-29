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
	dm.ContainerCallback(containerEvent(containercollection.EventTypeAddContainer, containerID))
	return dm, timers
}

func containerEvent(eventType containercollection.EventType, containerID string) containercollection.PubSubEvent {
	return containercollection.PubSubEvent{
		Type:      eventType,
		Container: &containercollection.Container{Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{ContainerID: containerID}}},
	}
}

func cloudDNSEvent(containerID string, pid uint32, name string, ts int64) *utils.StructEvent {
	return &utils.StructEvent{ContainerID: containerID, Pid: pid, DNSName: name, Addresses: []string{"52.218.0.1"}, Timestamp: ts}
}

func exitEvent(containerID string, pid, tid uint32, ts int64) *utils.StructEvent {
	return &utils.StructEvent{EventType: utils.ExitEventType, ContainerID: containerID, Pid: pid, PID64: uint64(pid)<<32 | uint64(tid), Timestamp: ts}
}

func resolvedNames(dm *DNSManager, containerID string, pid uint32) []string {
	services := dm.ResolveContainerProcessToCloudServices(containerID, pid)
	if services == nil {
		return nil
	}
	return services.ToSlice()
}

func TestReportExitEvent_RecycledPidDoesNotInheritCloudServices(t *testing.T) {
	dm, timers := newExitTestManager(t, "worker")
	dm.ReportEvent(cloudDNSEvent("worker", 4242, "s3.eu-west-1.amazonaws.com.", 100))

	dm.ReportExitEvent(exitEvent("worker", 4242, 4242, 200))
	require.Equal(t, []string{"s3.eu-west-1.amazonaws.com."}, resolvedNames(dm, "worker", 4242), "alerts raised just before the exit must still get the cloud services")

	timers.fire()
	require.Nil(t, dm.ResolveContainerProcessToCloudServices("worker", 4242), "a recycled pid must not inherit cloud services")
}

func TestReportExitEvent_ReplacementKeepsItsCloudServices(t *testing.T) {
	dm, timers := newExitTestManager(t, "worker")
	dm.ReportEvent(cloudDNSEvent("worker", 4242, "s3.eu-west-1.amazonaws.com.", 100))
	dm.ReportExitEvent(exitEvent("worker", 4242, 4242, 200))

	dm.ReportEvent(cloudDNSEvent("worker", 4242, "sts.amazonaws.com.", 300))
	timers.fire()
	require.Equal(t, []string{"sts.amazonaws.com."}, resolvedNames(dm, "worker", 4242), "the replacement must keep only its own cloud services")
}

func TestReportExitEvent_LateExitKeepsReplacementCloudServices(t *testing.T) {
	dm, timers := newExitTestManager(t, "worker")
	dm.ReportEvent(cloudDNSEvent("worker", 4242, "s3.eu-west-1.amazonaws.com.", 100))
	dm.ReportEvent(cloudDNSEvent("worker", 4242, "sts.amazonaws.com.", 300))

	dm.ReportExitEvent(exitEvent("worker", 4242, 4242, 200))
	timers.fire()

	require.Contains(t, resolvedNames(dm, "worker", 4242), "sts.amazonaws.com.", "a late exit must not drop the replacement's cloud services")
}

func TestReportExitEvent_OutOfOrderExitsDropBothProcesses(t *testing.T) {
	dm, timers := newExitTestManager(t, "worker")
	dm.ReportEvent(cloudDNSEvent("worker", 4242, "s3.eu-west-1.amazonaws.com.", 100))
	dm.ReportEvent(cloudDNSEvent("worker", 4242, "sts.amazonaws.com.", 300))

	dm.ReportExitEvent(exitEvent("worker", 4242, 4242, 400))
	dm.ReportExitEvent(exitEvent("worker", 4242, 4242, 200))
	require.NotNil(t, dm.ResolveContainerProcessToCloudServices("worker", 4242), "lookups within the grace period must still get the cloud services")

	timers.fire()
	require.Nil(t, dm.ResolveContainerProcessToCloudServices("worker", 4242), "both exited processes must be dropped after the grace period")
}

func TestReportExitEvent_LookupDuringExitFindsCloudServices(t *testing.T) {
	dm, _ := newExitTestManager(t, "worker")
	for pid := uint32(1000); pid < 3000; pid++ {
		dm.ReportEvent(cloudDNSEvent("worker", pid, "s3.eu-west-1.amazonaws.com.", 100))
		done := make(chan struct{})
		go func() {
			defer close(done)
			dm.ReportExitEvent(exitEvent("worker", pid, pid, 200))
		}()
		for running := true; running; {
			select {
			case <-done:
				running = false
			default:
			}
			require.NotNil(t, dm.ResolveContainerProcessToCloudServices("worker", pid), "a lookup during an exit must still find the cloud services")
		}
	}
}

func TestReportExitEvent_ReaddedContainerDropsRetainedCloudServices(t *testing.T) {
	dm, _ := newExitTestManager(t, "worker")
	dm.ReportEvent(cloudDNSEvent("worker", 4242, "s3.eu-west-1.amazonaws.com.", 100))
	dm.ReportExitEvent(exitEvent("worker", 4242, 4242, 200))

	dm.ContainerCallback(containerEvent(containercollection.EventTypeRemoveContainer, "worker"))
	require.NotNil(t, dm.ResolveContainerProcessToCloudServices("worker", 4242), "alerts for a removed container must still get retained cloud services")
	dm.ContainerCallback(containerEvent(containercollection.EventTypeAddContainer, "worker"))

	require.Nil(t, dm.ResolveContainerProcessToCloudServices("worker", 4242), "a re-added container must not inherit retained cloud services")
}

func TestReportExitEvent_ExitWithoutTimestampKeepsCloudServices(t *testing.T) {
	dm, timers := newExitTestManager(t, "worker")
	dm.ReportEvent(cloudDNSEvent("worker", 4242, "s3.eu-west-1.amazonaws.com.", 100))

	dm.ReportExitEvent(exitEvent("worker", 4242, 4242, 0))

	require.Empty(t, timers.pending, "an exit without a timestamp must not schedule a cleanup")
	require.NotNil(t, dm.ResolveContainerProcessToCloudServices("worker", 4242), "an exit without a timestamp must not drop cloud services")
}

func TestReportExitEvent_ExitWithoutContainerIDKeepsCloudServices(t *testing.T) {
	dm, timers := newExitTestManager(t, "worker")
	dm.ReportEvent(cloudDNSEvent("worker", 4242, "s3.eu-west-1.amazonaws.com.", 100))

	dm.ReportExitEvent(exitEvent("", 4242, 0, 200))

	require.Empty(t, timers.pending, "an exit without a container id must not schedule a cleanup")
	require.NotNil(t, dm.ResolveContainerProcessToCloudServices("worker", 4242), "an exit without a container id must not drop cloud services")
}

func TestReportExitEvent_ThreadExitKeepsCloudServices(t *testing.T) {
	dm, timers := newExitTestManager(t, "worker")
	dm.ReportEvent(cloudDNSEvent("worker", 4242, "s3.eu-west-1.amazonaws.com.", 100))

	dm.ReportExitEvent(exitEvent("worker", 4242, 4243, 200))

	require.Empty(t, timers.pending, "a thread exit must not schedule a cleanup")
	require.NotNil(t, dm.ResolveContainerProcessToCloudServices("worker", 4242), "a thread exit must not drop the process's cloud services")
}

func TestReportExitEvent_ExitedPidsAreDropped(t *testing.T) {
	dm, timers := newExitTestManager(t, "cron-runner")
	for pid := uint32(1000); pid < 6000; pid++ {
		dm.ReportEvent(cloudDNSEvent("cron-runner", pid, "sts.amazonaws.com.", int64(pid)))
		dm.ReportExitEvent(exitEvent("cron-runner", pid, pid, int64(pid)+1))
	}
	timers.fire()

	pidToServices, found := dm.containerToCloudServices.Load("cron-runner")
	require.True(t, found, "container must be tracked")
	require.Zero(t, pidToServices.Len(), "exited pids must not stay in the map")
	require.Empty(t, dm.exitedCloudServices, "exited pids must be dropped after the grace period")
}
