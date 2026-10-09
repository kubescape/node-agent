package tracers

import (
	"context"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/processtree/conversion"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProcfsTracer(t *testing.T) {
	containerCollection := &containercollection.ContainerCollection{}
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	require.NoError(t, err)

	eventCallback := func(event utils.K8sEvent, containerID string, processID uint32) {
		// Test callback
	}

	tracer := NewProcfsTracer(
		containerCollection,
		tracerCollection,
		containercollection.ContainerSelector{},
		eventCallback,
		nil,
		config.Config{ProcfsScanInterval: 5 * time.Second},
		nil,
	)

	assert.NotNil(t, tracer)
	assert.Equal(t, "trace_procfs", tracer.GetName())
	assert.Equal(t, utils.ProcfsEventType, tracer.GetEventType())
	assert.False(t, tracer.started)
}

func TestProcfsTracer_IsEnabled(t *testing.T) {
	containerCollection := &containercollection.ContainerCollection{}
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	require.NoError(t, err)

	tracer := NewProcfsTracer(
		containerCollection,
		tracerCollection,
		containercollection.ContainerSelector{},
		nil,
		nil,
		config.Config{ProcfsScanInterval: 5 * time.Second},
		nil,
	)

	// Test with runtime detection enabled
	cfg := config.Config{EnableRuntimeDetection: true}
	assert.True(t, tracer.IsEnabled(cfg))

	// Test with application profile enabled
	cfg = config.Config{EnableApplicationProfile: true}
	assert.True(t, tracer.IsEnabled(cfg))

	// Test with both disabled
	cfg = config.Config{}
	assert.False(t, tracer.IsEnabled(cfg))
}

func TestProcfsTracer_StartStop(t *testing.T) {
	containerCollection := &containercollection.ContainerCollection{}
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	require.NoError(t, err)

	tracer := NewProcfsTracer(
		containerCollection,
		tracerCollection,
		containercollection.ContainerSelector{},
		nil,
		nil,
		config.Config{ProcfsScanInterval: 5 * time.Second, ProcfsPidScanInterval: 5 * time.Second},
		nil,
	)

	ctx := context.Background()

	// Test start
	err = tracer.Start(ctx)
	assert.NoError(t, err)
	assert.True(t, tracer.started)
	assert.NotNil(t, tracer.eventChan)
	assert.NotNil(t, tracer.cancel)

	// Test double start
	err = tracer.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already started")

	// Test stop
	err = tracer.Stop()
	assert.NoError(t, err)
	assert.False(t, tracer.started)
	assert.Nil(t, tracer.eventChan)
	assert.Nil(t, tracer.cancel)

	// Test restart after stop
	err = tracer.Start(ctx)
	assert.NoError(t, err)
	assert.True(t, tracer.started)
	assert.NoError(t, tracer.Stop())

	// Test stop when not started
	err = tracer.Stop()
	assert.NoError(t, err)
}

func TestProcfsEvent_InterfaceMethods(t *testing.T) {
	event := &events.ProcfsEvent{
		Type:      types.NORMAL,
		Timestamp: types.Time(time.Now().UnixNano()),
		PID:       123,
		Comm:      "test-process",
	}

	assert.Equal(t, utils.ProcfsEventType, event.GetEventType())
	assert.Equal(t, types.NORMAL, event.GetType())
	assert.Equal(t, event.Timestamp, event.GetTimestamp())
	assert.Equal(t, "", event.GetNamespace())
	assert.Equal(t, "", event.GetPod())
}

func TestProcfsTracer_HandleProcfsEvent_SharedNetns(t *testing.T) {
	cc := &containercollection.ContainerCollection{}
	tracerCollection, err := tracercollection.NewTracerCollection(cc)
	require.NoError(t, err)

	const sharedNetns = uint64(4026000100)
	const c1Mntns = uint64(4026000201)
	const c2Mntns = uint64(4026000202)

	c1 := &containercollection.Container{Mntns: c1Mntns, Netns: sharedNetns}
	c1.Runtime.ContainerID = "container-1"
	c2 := &containercollection.Container{Mntns: c2Mntns, Netns: sharedNetns}
	c2.Runtime.ContainerID = "container-2"
	cc.AddContainer(c1)
	cc.AddContainer(c2)

	var recordedEvent *events.ProcfsEvent
	callback := func(event utils.K8sEvent, containerID string, processID uint32) {
		if pe, ok := event.(*events.ProcfsEvent); ok {
			recordedEvent = pe
		}
	}

	tracer := NewProcfsTracer(
		cc,
		tracerCollection,
		containercollection.ContainerSelector{},
		callback,
		nil,
		config.Config{},
		nil,
	)

	// Case 1: Mount namespace matches c1 -> unambiguous
	tracer.handleProcfsEvent(conversion.ProcessEvent{
		ContainerMntNs: c1Mntns,
		ContainerNetNs: sharedNetns,
		PID:            100,
		Path:           "/bin/sh",
	})
	require.NotNil(t, recordedEvent)
	assert.Equal(t, "container-1", recordedEvent.ContainerID)
	assert.False(t, recordedEvent.AmbiguousContainer, "mount namespace match must not be flagged as ambiguous")

	// Case 2: Mount namespace matches c2 -> unambiguous
	recordedEvent = nil
	tracer.handleProcfsEvent(conversion.ProcessEvent{
		ContainerMntNs: c2Mntns,
		ContainerNetNs: sharedNetns,
		PID:            101,
		Path:           "/bin/sh",
	})
	require.NotNil(t, recordedEvent)
	assert.Equal(t, "container-2", recordedEvent.ContainerID)
	assert.False(t, recordedEvent.AmbiguousContainer, "mount namespace match must not be flagged as ambiguous")

	// Case 3: Mount namespace does not match any container, but netns matches multiple -> ambiguous
	const unknownMntns = uint64(4026000999)
	recordedEvent = nil
	tracer.handleProcfsEvent(conversion.ProcessEvent{
		ContainerMntNs: unknownMntns,
		ContainerNetNs: sharedNetns,
		PID:            200,
		Path:           "/bin/sidecar",
	})
	require.NotNil(t, recordedEvent)
	assert.True(t, recordedEvent.AmbiguousContainer, "falling back to shared netns without mntns match must be flagged as ambiguous")
}
