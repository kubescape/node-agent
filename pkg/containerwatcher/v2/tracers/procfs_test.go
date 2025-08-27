package tracers

import (
	"context"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	events "github.com/kubescape/node-agent/pkg/ebpf/events"
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
	assert.Equal(t, "procfs_tracer", tracer.GetName())
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

	// Test with runtime detection disabled
	cfg.EnableRuntimeDetection = false
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
		config.Config{ProcfsScanInterval: 5 * time.Second},
		nil,
	)

	ctx := context.Background()

	// Test start
	err = tracer.Start(ctx)
	assert.NoError(t, err)
	assert.True(t, tracer.started)

	// Test double start
	err = tracer.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already started")

	// Test stop
	err = tracer.Stop()
	assert.NoError(t, err)
	assert.False(t, tracer.started)

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

	assert.Equal(t, types.NORMAL, event.GetType())
	assert.Equal(t, event.Timestamp, event.GetTimestamp())
	assert.Equal(t, "", event.GetNamespace())
	assert.Equal(t, "", event.GetPod())
}
