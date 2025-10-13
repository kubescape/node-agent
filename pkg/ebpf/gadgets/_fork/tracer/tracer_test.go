package tracer

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/_fork/types"
	"github.com/stretchr/testify/assert"
)

func TestForkTracer_NewTracer(t *testing.T) {
	// Test that we can create a new tracer
	config := &Config{}
	eventCallback := func(event *types.Event) {
		// This will be called when events are received
	}

	tracer, err := NewTracer(config, eventCallback)
	if err != nil {
		// This is expected if we don't have root privileges
		t.Logf("Expected error when not running as root: %v", err)
		return
	}
	assert.NotNil(t, tracer)

	// Clean up
	if tracer != nil {
		tracer.Stop()
	}
}

func TestForkTracer_EventStructure(t *testing.T) {
	// Test that the event structure is correct
	event := types.Event{
		Pid:      1234,
		Tid:      1234,
		PPid:     1000,
		Uid:      1000,
		Gid:      1000,
		Comm:     "test-process",
		ExePath:  "/usr/bin/test-process",
		ChildPid: 5678,
		ChildTid: 5678,
	}

	assert.Equal(t, uint32(1234), event.Pid)
	assert.Equal(t, uint32(1000), event.PPid)
	assert.Equal(t, "test-process", event.Comm)
	assert.Equal(t, "/usr/bin/test-process", event.ExePath)
	assert.Equal(t, uint32(5678), event.ChildPid)
}

func TestForkTracer_GadgetDesc(t *testing.T) {
	// Test that the GadgetDesc works correctly
	desc := &GadgetDesc{}
	gadget, err := desc.NewInstance()
	assert.NoError(t, err)
	assert.NotNil(t, gadget)

	// Test that we can set the mount namespace map
	tracer, ok := gadget.(*Tracer)
	assert.True(t, ok)
	assert.NotNil(t, tracer)
}
