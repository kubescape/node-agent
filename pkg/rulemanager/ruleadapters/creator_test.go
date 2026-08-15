package ruleadapters

import (
	armotypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"testing"
)

type MockEnrichEvent struct {
	utils.EnrichEvent
	containerID string
}

func (m *MockEnrichEvent) GetContainerID() string {
	return m.containerID
}

func TestGetHostPath_MappedContainerID(t *testing.T) {
	containerIdToPid := new(maps.SafeMap[string, uint32])
	containerIdToPid.Set("test-container", 1234)

	creator := &RuleFailureCreator{
		containerIdToPid: containerIdToPid,
	}

	mockTrigger := &MockEnrichEvent{containerID: "test-container"}
	processTree := armotypes.Process{
		Path: "/bin/sh",
		PID:  9999,
	}

	hostPath, err := creator.getHostPath(processTree, mockTrigger)
	assert.NoError(t, err)
	assert.Equal(t, "/proc/1234/root/bin/sh", hostPath)
}

func TestGetHostPath_MissingContainerID(t *testing.T) {
	containerIdToPid := new(maps.SafeMap[string, uint32])

	creator := &RuleFailureCreator{
		containerIdToPid: containerIdToPid,
	}

	mockTrigger := &MockEnrichEvent{containerID: "test-container-not-mapped"}
	processTree := armotypes.Process{
		Path: "/bin/sh",
		PID:  9999,
	}

	hostPath, err := creator.getHostPath(processTree, mockTrigger)
	assert.NoError(t, err)
	assert.Equal(t, "/proc/9999/root/bin/sh", hostPath)
}
