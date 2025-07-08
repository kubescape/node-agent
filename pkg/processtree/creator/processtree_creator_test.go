package processtreecreator

import (
	"encoding/json"
	"testing"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessTreeCreator_CircularReferencePrevention(t *testing.T) {
	containerTree := containerprocesstree.NewContainerProcessTree()
	creator := NewProcessTreeCreator(containerTree).(*processTreeCreatorImpl)

	// Create a process that would have PPID == PID (circular reference)
	circularProcess := &apitypes.Process{
		PID:         42,
		PPID:        42, // Same as PID - this would create a circular reference
		Comm:        "circular-process",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}

	// Add to process map
	creator.processMap.Set(42, circularProcess)

	// Try to link the process to its parent (should be prevented)
	creator.linkProcessToParent(circularProcess)

	// Verify that the process is NOT in its own ChildrenMap (circular reference prevented)
	_, inSelf := circularProcess.ChildrenMap[apitypes.CommPID{Comm: circularProcess.Comm, PID: circularProcess.PID}]
	assert.False(t, inSelf, "Process should not be its own child (circular reference prevented)")

	// Verify that the process tree can be JSON marshaled without errors
	processTree := apitypes.ProcessTree{
		ProcessTree: *circularProcess,
	}

	// This should not panic or fail due to circular references
	jsonData, err := json.Marshal(processTree)
	require.NoError(t, err, "Process tree should be JSON serializable without circular references")
	assert.NotEmpty(t, jsonData, "JSON data should not be empty")

	// Verify the JSON contains the expected data
	var unmarshaled apitypes.ProcessTree
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err, "JSON should be unmarshalable")
	assert.Equal(t, uint32(42), unmarshaled.ProcessTree.PID)
	assert.Equal(t, uint32(42), unmarshaled.ProcessTree.PPID)
	assert.Equal(t, "circular-process", unmarshaled.ProcessTree.Comm)
}
