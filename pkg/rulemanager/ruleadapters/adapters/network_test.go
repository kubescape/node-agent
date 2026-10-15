package adapters

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestNetworkAdapterExePath(t *testing.T) {
	for _, path := range []string{"/usr/bin/curl", ""} {
		t.Run(path, func(t *testing.T) {
			event := &utils.StructEvent{EventType: utils.NetworkEventType, ExePath: path}
			failure := &types.GenericRuleFailure{}
			NewNetworkAdapter().SetFailureMetadata(failure, &events.EnrichedEvent{Event: event}, nil)
			require.Equal(t, path, failure.GetRuntimeProcessDetails().ProcessTree.Path)
		})
	}
}
