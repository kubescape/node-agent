package ruleadapters

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestCreateNetworkRuleFailurePathPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name      string
		eventPath string
		tree      armotypes.Process
		want      string
	}{
		{"missing tree uses socket path", "/socket/curl", armotypes.Process{}, "/socket/curl"},
		{"populated tree takes precedence", "/socket/curl", armotypes.Process{PID: 42, Comm: "curl", Path: "/tree/curl"}, "/tree/curl"},
		{"tree without path is retained", "/socket/curl", armotypes.Process{PID: 42, Comm: "curl"}, ""},
		{"unattributed event and missing tree", "", armotypes.Process{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			creator := NewRuleFailureCreator(nil, dnsmanager.CreateDNSManagerMock(), NewEventRuleAdapterFactory(), 0, "test", new(maps.SafeMap[string, uint32]))
			event := &utils.StructEvent{EventType: utils.NetworkEventType, ExePath: tc.eventPath, Pid: 42, Comm: "curl"}
			failure := creator.CreateRuleFailure(typesv1.Rule{ProfileDependency: armotypes.NotRequired}, &events.EnrichedEvent{Event: event, ProcessTree: tc.tree}, nil, "test", "id", "", nil)
			require.NotNil(t, failure)
			require.Equal(t, tc.want, failure.GetRuntimeProcessDetails().ProcessTree.Path)
			require.Equal(t, uint32(42), failure.GetRuntimeProcessDetails().ProcessTree.PID)
		})
	}
}
