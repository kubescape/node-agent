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

func TestCreateRuleFailureProcessAttribution(t *testing.T) {
	for _, eventType := range []utils.EventType{utils.ExecveEventType, utils.NetworkEventType, utils.SyscallEventType} {
		t.Run(string(eventType), func(t *testing.T) {
			for _, tc := range []struct {
				name     string
				tree     armotypes.Process
				wantTree bool
			}{
				{name: "missing tree"},
				{name: "unrelated PID", tree: armotypes.Process{PID: 999, Comm: "curl", Path: "/unrelated/curl"}},
				{name: "stale comm", tree: armotypes.Process{PID: 42, Comm: "old-process", Path: "/old/process"}, wantTree: eventType == utils.SyscallEventType},
				{name: "matching root", tree: armotypes.Process{PID: 42, Comm: "curl", Path: "/enriched/curl"}, wantTree: true},
				{name: "matching descendant", tree: armotypes.Process{PID: 1, Comm: "init", ChildrenMap: map[armotypes.CommPID]*armotypes.Process{{Comm: "curl", PID: 42}: {PID: 42, Comm: "curl", Path: "/enriched/curl"}}}, wantTree: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					creator := NewRuleFailureCreator(nil, dnsmanager.CreateDNSManagerMock(), NewEventRuleAdapterFactory(), 0, "test", new(maps.SafeMap[string, uint32]))
					event := &utils.StructEvent{EventType: eventType, ContainerID: armotypes.HostContainerID, Pid: 42, Comm: "curl", ExePath: "/event/curl", Args: []string{"curl", "example.com"}, Uid: 1000, Gid: 1000}
					enriched := &events.EnrichedEvent{Event: event, ContainerID: armotypes.HostContainerID, ProcessTree: tc.tree}
					failure := creator.CreateRuleFailure(typesv1.Rule{ProfileDependency: armotypes.NotRequired}, enriched, nil, "test", "id", "", nil)
					require.NotNil(t, failure)
					require.Equal(t, uint32(42), failure.GetBaseRuntimeAlert().InfectedPID, "infected PID must remain the event PID, including when enrichment starts at an ancestor")
					require.Equal(t, "curl", failure.GetBaseRuntimeAlert().Identifiers.Process.Name)
					details := failure.GetRuntimeProcessDetails()
					require.Equal(t, armotypes.HostContainerID, details.ContainerID)
					if tc.wantTree {
						require.Equal(t, tc.tree, details.ProcessTree)
					} else {
						require.Equal(t, uint32(42), details.ProcessTree.PID)
						require.Equal(t, "curl", details.ProcessTree.Comm)
						require.Empty(t, details.ProcessTree.ChildrenMap)
						if eventType != utils.SyscallEventType {
							require.Equal(t, "/event/curl", details.ProcessTree.Path)
							require.NotNil(t, details.ProcessTree.Uid)
							require.Equal(t, uint32(1000), *details.ProcessTree.Uid)
							require.NotNil(t, details.ProcessTree.Gid)
							require.Equal(t, uint32(1000), *details.ProcessTree.Gid)
						}
					}
				})
			}
		})
	}
}

func TestEventProcessTreeRequiresPID(t *testing.T) {
	for _, tc := range []struct {
		name   string
		branch armotypes.Process
		event  armotypes.Process
		comm   string
		want   bool
	}{
		{name: "zero event PID", branch: armotypes.Process{PID: 1}},
		{name: "zero tree PID", event: armotypes.Process{PID: 42}},
		{name: "empty comm still requires matching PID", branch: armotypes.Process{PID: 1}, event: armotypes.Process{PID: 42}},
		{name: "empty comm allows matching PID", branch: armotypes.Process{PID: 42, Comm: "curl"}, event: armotypes.Process{PID: 42}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, ok := eventProcessTree(tc.branch, tc.event, tc.comm)
			require.Equal(t, tc.want, ok)
			if ok {
				require.Equal(t, tc.branch, tree)
			}
		})
	}
}
