package ruleadapters

import (
	"net/http"
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
		name      string
		branch    armotypes.Process
		event     armotypes.Process
		isSyscall bool
		want      bool
	}{
		{name: "zero event PID", branch: armotypes.Process{PID: 1}},
		{name: "zero tree PID", event: armotypes.Process{PID: 42}},
		{name: "empty comm still requires matching PID", branch: armotypes.Process{PID: 1}, event: armotypes.Process{PID: 42}},
		{name: "empty comm rejects matching PID", branch: armotypes.Process{PID: 42, Comm: "curl"}, event: armotypes.Process{PID: 42}},
		{name: "syscall empty comm allows matching PID", branch: armotypes.Process{PID: 42, Comm: "curl"}, event: armotypes.Process{PID: 42}, isSyscall: true, want: true},
		{name: "syscall still requires matching PID", branch: armotypes.Process{PID: 1}, event: armotypes.Process{PID: 42}, isSyscall: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, ok := eventProcessTree(tc.branch, tc.event, tc.isSyscall)
			require.Equal(t, tc.want, ok)
			if ok {
				require.Equal(t, tc.branch, tree)
			}
		})
	}
}

func TestCreateRuleFailureEmptyCommAttribution(t *testing.T) {
	for _, eventType := range []utils.EventType{utils.ExecveEventType, utils.NetworkEventType, utils.SyscallEventType} {
		t.Run(string(eventType), func(t *testing.T) {
			creator := NewRuleFailureCreator(nil, dnsmanager.CreateDNSManagerMock(), NewEventRuleAdapterFactory(), 0, "test", new(maps.SafeMap[string, uint32]))
			event := &utils.StructEvent{EventType: eventType, ContainerID: armotypes.HostContainerID, Pid: 42, ExePath: "/event/curl"}
			tree := armotypes.Process{PID: 42, Comm: "unverified", Path: "/unverified/process"}
			failure := creator.CreateRuleFailure(typesv1.Rule{ProfileDependency: armotypes.NotRequired}, &events.EnrichedEvent{Event: event, ContainerID: armotypes.HostContainerID, ProcessTree: tree}, nil, "test", "id", "", nil)
			require.NotNil(t, failure)
			require.Equal(t, uint32(42), failure.GetBaseRuntimeAlert().InfectedPID)
			if eventType == utils.SyscallEventType {
				require.Equal(t, tree, failure.GetRuntimeProcessDetails().ProcessTree)
			} else {
				require.Empty(t, failure.GetRuntimeProcessDetails().ProcessTree.Comm)
				require.Equal(t, "/event/curl", failure.GetRuntimeProcessDetails().ProcessTree.Path)
			}
		})
	}
}

func TestCreateRuleFailureHTTPProcessAttribution(t *testing.T) {
	for _, tc := range []struct {
		name     string
		pid      uint32
		comm     string
		tree     armotypes.Process
		wantTree bool
	}{
		{name: "matching root", pid: 42, comm: "curl", tree: armotypes.Process{PID: 42, Comm: "curl", Path: "/enriched/curl"}, wantTree: true},
		{name: "matching descendant", pid: 42, comm: "curl", tree: armotypes.Process{PID: 1, Comm: "init", ChildrenMap: map[armotypes.CommPID]*armotypes.Process{{Comm: "curl", PID: 42}: {PID: 42, Comm: "curl", Path: "/enriched/curl"}}}, wantTree: true},
		{name: "mismatched command", pid: 42, comm: "curl", tree: armotypes.Process{PID: 42, Comm: "stale", Path: "/stale/process"}},
		{name: "empty event command", pid: 42, tree: armotypes.Process{PID: 42, Comm: "curl", Path: "/enriched/curl"}},
		{name: "empty tree command", pid: 42, comm: "curl", tree: armotypes.Process{PID: 42, Path: "/enriched/curl"}},
		{name: "mismatched PID", pid: 42, comm: "curl", tree: armotypes.Process{PID: 99, Comm: "curl", Path: "/unrelated/curl"}},
		{name: "zero event PID", comm: "curl", tree: armotypes.Process{PID: 42, Comm: "curl"}},
		{name: "zero tree PID", pid: 42, comm: "curl"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, "http://example.com/test", nil)
			require.NoError(t, err)
			event := &utils.StructEvent{EventType: utils.HTTPEventType, ContainerID: armotypes.HostContainerID, Pid: tc.pid, Comm: tc.comm, Request: request}
			creator := NewRuleFailureCreator(nil, dnsmanager.CreateDNSManagerMock(), NewEventRuleAdapterFactory(), 0, "test", new(maps.SafeMap[string, uint32]))
			failure := creator.CreateRuleFailure(typesv1.Rule{ProfileDependency: armotypes.NotRequired}, &events.EnrichedEvent{Event: event, ContainerID: armotypes.HostContainerID, ProcessTree: tc.tree}, nil, "test", "id", "", nil)
			require.NotNil(t, failure)
			require.Equal(t, tc.pid, failure.GetBaseRuntimeAlert().InfectedPID)
			details := failure.GetRuntimeProcessDetails()
			require.Equal(t, armotypes.HostContainerID, details.ContainerID)
			if tc.wantTree {
				require.Equal(t, tc.tree, details.ProcessTree)
			} else {
				require.Equal(t, tc.pid, details.ProcessTree.PID)
				require.Empty(t, details.ProcessTree.Comm)
				require.Empty(t, details.ProcessTree.Path)
				require.Empty(t, details.ProcessTree.ChildrenMap)
			}
		})
	}
}
