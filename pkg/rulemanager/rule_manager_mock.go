package rulemanager

import (
	tracerrandomxtype "node-agent/pkg/ebpf/gadgets/randomx/types"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	tracersyscallstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/types"
)

type RuleManagerMock struct {
}

var _ RuleManagerClient = (*RuleManagerMock)(nil)

func CreateRuleManagerMock() *RuleManagerMock {
	return &RuleManagerMock{}
}

func (r *RuleManagerMock) ContainerCallback(_ containercollection.PubSubEvent) {
	// noop
}

func (r *RuleManagerMock) ReportCapability(_ string, _ tracercapabilitiestype.Event) {
	// noop
}

func (r *RuleManagerMock) ReportFileExec(_ string, _ tracerexectype.Event) {
	// noop
}

func (r *RuleManagerMock) ReportFileOpen(_ string, _ traceropentype.Event) {
	// noop
}
func (r *RuleManagerMock) ReportNetworkEvent(_ string, _ tracernetworktype.Event) {
	// noop
}
func (r *RuleManagerMock) ReportDNSEvent(event tracerdnstype.Event) {
	// noop
}
func (r *RuleManagerMock) ReportRandomxEvent(_ string, _ tracerrandomxtype.Event) {
	// noop
}

func (r *RuleManagerMock) ReportSyscallEvent(_ string, _ tracersyscallstype.Event) {
	// noop
}
