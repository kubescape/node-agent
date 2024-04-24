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

type RuleManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	ReportCapability(event tracercapabilitiestype.Event)
	ReportFileExec(event tracerexectype.Event)
	ReportFileOpen(event traceropentype.Event)
	ReportNetworkEvent(event tracernetworktype.Event)
	ReportDNSEvent(event tracerdnstype.Event)
	ReportRandomxEvent(event tracerrandomxtype.Event)
	ReportSyscallEvent(event tracersyscallstype.Event)
}
