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
	ReportCapability(k8sContainerID string, event tracercapabilitiestype.Event)
	ReportFileExec(k8sContainerID string, event tracerexectype.Event)
	ReportFileOpen(k8sContainerID string, event traceropentype.Event)
	ReportNetworkEvent(k8sContainerID string, event tracernetworktype.Event)
	ReportDNSEvent(event tracerdnstype.Event)
	ReportRandomxEvent(k8sContainerID string, event tracerrandomxtype.Event)
	ReportSyscallEvent(k8sContainerID string, event tracersyscallstype.Event)
}
