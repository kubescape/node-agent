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
	v1 "k8s.io/api/core/v1"
)

type RuleManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	ReportCapability(event tracercapabilitiestype.Event)
	ReportFileExec(event tracerexectype.Event)
	ReportFileOpen(event traceropentype.Event)
	ReportNetworkEvent(event tracernetworktype.Event)
	ReportDNSEvent(event tracerdnstype.Event)
	ReportSyscallEvent(event tracersyscallstype.Event)
	ReportRandomxEvent(event tracerrandomxtype.Event)
	HasApplicableRuleBindings(namespace, name string) bool
	HasFinalApplicationProfile(pod *v1.Pod) bool
	IsContainerMonitored(k8sContainerID string) bool
	IsPodMonitored(namespace, pod string) bool
}
