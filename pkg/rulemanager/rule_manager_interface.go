package rulemanager

import (
	tracerrandomxtype "node-agent/pkg/ebpf/gadgets/randomx/types"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	v1 "k8s.io/api/core/v1"
)

type RuleManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	RegisterPeekFunc(peek func(mntns uint64) ([]string, error))
	ReportCapability(k8sContainerID string, event tracercapabilitiestype.Event)
	ReportFileExec(k8sContainerID string, event tracerexectype.Event)
	ReportFileOpen(k8sContainerID string, event traceropentype.Event)
	ReportNetworkEvent(k8sContainerID string, event tracernetworktype.Event)
	ReportDNSEvent(event tracerdnstype.Event)
	ReportRandomxEvent(k8sContainerID string, event tracerrandomxtype.Event)
	HasApplicableRuleBindings(namespace, name string) bool
	HasFinalApplicationProfile(pod *v1.Pod) bool
	IsContainerMonitored(k8sContainerID string) bool
	IsPodMonitored(namespace, pod string) bool
}
