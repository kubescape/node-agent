package rulemanager

import (
	tracerantitamperingtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/antitampering/types"
	tracerhardlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/types"
	tracerrandomxtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/randomx/types"
	tracersymlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/types"

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
	ReportCapability(event tracercapabilitiestype.Event)
	ReportFileExec(event tracerexectype.Event)
	ReportFileOpen(event traceropentype.Event)
	ReportNetworkEvent(event tracernetworktype.Event)
	ReportDNSEvent(event tracerdnstype.Event)
	ReportRandomxEvent(event tracerrandomxtype.Event)
	ReportSymlinkEvent(event tracersymlinktype.Event)
	ReportHardlinkEvent(event tracerhardlinktype.Event)
	ReportAntitamperingEvent(event tracerantitamperingtype.Event)
	HasApplicableRuleBindings(namespace, name string) bool
	HasFinalApplicationProfile(pod *v1.Pod) bool
	IsContainerMonitored(k8sContainerID string) bool
	IsPodMonitored(namespace, pod string) bool
}
