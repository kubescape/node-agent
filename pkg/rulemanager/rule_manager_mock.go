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

type RuleManagerMock struct {
}

var _ RuleManagerClient = (*RuleManagerMock)(nil)

func CreateRuleManagerMock() *RuleManagerMock {
	return &RuleManagerMock{}
}

func (r *RuleManagerMock) ContainerCallback(_ containercollection.PubSubEvent) {
	// noop
}

func (r *RuleManagerMock) RegisterPeekFunc(_ func(mntns uint64) ([]string, error)) {
	// noop
}

func (r *RuleManagerMock) ReportCapability(_ tracercapabilitiestype.Event) {
	// noop
}

func (r *RuleManagerMock) ReportFileExec(_ tracerexectype.Event) {
	// noop
}

func (r *RuleManagerMock) ReportFileOpen(_ traceropentype.Event) {
	// noop
}

func (r *RuleManagerMock) ReportNetworkEvent(_ tracernetworktype.Event) {
	// noop
}

func (r *RuleManagerMock) ReportDNSEvent(_ tracerdnstype.Event) {
	// noop
}

func (r *RuleManagerMock) ReportRandomxEvent(_ tracerrandomxtype.Event) {
	// noop
}

func (r *RuleManagerMock) ReportSymlinkEvent(_ tracersymlinktype.Event) {
	// noop
}

func (r *RuleManagerMock) ReportHardlinkEvent(_ tracerhardlinktype.Event) {
	// noop
}

func (r *RuleManagerMock) ReportAntitamperingEvent(_ tracerantitamperingtype.Event) {
	// noop
}

func (r *RuleManagerMock) HasApplicableRuleBindings(_, _ string) bool {
	return false
}

func (r *RuleManagerMock) HasFinalApplicationProfile(_ *v1.Pod) bool {
	return false
}

func (r *RuleManagerMock) IsContainerMonitored(_ string) bool {
	return false
}

func (r *RuleManagerMock) IsPodMonitored(_, _ string) bool {
	return false
}
