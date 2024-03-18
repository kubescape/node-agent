package rulemanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
)

type RuleManagerMock struct {
}

var _ RuleManagerClient = (*RuleManagerMock)(nil)

func CreateApplicationProfileManagerMock() *RuleManagerMock {
	return &RuleManagerMock{}
}

func (r *RuleManagerMock) ContainerCallback(_ containercollection.PubSubEvent) {
	// noop
}

func (r *RuleManagerMock) RegisterPeekFunc(_ func(mntns uint64) ([]string, error)) {
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
