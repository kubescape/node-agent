package signaturerulemanager

import containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"

type SignatureRuleManagerMock struct {
}

var _ SignatureRuleManagerClient = (*SignatureRuleManagerMock)(nil)

func CreateApplicationProfileManagerMock() *SignatureRuleManagerMock {
	return &SignatureRuleManagerMock{}
}

func (s SignatureRuleManagerMock) ContainerCallback(_ containercollection.PubSubEvent) {
	// noop
}

func (s SignatureRuleManagerMock) RegisterPeekFunc(_ func(mntns uint64) ([]string, error)) {
	// noop
}

func (s SignatureRuleManagerMock) ReportCapability(_, _ string) {
	// noop
}

func (s SignatureRuleManagerMock) ReportFileExec(_, _ string, _ []string) {
	// noop
}

func (s SignatureRuleManagerMock) ReportFileOpen(_, _ string, _ []string) {
	// noop
}
