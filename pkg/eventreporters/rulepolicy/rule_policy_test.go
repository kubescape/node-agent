package rulepolicy

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubRuleManager struct {
	rulemanager.RuleManagerMock
	ruleIDs       []string
	lastEventType utils.EventType
	lastEvent     utils.K8sEvent
}

func (s *stubRuleManager) EvaluatePolicyRulesForEvent(eventType utils.EventType, event utils.K8sEvent) []string {
	s.lastEventType = eventType
	s.lastEvent = event
	return s.ruleIDs
}

type reportedPolicyCall struct {
	containerID      string
	ruleID           string
	allowedProcess   string
	allowedContainer bool
}

type stubContainerProfileManager struct {
	containerprofilemanager.ContainerProfileManagerMock
	calls []reportedPolicyCall
}

func (s *stubContainerProfileManager) ReportRulePolicy(containerID, ruleID, allowedProcess string, allowedContainer bool) {
	s.calls = append(s.calls, reportedPolicyCall{
		containerID:      containerID,
		ruleID:           ruleID,
		allowedProcess:   allowedProcess,
		allowedContainer: allowedContainer,
	})
}

func TestNewRulePolicyReporter(t *testing.T) {
	rm := &stubRuleManager{}
	cpm := &stubContainerProfileManager{}

	reporter := NewRulePolicyReporter(rm, cpm)
	require.NotNil(t, reporter)
	assert.Same(t, rm, reporter.ruleManager)
	assert.Same(t, cpm, reporter.containerProfileManager)
}

func TestRulePolicyReporter_ReportEvent(t *testing.T) {
	rm := &stubRuleManager{ruleIDs: []string{"R0001", "R0005"}}
	cpm := &stubContainerProfileManager{}

	reporter := NewRulePolicyReporter(rm, cpm)
	require.NotNil(t, reporter)

	ev := &utils.StructEvent{EventType: utils.ExecveEventType}
	reporter.ReportEvent(utils.ExecveEventType, ev, "container-123", "/usr/bin/curl")

	assert.Equal(t, utils.ExecveEventType, rm.lastEventType)
	assert.Same(t, ev, rm.lastEvent)
	require.Len(t, cpm.calls, 2)
	assert.Equal(t, reportedPolicyCall{
		containerID:      "container-123",
		ruleID:           "R0001",
		allowedProcess:   "/usr/bin/curl",
		allowedContainer: false,
	}, cpm.calls[0])
	assert.Equal(t, reportedPolicyCall{
		containerID:      "container-123",
		ruleID:           "R0005",
		allowedProcess:   "/usr/bin/curl",
		allowedContainer: false,
	}, cpm.calls[1])

	// Empty rule list results in no ReportRulePolicy calls
	rmEmpty := &stubRuleManager{ruleIDs: nil}
	cpmEmpty := &stubContainerProfileManager{}
	emptyReporter := NewRulePolicyReporter(rmEmpty, cpmEmpty)
	emptyReporter.ReportEvent(utils.OpenEventType, ev, "container-123", "/etc/hosts")
	assert.Empty(t, cpmEmpty.calls)
}
