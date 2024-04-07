package ruleengine

import (
	"node-agent/pkg/utils"
	"testing"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestR1000ExecFromMaliciousSource(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1000ExecFromMaliciousSource()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}
	// Create a exec event
	e := &tracerexectype.Event{
		Event: eventtypes.Event{
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						ContainerName: "test",
					},
				},
			},
		},
		Comm: "/test",
		Args: []string{},
	}

	ruleResult := r.ProcessEvent(utils.ExecveEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since test is not a malicious exec")
	}

	e.Comm = "/proc/self/fd/3"

	ruleResult = r.ProcessEvent(utils.ExecveEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult since exec is malicious")
	}
}

// func TestProcessEvent(t *testing.T) {
//     rule := &R1000ExecFromMaliciousSource{}

//     tests := []struct {
//         name     string
//         eventType utils.EventType
//         event    *tracerexectype.Event
//         expected ruleengine.RuleFailure
//     }{
//         {
//             name:     "Test with non-ExecveEventType",
//             eventType: utils.OtherEventType,
//             event:    &tracerexectype.Event{},
//             expected: nil,
//         },
//         {
//             name:     "Test with ExecveEventType and non-malicious source",
//             eventType: utils.ExecveEventType,
//             event: &tracerexectype.Event{
//                 Event: tracerexectype.Event{
//                     Cwd: "/home/user",
//                 },
//             },
//             expected: nil,
//         },
//         {
//             name:     "Test with ExecveEventType and malicious source",
//             eventType: utils.ExecveEventType,
//             event: &tracerexectype.Event{
//                 Event: tracerexectype.Event{
//                     Cwd: "/run_amit.sh",
//                 },
//             },
//             expected: &GenericRuleFailure{
//                 // Fill in expected GenericRuleFailure fields here
//             },
//         },
// 		{
//             name:     "Test with ExecveEventType and malicious source",
//             eventType: utils.ExecveEventType,
//             event: &tracerexectype.Event{
//                 Event: tracerexectype.Event{
//                     Cwd: "/run/amit.sh",
//                 },
//             },
//             expected: &GenericRuleFailure{
//                 // Fill in expected GenericRuleFailure fields here
//             },
//         },
//     }

//     for _, tt := range tests {
//         t.Run(tt.name, func(t *testing.T) {
//             result := rule.ProcessEvent(tt.eventType, tt.event, nil)
//             assert.Equal(t, tt.expected, result)
//         })
//     }
// }
