package rulemanager

import (
	"net/http"
	"testing"

	"github.com/kubescape/node-agent/pkg/rulemanager/prefilter"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/consts"
	"github.com/stretchr/testify/assert"
)

func TestExtractEventFields(t *testing.T) {
	tests := []struct {
		name   string
		event  *utils.StructEvent
		expect prefilter.EventFields
	}{
		{
			name:   "open event extracts path",
			event:  &utils.StructEvent{EventType: utils.OpenEventType, Path: "/etc/passwd"},
			expect: prefilter.EventFields{Path: "/etc/passwd", Extracted: true},
		},
		{
			name:   "exec event extracts exe path",
			event:  &utils.StructEvent{EventType: utils.ExecveEventType, ExePath: "/usr/bin/curl"},
			expect: prefilter.EventFields{Path: "/usr/bin/curl", Extracted: true},
		},
		{
			name:   "HTTP event extracts direction, method, port",
			event:  &utils.StructEvent{EventType: utils.HTTPEventType, Direction: consts.Inbound, DstPort: 8080, Request: &http.Request{Method: "POST"}},
			expect: prefilter.EventFields{Dir: prefilter.DirInbound, MethodBit: prefilter.MethodPOST, DstPort: 8080, Extracted: true},
		},
		{
			name:   "HTTP nil request leaves method zero",
			event:  &utils.StructEvent{EventType: utils.HTTPEventType, Direction: consts.Outbound},
			expect: prefilter.EventFields{Dir: prefilter.DirOutbound, Extracted: true},
		},
		{
			name:   "HTTP unknown direction maps to DirNone",
			event:  &utils.StructEvent{EventType: utils.HTTPEventType, Direction: "unknown", Request: &http.Request{Method: "POST"}},
			expect: prefilter.EventFields{MethodBit: prefilter.MethodPOST, Extracted: true},
		},
		{
			name:   "network event extracts port and sets PortEligible",
			event:  &utils.StructEvent{EventType: utils.NetworkEventType, DstPort: 443},
			expect: prefilter.EventFields{DstPort: 443, PortEligible: true, Extracted: true},
		},
		{
			name:   "SSH event extracts port and sets PortEligible",
			event:  &utils.StructEvent{EventType: utils.SSHEventType, DstPort: 22},
			expect: prefilter.EventFields{DstPort: 22, PortEligible: true, Extracted: true},
		},
		{
			name:   "unhandled event type returns empty fields",
			event:  &utils.StructEvent{EventType: utils.DnsEventType},
			expect: prefilter.EventFields{Extracted: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractEventFields(tt.event)
			assert.Equal(t, tt.expect, got)
		})
	}
}
