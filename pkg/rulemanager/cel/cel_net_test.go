package cel

import (
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/require"
)

// TestCEL_FormatEndpoint runs net.format_endpoint through the rule manager's
// CEL environment against a real network event, the way a rule message uses it.
func TestCEL_FormatEndpoint(t *testing.T) {
	c := newTestCEL(t)
	const expr = `'connection to ' + net.format_endpoint(event.dstAddr, event.dstPort)`

	for _, tt := range []struct {
		addr     string
		expected string
	}{
		{addr: "10.0.0.5", expected: "connection to 10.0.0.5:23"},
		{addr: "fd00::1", expected: "connection to [fd00::1]:23"},
	} {
		t.Run(tt.addr, func(t *testing.T) {
			e := &utils.StructEvent{
				EventType:   utils.NetworkEventType,
				DstEndpoint: types.L3Endpoint{Addr: tt.addr},
				DstPort:     23,
			}
			out, err := c.EvaluateExpression(&events.EnrichedEvent{Event: e}, expr)
			require.NoError(t, err)
			require.Equal(t, tt.expected, out)
		})
	}
}
