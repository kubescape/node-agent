package cel

import (
	"net/http"
	"testing"

	"github.com/goradd/maps"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKubeletTLSEvent implements utils.CelEvent for testing the kubelet_tls CEL wiring.
// CelEvent embeds all event interfaces (CapabilitiesEvent, DNSEvent, ExecEvent, etc.).
// We only provide meaningful data for the KubeletTLSEvent methods; all others return zero values.
type mockKubeletTLSEvent struct {
	containerID  string
	eventType    utils.EventType
	comm         string
	pid          uint32
	tlsData      string
	tlsDataLen   int32
	tlsEventType uint8 // 0=write, 1=read
}

// K8sEvent methods
func (m *mockKubeletTLSEvent) GetContainerID() string        { return m.containerID }
func (m *mockKubeletTLSEvent) GetEventType() utils.EventType { return m.eventType }
func (m *mockKubeletTLSEvent) GetNamespace() string          { return "test-ns" }
func (m *mockKubeletTLSEvent) GetPod() string                { return "test-pod" }
func (m *mockKubeletTLSEvent) GetTimestamp() types.Time      { return 0 }
func (m *mockKubeletTLSEvent) HasDroppedEvents() bool        { return false }
func (m *mockKubeletTLSEvent) Release()                      {}

// EnrichEvent methods
func (m *mockKubeletTLSEvent) GetComm() string                 { return m.comm }
func (m *mockKubeletTLSEvent) GetContainer() string            { return "test-container" }
func (m *mockKubeletTLSEvent) GetContainerImage() string       { return "" }
func (m *mockKubeletTLSEvent) GetContainerImageDigest() string { return "" }
func (m *mockKubeletTLSEvent) GetError() int64                 { return 0 }
func (m *mockKubeletTLSEvent) GetExtra() interface{}           { return nil }
func (m *mockKubeletTLSEvent) GetGid() *uint32                 { return nil }
func (m *mockKubeletTLSEvent) GetHostNetwork() bool            { return false }
func (m *mockKubeletTLSEvent) GetMountNsID() uint64            { return 0 }
func (m *mockKubeletTLSEvent) GetPcomm() string                { return "" }
func (m *mockKubeletTLSEvent) GetPID() uint32                  { return m.pid }
func (m *mockKubeletTLSEvent) GetPID64() uint64                { return uint64(m.pid) }
func (m *mockKubeletTLSEvent) GetPodLabels() map[string]string { return nil }
func (m *mockKubeletTLSEvent) GetPpid() uint32                 { return 0 }
func (m *mockKubeletTLSEvent) GetUid() *uint32                 { return nil }
func (m *mockKubeletTLSEvent) SetExtra(extra interface{})      {}
func (m *mockKubeletTLSEvent) GetEcsClusterName() string       { return "" }
func (m *mockKubeletTLSEvent) GetEcsClusterARN() string        { return "" }
func (m *mockKubeletTLSEvent) GetEcsTaskARN() string           { return "" }
func (m *mockKubeletTLSEvent) GetEcsTaskFamily() string        { return "" }
func (m *mockKubeletTLSEvent) GetEcsTaskDefinitionARN() string { return "" }
func (m *mockKubeletTLSEvent) GetEcsServiceName() string       { return "" }
func (m *mockKubeletTLSEvent) GetEcsContainerName() string     { return "" }
func (m *mockKubeletTLSEvent) GetEcsContainerARN() string      { return "" }
func (m *mockKubeletTLSEvent) GetEcsContainerInstance() string { return "" }
func (m *mockKubeletTLSEvent) GetEcsAvailabilityZone() string  { return "" }
func (m *mockKubeletTLSEvent) GetEcsLaunchType() string        { return "" }

// BpfEvent methods
func (m *mockKubeletTLSEvent) GetCmd() uint32      { return 0 }
func (m *mockKubeletTLSEvent) GetAttrSize() uint32 { return 0 }

// CapabilitiesEvent methods
func (m *mockKubeletTLSEvent) GetCapability() string { return "" }

// DNSEvent methods
func (m *mockKubeletTLSEvent) GetAddresses() []string  { return nil }
func (m *mockKubeletTLSEvent) GetDNSName() string      { return "" }
func (m *mockKubeletTLSEvent) GetNumAnswers() int      { return 0 }
func (m *mockKubeletTLSEvent) GetQr() utils.DNSPktType { return "" }

// ExecEvent methods
func (m *mockKubeletTLSEvent) GetArgs() []string    { return nil }
func (m *mockKubeletTLSEvent) GetPupperLayer() bool { return false }

// HttpEvent methods
func (m *mockKubeletTLSEvent) GetBuf() []byte              { return nil }
func (m *mockKubeletTLSEvent) GetSockFd() uint32           { return 0 }
func (m *mockKubeletTLSEvent) GetSocketInode() uint64      { return 0 }
func (m *mockKubeletTLSEvent) GetType() utils.HTTPDataType { return 0 }
func (m *mockKubeletTLSEvent) MakeHttpEvent(_ *http.Request, _ consts.NetworkDirection) utils.HttpEvent {
	return nil
}
func (m *mockKubeletTLSEvent) GetDirection() consts.NetworkDirection { return "" }
func (m *mockKubeletTLSEvent) GetInternal() bool                     { return false }
func (m *mockKubeletTLSEvent) GetOtherIp() string                    { return "" }
func (m *mockKubeletTLSEvent) GetRequest() *http.Request             { return nil }
func (m *mockKubeletTLSEvent) GetResponse() *http.Response           { return nil }
func (m *mockKubeletTLSEvent) SetResponse(_ *http.Response)          {}

// IOUring methods
func (m *mockKubeletTLSEvent) GetIdentifier() string { return "" }
func (m *mockKubeletTLSEvent) GetOpcode() int        { return 0 }

// KubeletTLSEvent methods — the important ones
func (m *mockKubeletTLSEvent) GetTLSData() string     { return m.tlsData }
func (m *mockKubeletTLSEvent) GetTLSDataLen() int32   { return m.tlsDataLen }
func (m *mockKubeletTLSEvent) GetTLSEventType() uint8 { return m.tlsEventType }

// KmodEvent methods
func (m *mockKubeletTLSEvent) GetModule() string { return "" }

// LinkEvent methods
func (m *mockKubeletTLSEvent) GetNewPath() string { return "" }
func (m *mockKubeletTLSEvent) GetOldPath() string { return "" }

// NetworkEvent methods
func (m *mockKubeletTLSEvent) GetDstEndpoint() types.L4Endpoint { return types.L4Endpoint{} }
func (m *mockKubeletTLSEvent) GetPktType() string               { return "" }
func (m *mockKubeletTLSEvent) GetPodHostIP() string             { return "" }
func (m *mockKubeletTLSEvent) GetProto() string                 { return "" }

// OpenEvent methods
func (m *mockKubeletTLSEvent) GetFlagsRaw() uint32 { return 0 }
func (m *mockKubeletTLSEvent) GetFullPath() string { return "" }
func (m *mockKubeletTLSEvent) GetPath() string     { return "" }
func (m *mockKubeletTLSEvent) IsDir() bool         { return false }

// SshEvent methods
func (m *mockKubeletTLSEvent) GetDstIP() string   { return "" }
func (m *mockKubeletTLSEvent) GetDstPort() uint16 { return 0 }
func (m *mockKubeletTLSEvent) GetSrcIP() string   { return "" }
func (m *mockKubeletTLSEvent) GetSrcPort() uint16 { return 0 }

// SyscallEvent methods
func (m *mockKubeletTLSEvent) GetSyscall() string { return "" }

// UnshareEvent methods — no unique methods beyond shared ones

// Shared methods that appear in multiple interfaces
func (m *mockKubeletTLSEvent) GetExePath() string  { return "" }
func (m *mockKubeletTLSEvent) GetCwd() string      { return "" }
func (m *mockKubeletTLSEvent) GetFlags() []string  { return nil }
func (m *mockKubeletTLSEvent) GetUpperLayer() bool { return false }

// Compile-time check: mockKubeletTLSEvent must implement CelEvent
var _ utils.CelEvent = (*mockKubeletTLSEvent)(nil)

func newMockObjectCache() objectcache.ObjectCache {
	return &objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}
}

// TestKubeletTLSCelRuleCompilation verifies that the R1031 rule expressions
// compile successfully in the CEL environment.
func TestKubeletTLSCelRuleCompilation(t *testing.T) {
	celEval, err := NewCEL(newMockObjectCache(), config.Config{})
	require.NoError(t, err)

	expressions := []string{
		// R1031 rule expression — always matches kubelet_tls events
		`true`,
		// Message expression from R1031
		`'Kubelet TLS exec request intercepted: ' + event.tlsData + ' (len=' + string(event.tlsDataLen) + ', type=' + string(event.tlsEventType) + ') in ' + event.comm + '.'`,
		// UniqueID expression from R1031
		`event.comm + '_' + string(event.tlsEventType)`,
		// More complex expressions accessing kubelet_tls fields
		`event.tlsDataLen > 0`,
		`event.tlsEventType == 0u || event.tlsEventType == 1u`,
		`event.tlsData.contains("exec")`,
	}

	for _, expr := range expressions {
		t.Run(expr, func(t *testing.T) {
			err := celEval.registerExpression(expr)
			assert.NoError(t, err, "Expression should compile: %s", expr)
		})
	}
}

// TestKubeletTLSEvaluateRule verifies that EvaluateRule correctly matches
// kubelet_tls events against R1031 rule expressions.
func TestKubeletTLSEvaluateRule(t *testing.T) {
	celEval, err := NewCEL(newMockObjectCache(), config.Config{})
	require.NoError(t, err)

	tests := []struct {
		name      string
		event     *mockKubeletTLSEvent
		ruleExprs []typesv1.RuleExpression
		wantMatch bool
		wantErr   bool
	}{
		{
			name: "R1031 always-true rule matches kubelet_tls write event",
			event: &mockKubeletTLSEvent{
				containerID:  "test-container-123",
				eventType:    utils.KubeletTLSEventType,
				comm:         "kubelet",
				pid:          1234,
				tlsData:      "POST /exec/test-ns/test-pod/alpine HTTP/1.1",
				tlsDataLen:   44,
				tlsEventType: 0, // write
			},
			ruleExprs: []typesv1.RuleExpression{
				{
					EventType:  utils.KubeletTLSEventType,
					Expression: "true",
				},
			},
			wantMatch: true,
		},
		{
			name: "R1031 always-true rule matches kubelet_tls read event",
			event: &mockKubeletTLSEvent{
				containerID:  "test-container-456",
				eventType:    utils.KubeletTLSEventType,
				comm:         "kubelet",
				pid:          5678,
				tlsData:      "HTTP/1.1 101 Switching Protocols",
				tlsDataLen:   33,
				tlsEventType: 1, // read
			},
			ruleExprs: []typesv1.RuleExpression{
				{
					EventType:  utils.KubeletTLSEventType,
					Expression: "true",
				},
			},
			wantMatch: true,
		},
		{
			name: "expression checking data length matches",
			event: &mockKubeletTLSEvent{
				containerID:  "test-container-789",
				eventType:    utils.KubeletTLSEventType,
				comm:         "kubelet",
				pid:          9999,
				tlsData:      "POST /exec/ns/pod/container HTTP/1.1",
				tlsDataLen:   37,
				tlsEventType: 0,
			},
			ruleExprs: []typesv1.RuleExpression{
				{
					EventType:  utils.KubeletTLSEventType,
					Expression: "event.tlsDataLen > 0",
				},
			},
			wantMatch: true,
		},
		{
			name: "expression checking data contains exec",
			event: &mockKubeletTLSEvent{
				containerID:  "test-container-abc",
				eventType:    utils.KubeletTLSEventType,
				comm:         "kubelet",
				pid:          1111,
				tlsData:      "POST /exec/ns/pod/container HTTP/1.1",
				tlsDataLen:   37,
				tlsEventType: 0,
			},
			ruleExprs: []typesv1.RuleExpression{
				{
					EventType:  utils.KubeletTLSEventType,
					Expression: `event.tlsData.contains("exec")`,
				},
			},
			wantMatch: true,
		},
		{
			name: "expression checking data does NOT contain exec",
			event: &mockKubeletTLSEvent{
				containerID:  "test-container-def",
				eventType:    utils.KubeletTLSEventType,
				comm:         "kubelet",
				pid:          2222,
				tlsData:      "GET /healthz HTTP/1.1",
				tlsDataLen:   21,
				tlsEventType: 0,
			},
			ruleExprs: []typesv1.RuleExpression{
				{
					EventType:  utils.KubeletTLSEventType,
					Expression: `event.tlsData.contains("exec")`,
				},
			},
			wantMatch: false,
		},
		{
			name: "wrong event type does not match kubelet_tls rule",
			event: &mockKubeletTLSEvent{
				containerID:  "test-container-ghi",
				eventType:    utils.ExecveEventType, // not kubelet_tls
				comm:         "bash",
				pid:          3333,
				tlsData:      "",
				tlsDataLen:   0,
				tlsEventType: 0,
			},
			ruleExprs: []typesv1.RuleExpression{
				{
					EventType:  utils.KubeletTLSEventType,
					Expression: "true",
				},
			},
			wantMatch: true, // EvaluateRule returns true when no expressions match the event type
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enrichedEvent := &events.EnrichedEvent{
				Event: tt.event,
			}

			matched, err := celEval.EvaluateRule(enrichedEvent, tt.ruleExprs)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantMatch, matched, "Rule match should be %v", tt.wantMatch)
			}
		})
	}
}

// TestKubeletTLSEvaluateMessageExpression verifies that the R1031 message
// expression correctly generates alert messages from kubelet_tls events.
func TestKubeletTLSEvaluateMessageExpression(t *testing.T) {
	celEval, err := NewCEL(newMockObjectCache(), config.Config{})
	require.NoError(t, err)

	event := &mockKubeletTLSEvent{
		containerID:  "test-container-msg",
		eventType:    utils.KubeletTLSEventType,
		comm:         "kubelet",
		pid:          4444,
		tlsData:      "POST /exec/default/my-pod/my-container HTTP/1.1",
		tlsDataLen:   48,
		tlsEventType: 0,
	}

	enrichedEvent := &events.EnrichedEvent{
		Event: event,
	}

	// Test the R1031 message expression
	messageExpr := `'Kubelet TLS exec request intercepted: ' + event.tlsData + ' (len=' + string(event.tlsDataLen) + ', type=' + string(event.tlsEventType) + ') in ' + event.comm + '.'`

	msg, err := celEval.EvaluateExpression(enrichedEvent, messageExpr)
	require.NoError(t, err)
	assert.Contains(t, msg, "Kubelet TLS exec request intercepted:")
	assert.Contains(t, msg, "POST /exec/default/my-pod/my-container HTTP/1.1")
	assert.Contains(t, msg, "len=48")
	assert.Contains(t, msg, "type=0")
	assert.Contains(t, msg, "kubelet")

	// Test the uniqueID expression
	uniqueIDExpr := `event.comm + '_' + string(event.tlsEventType)`
	uniqueID, err := celEval.EvaluateExpression(enrichedEvent, uniqueIDExpr)
	require.NoError(t, err)
	assert.Equal(t, "kubelet_0", uniqueID)
}

// TestKubeletTLSEvaluateMessageExpression_ReadEvent tests message generation for a read event.
func TestKubeletTLSEvaluateMessageExpression_ReadEvent(t *testing.T) {
	celEval, err := NewCEL(newMockObjectCache(), config.Config{})
	require.NoError(t, err)

	event := &mockKubeletTLSEvent{
		containerID:  "test-container-read",
		eventType:    utils.KubeletTLSEventType,
		comm:         "kubelet",
		pid:          5555,
		tlsData:      "HTTP/1.1 101 Switching Protocols",
		tlsDataLen:   33,
		tlsEventType: 1, // read
	}

	enrichedEvent := &events.EnrichedEvent{
		Event: event,
	}

	uniqueIDExpr := `event.comm + '_' + string(event.tlsEventType)`
	uniqueID, err := celEval.EvaluateExpression(enrichedEvent, uniqueIDExpr)
	require.NoError(t, err)
	assert.Equal(t, "kubelet_1", uniqueID)
}
