package adapters

import (
	"net/http"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	rmtypes "github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTLSEvent implements utils.KubeletTLSEvent (and its parent utils.EnrichEvent + utils.K8sEvent).
type mockTLSEvent struct {
	containerID  string
	eventType    utils.EventType
	comm         string
	pid          uint32
	tlsData      string
	tlsDataLen   int32
	tlsEventType uint8
}

func (m *mockTLSEvent) GetContainerID() string          { return m.containerID }
func (m *mockTLSEvent) GetEventType() utils.EventType   { return m.eventType }
func (m *mockTLSEvent) GetNamespace() string            { return "test-ns" }
func (m *mockTLSEvent) GetPod() string                  { return "test-pod" }
func (m *mockTLSEvent) GetTimestamp() types.Time        { return 0 }
func (m *mockTLSEvent) HasDroppedEvents() bool          { return false }
func (m *mockTLSEvent) Release()                        {}
func (m *mockTLSEvent) GetComm() string                 { return m.comm }
func (m *mockTLSEvent) GetContainer() string            { return "test-container" }
func (m *mockTLSEvent) GetContainerImage() string       { return "" }
func (m *mockTLSEvent) GetContainerImageDigest() string { return "" }
func (m *mockTLSEvent) GetError() int64                 { return 0 }
func (m *mockTLSEvent) GetExtra() interface{}           { return nil }
func (m *mockTLSEvent) GetGid() *uint32                 { return nil }
func (m *mockTLSEvent) GetHostNetwork() bool            { return false }
func (m *mockTLSEvent) GetMountNsID() uint64            { return 0 }
func (m *mockTLSEvent) GetPcomm() string                { return "" }
func (m *mockTLSEvent) GetPID() uint32                  { return m.pid }
func (m *mockTLSEvent) GetPID64() uint64                { return uint64(m.pid) }
func (m *mockTLSEvent) GetPodLabels() map[string]string { return map[string]string{"app": "test"} }
func (m *mockTLSEvent) GetPpid() uint32                 { return 0 }
func (m *mockTLSEvent) GetUid() *uint32                 { uid := uint32(0); return &uid }
func (m *mockTLSEvent) SetExtra(_ interface{})          {}
func (m *mockTLSEvent) GetTLSData() string              { return m.tlsData }
func (m *mockTLSEvent) GetTLSDataLen() int32            { return m.tlsDataLen }
func (m *mockTLSEvent) GetTLSEventType() uint8          { return m.tlsEventType }

// ECS methods (all empty)
func (m *mockTLSEvent) GetEcsClusterName() string       { return "" }
func (m *mockTLSEvent) GetEcsClusterARN() string        { return "" }
func (m *mockTLSEvent) GetEcsTaskARN() string           { return "" }
func (m *mockTLSEvent) GetEcsTaskFamily() string        { return "" }
func (m *mockTLSEvent) GetEcsTaskDefinitionARN() string { return "" }
func (m *mockTLSEvent) GetEcsServiceName() string       { return "" }
func (m *mockTLSEvent) GetEcsContainerName() string     { return "" }
func (m *mockTLSEvent) GetEcsContainerARN() string      { return "" }
func (m *mockTLSEvent) GetEcsContainerInstance() string { return "" }
func (m *mockTLSEvent) GetEcsAvailabilityZone() string  { return "" }
func (m *mockTLSEvent) GetEcsLaunchType() string        { return "" }

// Additional methods that may be required by other interfaces in the chain
func (m *mockTLSEvent) GetExePath() string                    { return "" }
func (m *mockTLSEvent) GetCwd() string                        { return "" }
func (m *mockTLSEvent) GetArgs() []string                     { return nil }
func (m *mockTLSEvent) GetFlags() []string                    { return nil }
func (m *mockTLSEvent) GetUpperLayer() bool                   { return false }
func (m *mockTLSEvent) GetPupperLayer() bool                  { return false }
func (m *mockTLSEvent) GetDstIP() string                      { return "" }
func (m *mockTLSEvent) GetDstPort() uint16                    { return 0 }
func (m *mockTLSEvent) GetSrcIP() string                      { return "" }
func (m *mockTLSEvent) GetSrcPort() uint16                    { return 0 }
func (m *mockTLSEvent) GetDirection() consts.NetworkDirection { return "" }
func (m *mockTLSEvent) GetInternal() bool                     { return false }
func (m *mockTLSEvent) GetOtherIp() string                    { return "" }
func (m *mockTLSEvent) GetRequest() *http.Request             { return nil }
func (m *mockTLSEvent) GetResponse() *http.Response           { return nil }
func (m *mockTLSEvent) SetResponse(_ *http.Response)          {}
func (m *mockTLSEvent) GetBuf() []byte                        { return nil }
func (m *mockTLSEvent) GetSockFd() uint32                     { return 0 }
func (m *mockTLSEvent) GetSocketInode() uint64                { return 0 }
func (m *mockTLSEvent) GetType() utils.HTTPDataType           { return 0 }
func (m *mockTLSEvent) MakeHttpEvent(_ *http.Request, _ consts.NetworkDirection) utils.HttpEvent {
	return nil
}
func (m *mockTLSEvent) GetSyscall() string               { return "" }
func (m *mockTLSEvent) GetCapability() string            { return "" }
func (m *mockTLSEvent) GetDNSName() string               { return "" }
func (m *mockTLSEvent) GetAddresses() []string           { return nil }
func (m *mockTLSEvent) GetNumAnswers() int               { return 0 }
func (m *mockTLSEvent) GetQr() utils.DNSPktType          { return "" }
func (m *mockTLSEvent) GetProto() string                 { return "" }
func (m *mockTLSEvent) GetDstEndpoint() types.L4Endpoint { return types.L4Endpoint{} }
func (m *mockTLSEvent) GetPktType() string               { return "" }
func (m *mockTLSEvent) GetPodHostIP() string             { return "" }
func (m *mockTLSEvent) GetFlagsRaw() uint32              { return 0 }
func (m *mockTLSEvent) GetFullPath() string              { return "" }
func (m *mockTLSEvent) GetPath() string                  { return "" }
func (m *mockTLSEvent) IsDir() bool                      { return false }
func (m *mockTLSEvent) GetNewPath() string               { return "" }
func (m *mockTLSEvent) GetOldPath() string               { return "" }
func (m *mockTLSEvent) GetModule() string                { return "" }
func (m *mockTLSEvent) GetIdentifier() string            { return "" }
func (m *mockTLSEvent) GetOpcode() int                   { return 0 }
func (m *mockTLSEvent) GetCmd() uint32                   { return 0 }
func (m *mockTLSEvent) GetAttrSize() uint32              { return 0 }

// Compile-time check
var _ utils.KubeletTLSEvent = (*mockTLSEvent)(nil)

func TestKubeletTLSAdapter_WriteEvent(t *testing.T) {
	adapter := NewKubeletTLSAdapter()

	event := &mockTLSEvent{
		containerID:  "container-abc",
		eventType:    utils.KubeletTLSEventType,
		comm:         "kubelet",
		pid:          1234,
		tlsData:      "POST /exec/default/my-pod/my-container HTTP/1.1",
		tlsDataLen:   48,
		tlsEventType: 0, // write
	}

	enrichedEvent := &events.EnrichedEvent{
		Event: event,
	}

	failure := &rmtypes.GenericRuleFailure{}
	adapter.SetFailureMetadata(failure, enrichedEvent, nil)

	// Verify base runtime alert
	alert := failure.GetBaseRuntimeAlert()
	require.NotNil(t, alert.Arguments)
	assert.Equal(t, uint32(1234), alert.InfectedPID)
	assert.Equal(t, "POST /exec/default/my-pod/my-container HTTP/1.1", alert.Arguments["tls_data"])
	assert.Equal(t, int32(48), alert.Arguments["tls_data_len"])
	assert.Equal(t, uint8(0), alert.Arguments["tls_event_type"])
	assert.Equal(t, "write", alert.Arguments["tls_direction"])

	// Verify identifiers
	require.NotNil(t, alert.Identifiers)
	require.NotNil(t, alert.Identifiers.Process)
	assert.Equal(t, "kubelet (kubelet TLS write)", alert.Identifiers.Process.Name)

	// Verify process details
	processTree := failure.GetRuntimeProcessDetails()
	assert.Equal(t, "kubelet", processTree.ProcessTree.Comm)
	assert.Equal(t, uint32(1234), processTree.ProcessTree.PID)
	assert.Equal(t, "container-abc", processTree.ContainerID)

	// Verify K8s details
	k8sDetails := failure.GetRuntimeAlertK8sDetails()
	assert.Equal(t, "test-pod", k8sDetails.PodName)
}

func TestKubeletTLSAdapter_ReadEvent(t *testing.T) {
	adapter := NewKubeletTLSAdapter()

	event := &mockTLSEvent{
		containerID:  "container-def",
		eventType:    utils.KubeletTLSEventType,
		comm:         "kubelet",
		pid:          5678,
		tlsData:      "HTTP/1.1 101 Switching Protocols",
		tlsDataLen:   33,
		tlsEventType: 1, // read
	}

	enrichedEvent := &events.EnrichedEvent{
		Event: event,
	}

	failure := &rmtypes.GenericRuleFailure{}
	adapter.SetFailureMetadata(failure, enrichedEvent, nil)

	alert := failure.GetBaseRuntimeAlert()
	require.NotNil(t, alert.Arguments)
	assert.Equal(t, "read", alert.Arguments["tls_direction"])
	assert.Equal(t, uint8(1), alert.Arguments["tls_event_type"])
	assert.Equal(t, "kubelet (kubelet TLS read)", alert.Identifiers.Process.Name)
}

func TestKubeletTLSAdapter_NonTLSEvent(t *testing.T) {
	adapter := NewKubeletTLSAdapter()

	// Pass a non-TLS event — the adapter should silently return
	enrichedEvent := &events.EnrichedEvent{
		Event: &nonTLSEvent{},
	}

	failure := &rmtypes.GenericRuleFailure{}
	adapter.SetFailureMetadata(failure, enrichedEvent, nil)

	// Nothing should be set
	alert := failure.GetBaseRuntimeAlert()
	assert.Nil(t, alert.Arguments)
	assert.Nil(t, alert.Identifiers)
}

// nonTLSEvent implements K8sEvent but NOT KubeletTLSEvent
type nonTLSEvent struct{}

func (n *nonTLSEvent) GetContainerID() string        { return "" }
func (n *nonTLSEvent) GetEventType() utils.EventType { return utils.ExecveEventType }
func (n *nonTLSEvent) GetNamespace() string          { return "" }
func (n *nonTLSEvent) GetPod() string                { return "" }
func (n *nonTLSEvent) GetTimestamp() types.Time      { return 0 }
func (n *nonTLSEvent) HasDroppedEvents() bool        { return false }
func (n *nonTLSEvent) Release()                      {}
