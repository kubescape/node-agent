package objectcache

import (
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"k8s.io/utils/ptr"
)

func np(proto string, p int32) v1beta1.NetworkPort {
	return v1beta1.NetworkPort{Protocol: v1beta1.Protocol(proto), Port: ptr.To(p)}
}

func TestExtractAddrPorts_ZeroPortIsALiteralNotAWildcard(t *testing.T) {
	groups := ExtractAddrPorts([]v1beta1.NetworkNeighbor{
		{IPAddresses: []string{"10.0.5.9"}, Ports: []v1beta1.NetworkPort{np("TCP", 0), np("UDP", 53)}},
	})
	assert.Len(t, groups, 1)
	assert.NotNil(t, groups[0].Ports, "a zero-port entry must not collapse the entry to fully open")
	assert.Contains(t, groups[0].Ports, PortKey("TCP", 0))
	assert.Contains(t, groups[0].Ports, PortKey("UDP", 53))
	assert.Len(t, groups[0].Ports, 2)
}

func TestExtractAddrPorts_AbsentStanzaIsTheOnlyWildcard(t *testing.T) {
	groups := ExtractAddrPorts([]v1beta1.NetworkNeighbor{
		{IPAddresses: []string{"93.184.216.34"}},
	})
	assert.Len(t, groups, 1)
	assert.Nil(t, groups[0].Ports)
}

func TestExtractAddrPorts_NilPortEntryContributesNothing(t *testing.T) {
	groups := ExtractAddrPorts([]v1beta1.NetworkNeighbor{
		{IPAddresses: []string{"10.1.2.3"}, Ports: []v1beta1.NetworkPort{{Protocol: "TCP", Port: nil}, np("UDP", 53)}},
	})
	assert.Len(t, groups, 1)
	assert.NotNil(t, groups[0].Ports)
	assert.NotContains(t, groups[0].Ports, PortKey("TCP", 0))
	assert.Contains(t, groups[0].Ports, PortKey("UDP", 53))
	assert.Len(t, groups[0].Ports, 1)
}
