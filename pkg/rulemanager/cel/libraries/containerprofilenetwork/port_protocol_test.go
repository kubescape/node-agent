package containerprofilenetwork

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"k8s.io/utils/ptr"
)

func port(proto string, p int32) v1beta1.NetworkPort {
	return v1beta1.NetworkPort{Protocol: v1beta1.Protocol(proto), Port: ptr.To(p)}
}

func evalEgressPort(lib *containerProfileNetworkLibrary, addr string, p int64, proto string) types.Bool {
	res := lib.wasAddressPortProtocolInEgress(types.String("cid"), types.String(addr), types.Int(p), types.String(proto))
	return cache.ConvertProfileNotAvailableErrToBool(res, false).(types.Bool)
}

func evalIngressPort(lib *containerProfileNetworkLibrary, addr string, p int64, proto string) types.Bool {
	res := lib.wasAddressPortProtocolInIngress(types.String("cid"), types.String(addr), types.Int(p), types.String(proto))
	return cache.ConvertProfileNotAvailableErrToBool(res, false).(types.Bool)
}

func TestWasAddressPortProtocolInEgress_PortWildcard(t *testing.T) {
	noPorts := buildLibWithContainer(t, []v1beta1.NetworkNeighbor{
		{IPAddresses: []string{"93.184.216.34"}},
	}, nil)
	assert.Equal(t, types.Bool(true), evalEgressPort(noPorts, "93.184.216.34", 8080, "TCP"))
	assert.Equal(t, types.Bool(false), evalEgressPort(noPorts, "1.1.1.1", 8080, "TCP"))

	zeroPort := buildLibWithContainer(t, []v1beta1.NetworkNeighbor{
		{IPAddresses: []string{"93.184.216.34"}, Ports: []v1beta1.NetworkPort{port("TCP", 0)}},
	}, nil)
	assert.Equal(t, types.Bool(false), evalEgressPort(zeroPort, "93.184.216.34", 8080, "TCP"),
		"an explicit port 0 is a literal, not a wildcard: only an absent ports stanza opens the entry")
}

func TestWasAddressPortProtocolInIngress_Symmetric(t *testing.T) {
	lib := buildLibWithContainer(t, nil, []v1beta1.NetworkNeighbor{
		{IPAddresses: []string{"172.16.0.0/12"}, Ports: []v1beta1.NetworkPort{port("TCP", 6379)}},
	})
	assert.Equal(t, types.Bool(true), evalIngressPort(lib, "172.16.5.9", 6379, "TCP"))
	assert.Equal(t, types.Bool(false), evalIngressPort(lib, "172.16.5.9", 5432, "TCP"))
	assert.Equal(t, types.Bool(false), evalIngressPort(lib, "10.0.0.1", 6379, "TCP"))
}

func TestWasAddressPortProtocolInEgress_ZeroPortIsNotAWildcard(t *testing.T) {
	lib := buildLibWithContainer(t, []v1beta1.NetworkNeighbor{
		{IPAddresses: []string{"93.184.216.34"}, Ports: []v1beta1.NetworkPort{port("TCP", 0)}},
	}, nil)
	assert.Equal(t, types.Bool(false), evalEgressPort(lib, "93.184.216.34", 8080, "TCP"))
	assert.Equal(t, types.Bool(false), evalEgressPort(lib, "93.184.216.34", 53, "UDP"))
}

func TestWasAddressPortProtocolInEgress_MixedZeroPortKeepsEveryProtocolRestricted(t *testing.T) {
	lib := buildLibWithContainer(t, []v1beta1.NetworkNeighbor{
		{IPAddresses: []string{"10.0.5.9"}, Ports: []v1beta1.NetworkPort{port("TCP", 0), port("UDP", 53)}},
	}, nil)
	assert.Equal(t, types.Bool(false), evalEgressPort(lib, "10.0.5.9", 9999, "TCP"),
		"an explicit {TCP,0} entry no longer opens TCP: wildcard is expressed only by omitting the ports stanza")
	assert.Equal(t, types.Bool(true), evalEgressPort(lib, "10.0.5.9", 53, "UDP"))
	assert.Equal(t, types.Bool(false), evalEgressPort(lib, "10.0.5.9", 54, "UDP"))
}

func TestWasAddressPortProtocolInEgress_NilPortEntryContributesNothing(t *testing.T) {
	lib := buildLibWithContainer(t, []v1beta1.NetworkNeighbor{
		{IPAddresses: []string{"10.0.5.9"}, Ports: []v1beta1.NetworkPort{{Protocol: "TCP"}, port("UDP", 53)}},
	}, nil)
	assert.Equal(t, types.Bool(false), evalEgressPort(lib, "10.0.5.9", 8080, "TCP"))
	assert.Equal(t, types.Bool(true), evalEgressPort(lib, "10.0.5.9", 53, "UDP"))
}

func TestMatchAddrPort_TruthTable(t *testing.T) {
	groups := objectcache.ExtractAddrPorts([]v1beta1.NetworkNeighbor{
		{IPAddresses: []string{"10.0.0.0/8"}, Ports: []v1beta1.NetworkPort{port("TCP", 443)}},
		{IPAddresses: []string{"192.168.1.5"}},
		{IPAddresses: []string{"172.16.0.9"}, Ports: []v1beta1.NetworkPort{port("UDP", 53)}},
		{IPAddresses: []string{"9.9.9.9"}, Ports: []v1beta1.NetworkPort{port("tcp", 8443)}},
	})
	grid := []struct {
		ip    string
		port  int32
		proto string
		want  bool
		why   string
	}{
		{"10.1.2.3", 443, "TCP", true, "CIDR member on the declared port"},
		{"10.1.2.3", 443, "tcp", true, "observed protocol match is case-insensitive"},
		{"10.1.2.3", 443, "Tcp", true, "mixed-case protocol still matches"},
		{"10.1.2.3", 80, "TCP", false, "wrong port (port-sensitive)"},
		{"10.1.2.3", 443, "UDP", false, "wrong protocol"},
		{"192.168.1.5", 9999, "TCP", true, "absent ports stanza = any port"},
		{"192.168.1.5", 53, "udp", true, "absent ports stanza = any protocol too"},
		{"172.16.0.9", 53, "UDP", true, "literal IP + UDP port"},
		{"172.16.0.9", 53, "TCP", false, "protocol-sensitive even on the right port"},
		{"9.9.9.9", 8443, "TCP", true, "lowercase profile protocol is normalised at build"},
		{"8.8.8.8", 443, "TCP", false, "address absent from every group"},
		{"", 443, "TCP", false, "empty address never matches"},
	}
	for _, c := range grid {
		if got := matchAddrPort(groups, c.ip, c.proto, c.port); got != c.want {
			t.Errorf("matchAddrPort(%q,%d,%s)=%v want %v — %s", c.ip, c.port, c.proto, got, c.want, c.why)
		}
	}

	assert.False(t, matchAddrPort(nil, "10.1.2.3", "TCP", 443), "nil groups must never match")
	assert.False(t, matchAddrPort([]objectcache.AddrPortGroup{}, "10.1.2.3", "TCP", 443), "empty groups must never match")
}
