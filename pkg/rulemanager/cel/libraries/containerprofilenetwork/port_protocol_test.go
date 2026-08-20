package containerprofilenetwork

import (
	"testing"

	"github.com/google/cel-go/common/types"
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
