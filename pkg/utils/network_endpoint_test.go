package utils

import (
	"encoding/binary"
	"net"
	"testing"

	celtypes "github.com/google/cel-go/common/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/picatz/xcel"
	"github.com/stretchr/testify/require"
)

func TestNetworkEndpointAddressFamilies(t *testing.T) {
	// Accessors are cached per event type in production. Isolate the synthetic
	// schema from other tests using network data sources.
	cached, existed := fieldCaches.LoadAndDelete(NetworkEventType)
	t.Cleanup(func() {
		fieldCaches.Delete(NetworkEventType)
		if existed {
			fieldCaches.Store(NetworkEventType, cached)
		}
	})
	ds, err := datasource.New(datasource.TypeSingle, "network")
	require.NoError(t, err)
	fields := make(map[string]datasource.FieldAccessor)
	for name, kind := range map[string]api.Kind{
		"endpoint.addr_raw.v4": api.Kind_Uint32,
		"endpoint.addr_raw.v6": api.Kind_Bytes,
		"endpoint.version":     api.Kind_Uint8,
		"endpoint.port":        api.Kind_Uint16,
		"endpoint.proto_raw":   api.Kind_Uint16,
	} {
		fields[name], err = ds.AddField(name, kind)
		require.NoError(t, err)
	}
	for _, ip := range []string{"::1", "fc00::1", "fe80::1234", "2001:db8::abcd", "10.1.2.3", "100.64.0.1"} {
		t.Run(ip, func(t *testing.T) {
			data, err := ds.NewPacketSingle()
			require.NoError(t, err)
			parsed := net.ParseIP(ip)
			version := uint8(6)
			// Poison the other family to expose accidental IPv4 decoding.
			require.NoError(t, fields["endpoint.addr_raw.v4"].PutUint32(data, 0xdeadbeef))
			require.NoError(t, fields["endpoint.addr_raw.v6"].PutBytes(data, parsed.To16()))
			if v4 := parsed.To4(); v4 != nil {
				version = 4
				require.NoError(t, fields["endpoint.addr_raw.v4"].PutUint32(data, binary.LittleEndian.Uint32(v4)))
			}
			require.NoError(t, fields["endpoint.version"].PutUint8(data, version))
			require.NoError(t, fields["endpoint.port"].PutUint16(data, 10250))
			require.NoError(t, fields["endpoint.proto_raw"].PutUint16(data, 6))
			ev := &DatasourceEvent{Datasource: ds, Data: data, EventType: NetworkEventType}
			endpoint := ev.GetDstEndpoint()
			require.Equal(t, ip, endpoint.Addr)
			require.Equal(t, version, endpoint.Version)
			require.Equal(t, uint16(10250), endpoint.Port)
			require.Equal(t, uint16(6), endpoint.Proto)
			wrapped, _ := xcel.NewObject[CelEvent](ev)
			addr, err := CelFields["dstAddr"].GetFrom(wrapped)
			require.NoError(t, err)
			require.Equal(t, celtypes.String(ip), addr)
		})
	}
}
