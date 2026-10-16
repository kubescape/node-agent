package utils

import (
	"strings"
	"testing"

	celtypes "github.com/google/cel-go/common/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/picatz/xcel"
	"github.com/stretchr/testify/require"
)

func TestNetworkExePath(t *testing.T) {
	for _, tc := range []struct {
		name    string
		path    string
		present bool
	}{
		{"system binary", "/usr/bin/curl", true},
		{"renamed binary", "/tmp/renamed-client", true},
		{"unattributed socket", "", true},
		{"truncated path", "/" + strings.Repeat("a", 254), true},
		{"legacy schema", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cached, existed := fieldCaches.LoadAndDelete(NetworkEventType)
			t.Cleanup(func() {
				fieldCaches.Delete(NetworkEventType)
				if existed {
					fieldCaches.Store(NetworkEventType, cached)
				}
			})
			ds, err := datasource.New(datasource.TypeSingle, "network")
			require.NoError(t, err)
			var field datasource.FieldAccessor
			if tc.present {
				field, err = ds.AddField("exepath", api.Kind_CString)
				require.NoError(t, err)
			}
			data, err := ds.NewPacketSingle()
			require.NoError(t, err)
			if tc.present {
				// Real char[N] events can retain bytes after the first NUL.
				require.NoError(t, field.Set(data, []byte(tc.path+"\x00stale-previous-path")))
			}
			var event NetworkEvent = &DatasourceEvent{Datasource: ds, Data: data, EventType: NetworkEventType}
			require.Equal(t, tc.path, event.GetExePath())
			wrapped, _ := xcel.NewObject[CelEvent](event.(*DatasourceEvent))
			got, err := CelFields["exepath"].GetFrom(wrapped)
			require.NoError(t, err)
			require.Equal(t, celtypes.String(tc.path), got)
		})
	}
}
