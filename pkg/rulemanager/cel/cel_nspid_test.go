package cel

import (
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ownProcExpr is the shape the R0008/R1034 rules use to tell an open of the
// process's own /proc/<pid>/... from another process's.
const ownProcExpr = `event.nsPid > 0u && event.path.startsWith('/proc/' + string(event.nsPid) + '/')`

// newDatasourceOpenEvent builds a synthetic "open" datasource with fname and,
// when nsPid is not nil, the trace_open nspid field.
func newDatasourceOpenEvent(t *testing.T, path string, nsPid *uint32) *utils.DatasourceEvent {
	t.Helper()

	ds, err := datasource.New(datasource.TypeSingle, "open")
	require.NoError(t, err)

	fnameAcc, err := ds.AddField("fname", api.Kind_String)
	require.NoError(t, err)

	var nsPidAcc datasource.FieldAccessor
	if nsPid != nil {
		nsPidAcc, err = ds.AddField("nspid", api.Kind_Uint32)
		require.NoError(t, err)
	}

	data, err := ds.NewPacketSingle()
	require.NoError(t, err)
	t.Cleanup(func() { ds.Release(data) })

	require.NoError(t, fnameAcc.PutString(data, path))
	if nsPid != nil {
		require.NoError(t, nsPidAcc.PutUint32(data, *nsPid))
	}

	return &utils.DatasourceEvent{Datasource: ds, Data: data, EventType: utils.OpenEventType}
}

func TestCELNsPid(t *testing.T) {
	u32 := func(v uint32) *uint32 { return &v }

	tests := []struct {
		name  string
		path  string
		nsPid *uint32 // nil: the datasource has no nspid field
		own   bool
	}{
		{name: "own environ", path: "/proc/29/environ", nsPid: u32(29), own: true},
		{name: "own mem", path: "/proc/29/mem", nsPid: u32(29), own: true},
		{name: "other process", path: "/proc/1/environ", nsPid: u32(29), own: false},
		{name: "pid prefix is not own", path: "/proc/290/environ", nsPid: u32(29), own: false},
		{name: "unknown is not own", path: "/proc/0/environ", nsPid: u32(0), own: false},
		{name: "missing field is not own", path: "/proc/0/environ", nsPid: nil, own: false},
	}

	for _, tt := range tests {
		t.Run(tt.name+"/struct", func(t *testing.T) {
			e := &utils.StructEvent{EventType: utils.OpenEventType, Path: tt.path}
			if tt.nsPid != nil {
				e.NsPid = *tt.nsPid
			}
			assert.Equal(t, tt.own, evalTTY(t, e, ownProcExpr))
		})
		t.Run(tt.name+"/datasource", func(t *testing.T) {
			e := newDatasourceOpenEvent(t, tt.path, tt.nsPid)
			assert.Equal(t, tt.own, evalTTYEvent(t, e, utils.OpenEventType, ownProcExpr))
		})
	}
}

// TestCELNsPidIsUint guards the field type the rule library relies on: rules
// compare event.nsPid with unsigned literals, as they do event.pid.
func TestCELNsPidIsUint(t *testing.T) {
	c := newTestCEL(t)
	require.NoError(t, c.registerExpression(`event.nsPid == 0u`))
	require.Error(t, c.registerExpression(`event.nsPid > 0`), "an int literal must not compile against a uint field")
}
