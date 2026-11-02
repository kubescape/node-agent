package cel

import (
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/require"
)

// newDatasourceFileExecEvent builds a synthetic "exec" datasource with comm and
// exepath and, when withFile is set, the "file" field trace_exec v0.57 emits.
func newDatasourceFileExecEvent(t *testing.T, exepath, file string, withFile bool) *utils.DatasourceEvent {
	t.Helper()

	ds, err := datasource.New(datasource.TypeSingle, "exec")
	require.NoError(t, err)

	commAcc, err := ds.AddField("comm", api.Kind_String)
	require.NoError(t, err)
	exeAcc, err := ds.AddField("exepath", api.Kind_String)
	require.NoError(t, err)
	var fileAcc datasource.FieldAccessor
	if withFile {
		fileAcc, err = ds.AddField("file", api.Kind_String)
		require.NoError(t, err)
	}

	data, err := ds.NewPacketSingle()
	require.NoError(t, err)
	t.Cleanup(func() { ds.Release(data) })

	require.NoError(t, commAcc.PutString(data, "sh"))
	require.NoError(t, exeAcc.PutString(data, exepath))
	if withFile {
		require.NoError(t, fileAcc.PutString(data, file))
	}

	return &utils.DatasourceEvent{
		Data:       data,
		Datasource: ds,
		EventType:  utils.ExecveEventType,
	}
}

// TestCELExecFile covers event.file: for a shebang exec it is the script while
// event.exepath is the interpreter, so rules can match the executed file.
func TestCELExecFile(t *testing.T) {
	shebang := &utils.StructEvent{
		EventType: utils.ExecveEventType,
		Comm:      "x.pid",
		Args:      []string{"/bin/sh", "/run/x.pid"},
		ExePath:   "/usr/bin/dash",
		File:      "/run/x.pid",
	}
	require.True(t, evalTTY(t, shebang, `has(event.file) && event.file == "/run/x.pid"`))
	require.True(t, evalTTY(t, shebang, `event.exepath == "/usr/bin/dash"`))

	noFile := &utils.StructEvent{EventType: utils.ExecveEventType, Comm: "ls", ExePath: "/usr/bin/ls"}
	require.False(t, evalTTY(t, noFile, `has(event.file)`))
	require.True(t, evalTTY(t, noFile,
		`(event.file != "" ? event.file : event.exepath) == "/usr/bin/ls"`),
		"the documented fallback picks exepath when file is empty")

	ds := newDatasourceFileExecEvent(t, "/usr/bin/dash", "/run/x.pid", true)
	require.True(t, evalTTYEvent(t, ds, utils.ExecveEventType,
		`has(event.file) && event.file == "/run/x.pid" && event.exepath == "/usr/bin/dash"`))

	// A gadget that does not emit file (pre-v0.57): has() is false and the
	// expression still compiles, so a guarded rule is not silently disabled.
	old := newDatasourceFileExecEvent(t, "/usr/bin/dash", "", false)
	require.False(t, evalTTYEvent(t, old, utils.ExecveEventType, `has(event.file)`))
	require.True(t, evalTTYEvent(t, old, utils.ExecveEventType,
		`(has(event.file) && event.file != "" ? event.file : event.exepath) == "/usr/bin/dash"`))
}
