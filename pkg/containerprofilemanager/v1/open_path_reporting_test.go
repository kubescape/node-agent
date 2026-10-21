package containerprofilemanager

import (
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestReportFileOpenUnresolvedPath(t *testing.T) {
	// Use the real open accessor: empty failed syscall names remain unresolved,
	// whereas a captured root-directory path must remain a valid learned open.
	ds, err := datasource.New(datasource.TypeSingle, "open")
	require.NoError(t, err)
	fname, err := ds.AddField("fname", api.Kind_String)
	require.NoError(t, err)
	fpath, err := ds.AddField("fpath", api.Kind_String)
	require.NoError(t, err)
	errno, err := ds.AddField("error_raw", api.Kind_Int32)
	require.NoError(t, err)
	flags, err := ds.AddField("flags_raw", api.Kind_Int32)
	require.NoError(t, err)
	for _, name := range []string{"proc.pid", "proc.tid", "fd"} {
		_, err := ds.AddField(name, api.Kind_Uint32)
		require.NoError(t, err)
	}
	dfd, err := ds.AddField("dfd", api.Kind_Int32)
	require.NoError(t, err)

	for _, tc := range []struct {
		name, raw, resolved, wantPath string
		errno                         int32
		partial                       bool
	}{
		{name: "failed empty filename", errno: int32(unix.ENOENT)},
		{name: "successful open with missing path", partial: true},
		{name: "root directory", raw: ".", resolved: "/", wantPath: "/"},
		{name: "ordinary absolute open", raw: "/etc/passwd", resolved: "/etc/passwd", wantPath: "/etc/passwd"},
		{name: "failed named open", raw: "/missing-directory", errno: int32(unix.ENOENT), wantPath: "/missing-directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := ds.NewPacketSingle()
			require.NoError(t, err)
			defer ds.Release(data)
			require.NoError(t, fname.PutString(data, tc.raw))
			require.NoError(t, fpath.PutString(data, tc.resolved))
			require.NoError(t, errno.PutInt32(data, tc.errno))
			require.NoError(t, dfd.PutInt32(data, utils.AT_FDCWD))
			require.NoError(t, flags.PutInt32(data, unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_RDONLY))
			event := &utils.DatasourceEvent{Datasource: ds, Data: data, EventType: utils.OpenEventType, FullPathTracing: true}
			require.Equal(t, tc.wantPath, event.GetPath())
			require.Equal(t, int64(tc.errno), event.GetError(), "open error_raw carries positive errno, not a negative syscall return")

			cpm, entry := newTestManager(t, "container")
			cpm.ReportFileOpen("container", event)
			opens := entry.data.getOpens()
			if tc.wantPath == "" {
				require.Empty(t, opens, "an unresolved name must not become a profile entry that storage cleans to '.'")
				require.Zero(t, entry.data.size.Load())
			} else {
				require.Len(t, opens, 1)
				require.Equal(t, tc.wantPath, opens[0].Path)
				require.ElementsMatch(t, event.GetFlags(), opens[0].Flags)
			}
			require.Equal(t, tc.partial, entry.data.droppedEvents, "only a successful open with lost identity makes capture partial")
			require.Equal(t, tc.wantPath, event.GetPath(), "profile recording must not modify the event used by rule evaluation")
		})
	}
}
