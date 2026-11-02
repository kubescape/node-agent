package utils

import (
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/consts"
	"github.com/stretchr/testify/assert"
)

func TestStructEventGetDirection(t *testing.T) {
	tests := []struct {
		name      string
		event     *StructEvent
		expectDir consts.NetworkDirection
	}{
		{
			name:      "HTTP event with explicit direction Inbound",
			event:     &StructEvent{EventType: HTTPEventType, Direction: consts.Inbound},
			expectDir: consts.Inbound,
		},
		{
			name:      "HTTP event with explicit direction Outbound",
			event:     &StructEvent{EventType: HTTPEventType, Direction: consts.Outbound},
			expectDir: consts.Outbound,
		},
		{
			name:      "Network event with no Direction set and OUTGOING packet type maps to Outbound",
			event:     &StructEvent{EventType: NetworkEventType, PktType: "OUTGOING"},
			expectDir: consts.Outbound,
		},
		{
			name:      "Network event with no Direction set and HOST packet type maps to Inbound",
			event:     &StructEvent{EventType: NetworkEventType, PktType: "HOST"},
			expectDir: consts.Inbound,
		},
		{
			name:      "Network event with explicit Inbound direction ignores packet type",
			event:     &StructEvent{EventType: NetworkEventType, Direction: consts.Inbound, PktType: "OUTGOING"},
			expectDir: consts.Inbound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectDir, tt.event.GetDirection())
		})
	}
}

type mockFieldAccessor struct {
	datasource.FieldAccessor
	val uint8
}

func (m *mockFieldAccessor) Uint8(data datasource.Data) (uint8, error) {
	return m.val, nil
}

type mockDataSource struct {
	datasource.DataSource
	fields map[string]datasource.FieldAccessor
}

func (m *mockDataSource) GetField(name string) datasource.FieldAccessor {
	return m.fields[name]
}

func TestDatasourceEventGetDirection(t *testing.T) {
	// Create mock datasource that has a field "egress" returning a mockFieldAccessor
	dsOutgoing := &mockDataSource{
		fields: map[string]datasource.FieldAccessor{
			"egress": &mockFieldAccessor{val: 1},
		},
	}
	dsHost := &mockDataSource{
		fields: map[string]datasource.FieldAccessor{
			"egress": &mockFieldAccessor{val: 0},
		},
	}

	tests := []struct {
		name      string
		event     *DatasourceEvent
		expectDir consts.NetworkDirection
	}{
		{
			name: "Network event with egress=1 maps to Outbound",
			event: &DatasourceEvent{
				EventType:  NetworkEventType,
				Datasource: dsOutgoing,
			},
			expectDir: consts.Outbound,
		},
		{
			name: "Network event with egress=0 maps to Inbound",
			event: &DatasourceEvent{
				EventType:  NetworkEventType,
				Datasource: dsHost,
			},
			expectDir: consts.Inbound,
		},
		{
			name: "Non-network event doesn't map egress to outbound",
			event: &DatasourceEvent{
				EventType:  HTTPEventType,
				Datasource: dsOutgoing,
			},
			expectDir: "",
		},
		{
			name: "HTTP event with explicit direction Inbound",
			event: &DatasourceEvent{
				EventType: HTTPEventType,
				Direction: consts.Inbound,
			},
			expectDir: consts.Inbound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear package-level fieldCaches maps so we don't bleed cache between tests
			fieldCaches.Range(func(key, val any) bool {
				fieldCaches.Delete(key)
				return true
			})
			assert.Equal(t, tt.expectDir, tt.event.GetDirection())
		})
	}
}

// TestGetExecPathFromEvent covers the exec path order: file, then exepath,
// then comm. argv[0] is never used.
func TestGetExecPathFromEvent(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		file    string
		exepath string
		comm    string
		want    string
	}{
		{"plain exec", []string{"/bin/ls"}, "/usr/bin/ls", "/usr/bin/ls", "", "/usr/bin/ls"},
		{"symlink", []string{"/bin/sh"}, "/usr/bin/dash", "/usr/bin/dash", "", "/usr/bin/dash"},
		{"exec -a fake", []string{"fake", "1"}, "/usr/bin/sleep", "/usr/bin/sleep", "", "/usr/bin/sleep"},
		{"glibc system() on Debian", []string{"sh", "-c", "--", ":"}, "/usr/bin/dash", "/usr/bin/dash", "", "/usr/bin/dash"},
		{"busybox system() on Alpine", []string{"sh", "-c", "--", ":"}, "/bin/busybox", "/bin/busybox", "", "/bin/busybox"},
		{"relative", []string{"./x"}, "/app/x", "/app/x", "", "/app/x"},
		{"spoofed argv[0]", []string{"/bin/true"}, "/tmp/evil", "/tmp/evil", "", "/tmp/evil"},
		{"shebang", []string{"/bin/sh", "/app/run.sh"}, "/app/run.sh", "/usr/bin/dash", "", "/app/run.sh"},
		{"empty args", nil, "/usr/bin/dash", "/usr/bin/dash", "", "/usr/bin/dash"},
		{"empty file", nil, "", "/usr/bin/dash", "", "/usr/bin/dash"},
		{"all empty", nil, "", "", "comm", "comm"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &StructEvent{EventType: ExecveEventType, Args: tt.args, File: tt.file, ExePath: tt.exepath, Comm: tt.comm}
			assert.Equal(t, tt.want, GetExecPathFromEvent(e))
		})
	}
}

// TestGetExecArgsFromEvent checks that an uncaptured argv (nil) stays distinct
// from a shell run with no arguments (["sh"]).
func TestGetExecArgsFromEvent(t *testing.T) {
	assert.Nil(t, (&StructEvent{}).GetArgs())
	assert.Equal(t, []string{"sh"}, (&StructEvent{Args: []string{"sh"}}).GetArgs())
	assert.Empty(t, GetExecArgsFromEvent(&StructEvent{}))
	assert.Empty(t, GetExecArgsFromEvent(&StructEvent{Args: []string{"sh"}}))
	assert.Equal(t, []string{"-c", "--", ":"}, GetExecArgsFromEvent(&StructEvent{Args: []string{"sh", "-c", "--", ":"}}))
}

func TestGetHostFilePathsFromEvent(t *testing.T) {
	const containerPid = 42
	tests := []struct {
		name    string
		file    string
		exepath string
		pid     uint32
		want    []string
	}{
		{"plain exec", "/usr/bin/ls", "/usr/bin/ls", 7, []string{"/proc/42/root/usr/bin/ls"}},
		{"memfd", "/memfd:x (deleted)", "/memfd:x (deleted)", 7, []string{"/proc/7/exe"}},
		{"memfd without the deleted suffix", "/memfd:x", "/memfd:x", 7, []string{"/proc/7/exe"}},
		{"deleted file", "/tmp/evil (deleted)", "/tmp/evil (deleted)", 7, []string{"/proc/7/exe"}},
		{"empty file", "", "/usr/bin/dash", 7, []string{"/proc/7/exe"}},
		{"empty file, pid unknown", "", "/usr/bin/dash", 0, nil},
		{"memfd, pid unknown", "/memfd:x (deleted)", "/memfd:x (deleted)", 0, nil},
		{"binfmt_misc", "/app/arm-bin", "/usr/bin/qemu-aarch64-static", 7, []string{"/proc/42/root/app/arm-bin", "/proc/42/root/usr/bin/qemu-aarch64-static"}},
		{"shebang", "/app/run.sh", "/usr/bin/dash", 7, []string{"/proc/42/root/app/run.sh", "/proc/42/root/usr/bin/dash"}},
		{"shebang with deleted interpreter", "/app/run.sh", "/usr/bin/dash (deleted)", 7, []string{"/proc/42/root/app/run.sh", "/proc/7/exe"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &StructEvent{EventType: ExecveEventType, File: tt.file, ExePath: tt.exepath, Pid: tt.pid}
			got, err := GetHostFilePathsFromEvent(e, containerPid)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)

			first, err := GetHostFilePathFromEvent(e, containerPid)
			if len(tt.want) == 0 {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want[0], first)
			}
		})
	}

	t.Run("open event keeps its full path", func(t *testing.T) {
		e := &StructEvent{EventType: OpenEventType, FullPath: "/etc/passwd"}
		got, err := GetHostFilePathsFromEvent(e, containerPid)
		assert.NoError(t, err)
		assert.Equal(t, []string{"/proc/42/root/etc/passwd"}, got)
		first, err := GetHostFilePathFromEvent(e, containerPid)
		assert.NoError(t, err)
		assert.Equal(t, "/proc/42/root/etc/passwd", first)
	})

	t.Run("other event types error", func(t *testing.T) {
		_, err := GetHostFilePathsFromEvent(&StructEvent{EventType: DnsEventType}, containerPid)
		assert.Error(t, err)
	})
}

type mockStringFieldAccessor struct {
	datasource.FieldAccessor
	val string
}

func (m *mockStringFieldAccessor) String(datasource.Data) (string, error) {
	return m.val, nil
}

// TestDatasourceEventExecFields checks that an empty args field (argv not
// captured) yields nil args, and that file is normalized like exepath.
func TestDatasourceEventExecFields(t *testing.T) {
	fieldCaches.Range(func(key, val any) bool {
		fieldCaches.Delete(key)
		return true
	})
	t.Cleanup(func() {
		fieldCaches.Range(func(key, val any) bool {
			fieldCaches.Delete(key)
			return true
		})
	})
	e := &DatasourceEvent{
		EventType: ExecveEventType,
		Datasource: &mockDataSource{fields: map[string]datasource.FieldAccessor{
			"args":    &mockStringFieldAccessor{val: ""},
			"file":    &mockStringFieldAccessor{val: "/app/../app/run.sh"},
			"exepath": &mockStringFieldAccessor{val: "/usr/bin/dash"},
		}},
	}
	assert.Nil(t, e.GetArgs())
	assert.Equal(t, "/app/run.sh", e.GetFile())
	assert.Equal(t, "/app/run.sh", GetExecPathFromEvent(e))
}
