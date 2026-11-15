package adapters

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecAdapter_CommandLineAndFile(t *testing.T) {
	tests := []struct {
		name        string
		event       *utils.StructEvent
		wantExec    string
		wantCmdline string
		wantFileDir string
		wantFile    string
	}{
		{
			name:        "glibc system() keeps the real argv",
			event:       &utils.StructEvent{Args: []string{"sh", "-c", "--", ":"}, File: "/usr/bin/dash", ExePath: "/usr/bin/dash"},
			wantExec:    "/usr/bin/dash",
			wantCmdline: "sh -c -- :",
			wantFileDir: "/usr/bin",
			wantFile:    "dash",
		},
		{
			name:        "busybox applet name is kept",
			event:       &utils.StructEvent{Args: []string{"ls", "-la"}, File: "/bin/busybox", ExePath: "/bin/busybox"},
			wantExec:    "/bin/busybox",
			wantCmdline: "ls -la",
			wantFileDir: "/bin",
			wantFile:    "busybox",
		},
		{
			name:        "shebang: exec is the script, file entity is the interpreter",
			event:       &utils.StructEvent{Args: []string{"/bin/sh", "/app/run.sh"}, File: "/app/run.sh", ExePath: "/usr/bin/dash"},
			wantExec:    "/app/run.sh",
			wantCmdline: "/bin/sh /app/run.sh",
			wantFileDir: "/usr/bin",
			wantFile:    "dash",
		},
		{
			name:        "argv not captured falls back to the path",
			event:       &utils.StructEvent{File: "/usr/bin/dash", ExePath: "/usr/bin/dash"},
			wantExec:    "/usr/bin/dash",
			wantCmdline: "/usr/bin/dash",
			wantFileDir: "/usr/bin",
			wantFile:    "dash",
		},
		{
			name:        "no exepath: file entity uses the exec path",
			event:       &utils.StructEvent{Args: []string{"x"}, File: "/app/x"},
			wantExec:    "/app/x",
			wantCmdline: "x",
			wantFileDir: "/app",
			wantFile:    "x",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.event.EventType = utils.ExecveEventType
			failure := &types.GenericRuleFailure{}
			NewExecAdapter().SetFailureMetadata(failure, &events.EnrichedEvent{Event: tt.event}, nil)

			alert := failure.GetBaseRuntimeAlert()
			assert.Equal(t, tt.wantExec, alert.Arguments["exec"])
			require.NotNil(t, alert.Identifiers)
			assert.Equal(t, tt.wantCmdline, alert.Identifiers.Process.CommandLine)
			assert.Equal(t, tt.wantFile, alert.Identifiers.File.Name)
			assert.Equal(t, tt.wantFileDir, alert.Identifiers.File.Directory)
			assert.Equal(t, tt.wantCmdline, failure.GetRuntimeProcessDetails().ProcessTree.Cmdline)
		})
	}
}
