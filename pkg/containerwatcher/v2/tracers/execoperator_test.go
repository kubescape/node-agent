package tracers

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestDecodeExecArgs(t *testing.T) {
	join := func(args ...string) []byte {
		var b bytes.Buffer
		for _, a := range args {
			b.WriteString(a)
			b.WriteByte(0)
		}
		return b.Bytes()
	}

	t.Run("system() argv", func(t *testing.T) {
		p := join("sh", "-c", "--", ":")
		assert.Equal(t, []string{"sh", "-c", "--", ":"}, decodeExecArgs(p, uint32(len(p)), 4))
	})

	t.Run("empty payload yields no args instead of an error", func(t *testing.T) {
		assert.Empty(t, decodeExecArgs(nil, 0, 0))
		assert.Empty(t, decodeExecArgs([]byte{}, 16, 3))
	})

	t.Run("size larger than the payload is clamped", func(t *testing.T) {
		p := join("ls", "-la")
		assert.Equal(t, []string{"ls", "-la"}, decodeExecArgs(p, 1<<20, 2))
	})

	t.Run("partial last argument at the 5120-byte limit is dropped", func(t *testing.T) {
		const limit = 5120
		first := strings.Repeat("a", 100)
		p := append(join("echo", first), []byte(strings.Repeat("b", limit))...)
		p = p[:limit]
		assert.Equal(t, []string{"echo", first}, decodeExecArgs(p, limit, 3))
	})

	// IG v0.57 re-reads mm->arg_start..arg_end after a successful exec and sets
	// args_count to the byte count (an upper bound), not the argument count.
	// Argv may exceed the legacy 20-argument / 255-byte-per-argument caps.
	t.Run("v0.57 post-exec block with args_count == args_size", func(t *testing.T) {
		want := []string{"/bin/sh", "/tmp/script.sh", strings.Repeat("x", 300)}
		for i := 0; i < 30; i++ {
			want = append(want, "-v")
		}
		p := join(want...)
		assert.Equal(t, want, decodeExecArgs(p, uint32(len(p)), int32(len(p))))
	})
}

// TestExecCallbackFiltersFailedExecs checks that failed execs (non-zero error)
// are not forwarded, and that an exec with nil args is.
func TestExecCallbackFiltersFailedExecs(t *testing.T) {
	var got []utils.K8sEvent
	et := &ExecTracer{eventCallback: func(e utils.K8sEvent, _ string, _ uint32) { got = append(got, e) }}

	et.callback(&utils.StructEvent{EventType: utils.ExecveEventType, Comm: "sh", Error: 2})
	assert.Empty(t, got, "a failed exec (ENOENT) must be filtered")

	ok := &utils.StructEvent{EventType: utils.ExecveEventType, Comm: "sh", File: "/usr/bin/dash"}
	et.callback(ok)
	assert.Equal(t, []utils.K8sEvent{ok}, got, "an exec with uncaptured argv is kept")
	assert.Nil(t, ok.GetArgs())
}
