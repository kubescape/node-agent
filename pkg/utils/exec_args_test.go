package utils

import (
	"strings"
	"testing"

	igconsts "github.com/inspektor-gadget/inspektor-gadget/gadgets/trace_exec/consts"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/stretchr/testify/assert"
)

const nbsp = "\u00a0"

// TestExecArgsRoundTrip checks that argv keeps its argument boundaries and
// contents through the single-string "args" field, including arguments that
// contain the U+00A0 separator or the backslash escape character.
func TestExecArgsRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"plain argv", []string{"ls", "-la", "/tmp"}},
		{"argument with spaces", []string{"sh", "-c", "echo hello world"}},
		{"argument with the separator", []string{"sh", "-c", "a" + nbsp + "b"}},
		{"argument that is only the separator", []string{"echo", nbsp}},
		{"separators at the edges", []string{nbsp + "x" + nbsp}},
		{"argument with a backslash", []string{"printf", `a\nb`}},
		{"argument ending in a backslash", []string{"echo", `x\`, "y"}},
		{"literal escape sequence text", []string{"echo", `\u00a0`, `\\`, `\\u00a0`}},
		{"backslash next to the separator", []string{`\` + nbsp + `\`}},
		{"empty arguments", []string{"cmd", "", ""}},
		{"single argument", []string{"/bin/true"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.args, SplitExecArgs(JoinExecArgs(tt.args)))
		})
	}
}

// TestExecArgsSeparatorCannotForgeArgv is the SUB-9501 case: one argument
// that contains U+00A0 must not reach rules as the argv it spells out.
func TestExecArgsSeparatorCannotForgeArgv(t *testing.T) {
	forged := []string{"sh", "-c", "rm -f /var/cache/apt/archives/*.deb"}
	real := []string{"dash", forged[0] + nbsp + forged[1] + nbsp + forged[2]}

	got := SplitExecArgs(JoinExecArgs(real))
	assert.Equal(t, real, got)
	assert.Len(t, got, 2)
	assert.NotEqual(t, forged, got[1:])
}

func TestExecArgsEncoding(t *testing.T) {
	// Arguments without a backslash or U+00A0 are joined unchanged.
	for _, plain := range [][]string{
		{"ls", "-la"},
		{"/bin/sh", "-c", "echo hello world"},
		{"cmd", "", ""},
		{"x"},
	} {
		assert.Equal(t, strings.Join(plain, igconsts.ArgsSeparator), JoinExecArgs(plain))
	}
	// Plain arguments around an escaped one keep their place.
	assert.Equal(t, []string{"a", "b" + nbsp + "c", "d", `e\f`, "g"},
		SplitExecArgs(JoinExecArgs([]string{"a", "b" + nbsp + "c", "d", `e\f`, "g"})))
	assert.Equal(t, `a\u00a0b`, JoinExecArgs([]string{"a" + nbsp + "b"}))
	assert.Equal(t, `a\\b`, JoinExecArgs([]string{`a\b`}))
	// No argv and an empty string both mean "argv unknown".
	assert.Equal(t, "", JoinExecArgs(nil))
	assert.Nil(t, SplitExecArgs(""))
}

// TestDatasourceEventGetArgsKeepsSeparator checks the path rules use:
// DatasourceEvent.GetArgs() (CEL event.args) on a field built by JoinExecArgs.
func TestDatasourceEventGetArgsKeepsSeparator(t *testing.T) {
	clear := func() {
		fieldCaches.Range(func(key, _ any) bool {
			fieldCaches.Delete(key)
			return true
		})
	}
	clear()
	t.Cleanup(clear)

	argv := []string{"/bin/dash", "-c", "x" + nbsp + "y", `C:\path`}
	e := &DatasourceEvent{
		EventType: ExecveEventType,
		Datasource: &mockDataSource{fields: map[string]datasource.FieldAccessor{
			"args": &mockStringFieldAccessor{val: JoinExecArgs(argv)},
		}},
	}
	assert.Equal(t, argv, e.GetArgs())
}
