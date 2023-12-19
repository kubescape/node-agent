package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProcessDetails_GetArg(t *testing.T) {
	tests := []struct {
		name    string
		arg     string
		wantVal string
		p       ProcessDetails
		wantOK  bool
	}{
		{
			name: "exist with =",
			p: ProcessDetails{
				CmdLine: []string{"--foo=bar"},
			},
			arg:     "--foo",
			wantVal: "bar",
			wantOK:  true,
		},
		{
			name: "exist sapereted",
			p: ProcessDetails{
				CmdLine: []string{"--foo", "bar"},
			},
			arg:     "--foo",
			wantVal: "bar",
			wantOK:  true,
		},
		{
			name: "exist no value",
			p: ProcessDetails{
				CmdLine: []string{"--foo"},
			},
			arg:     "--foo",
			wantVal: "",
			wantOK:  true,
		},
		{
			name: "not exist",
			p: ProcessDetails{
				CmdLine: []string{"--bar"},
			},
			arg:     "--foo",
			wantVal: "",
			wantOK:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, ok := tt.p.GetArg(tt.arg)
			if val != tt.wantVal {
				t.Errorf("ProcessDetails.GetArg() val = %v, want %v", val, tt.wantVal)
			}
			if ok != tt.wantOK {
				t.Errorf("ProcessDetails.GetArg() ok = %v, want %v", ok, tt.wantOK)
			}
		})
	}
}

func TestProcessDetailsRawCmd(t *testing.T) {
	p := ProcessDetails{CmdLine: []string{"/foo/bar baz", "--flag", "value", "-f", "-d", "--flag=value"}}
	assert.Equal(t, p.RawCmd(), "/foo/bar baz --flag value -f -d --flag=value")
}

func TestProcessDetailsContainerdPath(t *testing.T) {
	p := ProcessDetails{PID: 1}
	assert.Equal(t, p.ContaineredPath("/foo/bar"), "/proc/1/root/foo/bar")
	assert.Equal(t, p.ContaineredPath("foo/bar"), "/proc/1/root/foo/bar")
}
