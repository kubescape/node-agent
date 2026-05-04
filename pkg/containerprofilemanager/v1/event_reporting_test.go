package containerprofilemanager

import "testing"

func TestResolveExecPath(t *testing.T) {
	tests := []struct {
		name    string
		exepath string
		comm    string
		args    []string
		want    string
	}{
		{
			name:    "exepath present (canonical exec)",
			exepath: "/usr/sbin/unix_chkpwd",
			comm:    "unix_chkpwd",
			args:    []string{"/usr/sbin/unix_chkpwd", "root"},
			want:    "/usr/sbin/unix_chkpwd",
		},
		{
			name:    "fexecve / execveat AT_EMPTY_PATH — pathname empty, argv[0] non-empty",
			exepath: "",
			comm:    "unix_chkpwd",
			args:    []string{"unix_chkpwd", "root"},
			want:    "unix_chkpwd",
		},
		{
			name:    "fexecve with empty argv[0] (older PAM convention)",
			exepath: "",
			comm:    "unix_chkpwd",
			args:    []string{"", "root"},
			want:    "unix_chkpwd",
		},
		{
			name:    "no exepath, no args — fall back to comm",
			exepath: "",
			comm:    "some_proc",
			args:    nil,
			want:    "some_proc",
		},
		{
			name:    "exepath wins even when argv[0] disagrees (argv[0] spoofing)",
			exepath: "/usr/bin/curl",
			comm:    "curl",
			args:    []string{"sshd", "-i"},
			want:    "/usr/bin/curl",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveExecPath(tt.exepath, tt.comm, tt.args)
			if got != tt.want {
				t.Errorf("resolveExecPath(%q, %q, %v) = %q, want %q", tt.exepath, tt.comm, tt.args, got, tt.want)
			}
		})
	}
}
