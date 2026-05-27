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
		{
			// Busybox symlink: kernel resolves /bin/sh → /bin/busybox and
			// reports exepath=/bin/busybox. The recorded identity is the
			// kernel-resolved exepath, not the user-controllable argv[0]
			// symlink form. User-authored profiles for busybox images
			// must therefore list /bin/busybox. Trusting absolute argv[0]
			// here would re-open the argv[0] spoofing hole pinned by the
			// "absolute argv[0] spoof" case below.
			name:    "busybox symlink — exepath /bin/busybox wins over argv[0]=/bin/sh",
			exepath: "/bin/busybox",
			comm:    "sh",
			args:    []string{"/bin/sh", "-c", "echo hi"},
			want:    "/bin/busybox",
		},
		{
			name:    "busybox symlink — exepath /bin/busybox wins over argv[0]=/usr/bin/nslookup",
			exepath: "/bin/busybox",
			comm:    "nslookup",
			args:    []string{"/usr/bin/nslookup", "example.com"},
			want:    "/bin/busybox",
		},
		{
			// `exec -a /bin/sh sleep 2` — attacker spoofs argv[0] to an
			// allowed absolute path while running a different binary.
			// The recorder MUST anchor on kernel-authoritative exepath
			// so the recorded identity reflects the real executable,
			// not the spoofed argv[0]. Regression pin for the parse.go
			// matthyx blocker on PR #805 (2026-05-27).
			name:    "absolute argv[0] spoof — exec -a /bin/sh sleep",
			exepath: "/usr/bin/sleep",
			comm:    "sleep",
			args:    []string{"/bin/sh", "2"},
			want:    "/usr/bin/sleep",
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
