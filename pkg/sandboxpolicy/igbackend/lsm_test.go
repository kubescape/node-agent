package igbackend

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

func TestCheckBPFLSM(t *testing.T) {
	write := func(list string) string {
		root := t.TempDir()
		dir := filepath.Join(root, "sys/kernel/security")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "lsm"), []byte(list), 0o644); err != nil {
			t.Fatal(err)
		}
		return root
	}
	if err := CheckBPFLSM(write("lockdown,capability,landlock,yama,apparmor,bpf\n")); err != nil {
		t.Fatalf("bpf active: %v", err)
	}
	for name, root := range map[string]string{
		"no bpf":        write("lockdown,capability,landlock,yama,apparmor\n"),
		"bpf-like":      write("lockdown,capability,bpfx\n"),
		"no securityfs": t.TempDir(),
	} {
		var u *sandboxpolicy.EnforcementUnavailableError
		if err := CheckBPFLSM(root); !errors.As(err, &u) || u.Reason != "BPFLSMInactive" {
			t.Errorf("%s: %v", name, err)
		}
	}
}
