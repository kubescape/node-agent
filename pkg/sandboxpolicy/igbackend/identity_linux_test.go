package igbackend

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

func TestLinuxValidatorRejectsIncompleteAndNonProcIdentity(t *testing.T) {
	_, _, _, b, _ := fixture(t)
	incomplete := b
	incomplete.PID = 0
	if _, err := (LinuxValidator{}).Acquire(context.Background(), incomplete); err == nil {
		t.Fatal("missing PID accepted")
	}
	fakeProc := t.TempDir()
	if err := os.Mkdir(filepath.Join(fakeProc, "123"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := (LinuxValidator{ProcRoot: fakeProc}).Acquire(context.Background(), b); err == nil || !strings.Contains(err.Error(), "procfs") {
		t.Fatalf("non-proc process identity accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (LinuxValidator{}).Acquire(ctx, b); err == nil {
		t.Fatal("canceled acquisition accepted")
	}
}
func TestPinnedProcessStatParsing(t *testing.T) {
	root := t.TempDir()
	dir, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	l := &linuxLease{proc: dir}
	defer l.Close()
	// comm can contain spaces and parentheses; starttime must still be field22.
	fields := append([]string{"S"}, make([]string, 19)...)
	for i := 1; i < len(fields); i++ {
		fields[i] = "0"
	}
	fields[19] = "123456"
	if err := os.WriteFile(filepath.Join(root, "stat"), []byte("10 (strange ) process) "+strings.Join(fields, " ")), 0600); err != nil {
		t.Fatal(err)
	}
	start, err := l.readStart()
	if err != nil || start != "123456" {
		t.Fatal(start, err)
	}
	if err := os.WriteFile(filepath.Join(root, "stat"), []byte("malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := l.readStart(); err == nil {
		t.Fatal("malformed stat accepted")
	}
}

func TestLinuxValidatorRejectsNonCanonicalCgroupBeforeProcAccess(t *testing.T) {
	binding := sandboxpolicy.Binding{
		Runtime: "containerd", ContainerID: strings.Repeat("a", 64), PID: 123,
		CgroupID: 1, MountNamespace: 1, CgroupPath: "/parent/container",
	}
	missing := filepath.Join(t.TempDir(), "missing")
	validator := LinuxValidator{ProcRoot: missing, CgroupRoot: missing}
	// A complete canonical identity gets past the early guard and fails only
	// on the deliberately absent ordinary proc fixture path.
	lease, err := validator.Acquire(context.Background(), binding)
	if lease != nil || !os.IsNotExist(err) {
		t.Fatalf("canonical control: lease=%v err=%v", lease, err)
	}
	for _, tc := range []struct{ name, path string }{
		{"root", "/"},
		{"relative", "parent/container"},
		{"dot", "/parent/./container"},
		{"dotdot", "/parent/child/../container"},
		{"repeated-separator", "/parent//container"},
		{"leading-separator-alias", "//parent/container"},
		{"trailing-separator", "/parent/container/"},
		{"root-dot-alias", "/."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := binding
			candidate.CgroupPath = tc.path
			lease, err := validator.Acquire(context.Background(), candidate)
			if lease != nil || err == nil || err.Error() != "complete non-root live container identity required" {
				t.Fatalf("expected early canonical identity rejection, lease=%v err=%v", lease, err)
			}
		})
	}
}

func TestLinuxLeaseRejectsCgroupMovementBeforeNamespaceAccess(t *testing.T) {
	const start = "123456"
	const expected = "/parent/container"
	for _, tc := range []struct{ name, cgroup, want string }{
		{"moved-child", "0::" + expected + "/child\n", "process cgroup changed"},
		{"moved-sibling", "0::/parent/sibling\n", "process cgroup changed"},
		{"duplicate-unified", "0::" + expected + "\n0::" + expected + "\n", "process cgroup changed"},
		{"missing-unified", "2:cpu:" + expected + "\n3:memory:" + expected + "\n", "missing unified process cgroup"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			fields := append([]string{"S"}, make([]string, 19)...)
			for i := 1; i < len(fields); i++ {
				fields[i] = "0"
			}
			fields[19] = start
			if err := os.WriteFile(filepath.Join(root, "stat"), []byte("123 (fixture process) "+strings.Join(fields, " ")), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "cgroup"), []byte(tc.cgroup), 0600); err != nil {
				t.Fatal(err)
			}
			proc, err := os.Open(root)
			if err != nil {
				t.Fatal(err)
			}
			lease := &linuxLease{proc: proc, identity: sandboxpolicy.Binding{CgroupPath: expected}, start: start}
			t.Cleanup(func() {
				if err := lease.Close(); err != nil {
					t.Error(err)
				}
			})
			if got, err := lease.readStart(); err != nil || got != start {
				t.Fatalf("fixture must pass the earlier starttime check: start=%q err=%v", got, err)
			}
			// Deliberately omit ns/mnt: reaching the later namespace open
			// would return ENOENT, not the exact cgroup rejection required here.
			if _, err := os.Stat(filepath.Join(root, "ns", "mnt")); !os.IsNotExist(err) {
				t.Fatalf("namespace fixture unexpectedly exists: %v", err)
			}
			if err := lease.Check(); err == nil || err.Error() != tc.want {
				t.Fatalf("expected cgroup rejection before namespace access: got %v, want %q", err, tc.want)
			}
		})
	}
}
