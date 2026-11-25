//go:build linux

package igbackend

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	fileruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/runtime"
	netruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/runtime"
	privruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/runtime"
)

// Every hook of the three sections has a trigger, except the three that
// load kernel code (documented as not proven at start). A new hook in a
// gadget fails here until it gets a trigger or a documented exception.
func TestCanaryTriggersCoverSectionHooks(t *testing.T) {
	exempt := map[string]bool{"kernel_read_file": true, "kernel_load_data": true, "kernel_module_request": true}
	for section, programs := range map[string]map[string]string{
		"privilege": privruntime.Programs, "network": netruntime.Programs, "file": fileruntime.Programs,
	} {
		for program, hook := range programs {
			if exempt[hook] {
				if canaryTriggered(hook) {
					t.Errorf("%s: %s has a trigger but is exempt", section, hook)
				}
				continue
			}
			if !canaryTriggered(hook) {
				t.Errorf("%s: program %s, hook %s has no canary trigger", section, program, hook)
			}
		}
	}
	for _, hook := range []string{"kernel_read_file", "kernel_load_data", "kernel_module_request"} {
		if canaryUnprovable(hook) == "" {
			t.Errorf("%s is not reported as not proven", hook)
		}
	}
}

// The base ACL is the xattr form (version 2) of USER_OBJ rw-, GROUP_OBJ
// ---, OTHER ---, each with the undefined id.
func TestCanaryBaseACL(t *testing.T) {
	want := []byte{2, 0, 0, 0,
		0x01, 0, 6, 0, 0xff, 0xff, 0xff, 0xff,
		0x04, 0, 0, 0, 0xff, 0xff, 0xff, 0xff,
		0x20, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}
	if got := canaryBaseACL(); !bytes.Equal(got, want) {
		t.Fatalf("ACL %x, want %x", got, want)
	}
}

// The child writes a refused call's hooks, and canaryResults reads them back.
// EPERM, EACCES, ENOSYS and ENOSPC can stop a call before its hook, and so can
// a fixture the call needs; any other result reached the hook.
func TestCanaryChildResults(t *testing.T) {
	saved := canaryTriggers
	t.Cleanup(func() { canaryTriggers = saved })
	canaryTriggers = []canaryTrigger{
		{[]string{"a"}, func(string) error { return unix.EPERM }},
		{[]string{"b"}, func(string) error { return unix.ENOENT }},
		{[]string{"c"}, func(string) error { return unix.ENOSYS }},
		{[]string{"c"}, func(string) error { return nil }}, // a second call reached it
		// The quota check comes before userns_create's hook; a full disk
		// fails mkdir after path_mkdir.
		{[]string{"userns_create"}, func(string) error { return unix.ENOSPC }},
		{[]string{"path_mkdir"}, func(string) error { return unix.ENOSPC }},
		{[]string{"path_rename"}, func(string) error { return canaryFixtureError{unix.EDQUOT} }},
		{[]string{"path_unlink"}, func(d string) error { return canaryFixture(filepath.Join(d, "no", "such", "dir")) }},
	}
	dir := t.TempDir()
	if rc := runCanaryChild([]string{"a", "b", "c", "userns_create", "path_mkdir", "path_rename", "path_unlink"}, dir); rc != 0 {
		t.Fatalf("rc %d", rc)
	}
	got := canaryResults(dir)
	want := map[string]string{"a": "EPERM", "userns_create": "ENOSPC", "path_rename": "fixture-EDQUOT", "path_unlink": "fixture-ENOENT"}
	if len(got) != len(want) {
		t.Fatalf("results %v, want %v", got, want)
	}
	for h, e := range want {
		if got[h] != e {
			t.Fatalf("results %v, want %v", got, want)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("the work directory was left: %v", entries)
	}
}

// cred_alloc_blank's call gets EPERM after its hook on a working node, but
// seccomp or an LSM at the keyring lookup can return it before: it counts
// as a refusal (a silent hook is not proven, a rising run count proves it).
func TestCanaryRefusalCredAllocBlank(t *testing.T) {
	if why := canaryRefusal("cred_alloc_blank", unix.EPERM); why != "EPERM" {
		t.Fatalf("EPERM: %q", why)
	}
}

// The io_uring setup reaches the anonymous inode hook on its own: a refused
// personality registration is not charged to that hook.
func TestCanaryUringTriggersSplit(t *testing.T) {
	n := 0 // the userfaultfd trigger and the ring setup trigger
	for _, tr := range canaryTriggers {
		for _, h := range tr.hooks {
			if h == "uring_override_creds" && len(tr.hooks) != 1 {
				t.Fatalf("the personality trigger also lists %v", tr.hooks)
			}
		}
		if len(tr.hooks) == 1 && tr.hooks[0] == "inode_init_security_anon" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("want two inode_init_security_anon triggers (userfaultfd, ring setup), got %d", n)
	}
}

// io_uring: a failure before the no-op is submitted says nothing about the
// hook (not proven); the no-op's completion result is the call's result, so
// an LSM that refuses it before the BPF program (EACCES) is a refusal, and a
// successful completion leaves the run count to decide.
func TestCanaryUringOutcome(t *testing.T) {
	if why := canaryRefusal("uring_override_creds", canaryFixtureError{unix.ENOMEM}); why != "fixture-ENOMEM" {
		t.Fatalf("a mapping failure before the submit: %q", why)
	}
	if why := canaryRefusal("uring_override_creds", canaryUringCompletion(-int32(unix.EACCES))); why != "EACCES" {
		t.Fatalf("a refused completion: %q", why)
	}
	if err := canaryUringCompletion(0); err != nil {
		t.Fatalf("a successful completion: %v", err)
	}
}

// A fork's EAGAIN can come before task_alloc's hook and before the child's
// PTRACE_TRACEME; it is reached for every other hook.
func TestCanaryRefusalForkEAGAIN(t *testing.T) {
	for hook, want := range map[string]string{"task_alloc": "EAGAIN", "ptrace_traceme": "EAGAIN", "cred_prepare": "", "path_mkdir": ""} {
		if got := canaryRefusal(hook, unix.EAGAIN); got != want {
			t.Errorf("%s: %q, want %q", hook, got, want)
		}
	}
}

// io_uring and user namespaces off on a node: their hooks are not proven
// there, with the node's reason.
func TestCanaryUnprovableNode(t *testing.T) {
	savedUring, savedUserns := canaryUringAvailable, canaryMaxUserNamespaces
	t.Cleanup(func() { canaryUringAvailable, canaryMaxUserNamespaces = savedUring, savedUserns })
	canaryUringAvailable = func() error { return unix.EPERM }
	limit := filepath.Join(t.TempDir(), "max_user_namespaces")
	if err := os.WriteFile(limit, []byte("0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	canaryMaxUserNamespaces = limit
	if why := canaryUnprovable("uring_override_creds"); !strings.Contains(why, "io_uring is not available") {
		t.Fatalf("io_uring off: %q", why)
	}
	if why := canaryUnprovable("userns_create"); !strings.Contains(why, "user.max_user_namespaces=0") {
		t.Fatalf("user namespaces off: %q", why)
	}
	canaryUringAvailable = func() error { return nil }
	if err := os.WriteFile(limit, []byte("1000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if why := canaryUnprovable("uring_override_creds") + canaryUnprovable("userns_create"); why != "" {
		t.Fatalf("both on: %q", why)
	}
}
