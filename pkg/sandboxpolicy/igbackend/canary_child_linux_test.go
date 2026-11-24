//go:build linux

package igbackend

import (
	"bytes"
	"os"
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

// The child writes a refused call's hooks, and canaryResults reads them back;
// a hook refused after its hook by design is never listed.
func TestCanaryChildResults(t *testing.T) {
	saved := canaryTriggers
	t.Cleanup(func() { canaryTriggers = saved })
	canaryTriggers = []canaryTrigger{
		{[]string{"a"}, func(string) error { return unix.EPERM }},
		{[]string{"b"}, func(string) error { return unix.ENOENT }},
		{[]string{"cred_alloc_blank"}, func(string) error { return unix.EPERM }},
		{[]string{"c"}, func(string) error { return unix.ENOSYS }},
		{[]string{"c"}, func(string) error { return nil }}, // a second call reached it
	}
	dir := t.TempDir()
	if rc := runCanaryChild([]string{"a", "b", "c", "cred_alloc_blank"}, dir); rc != 0 {
		t.Fatalf("rc %d", rc)
	}
	got := canaryResults(dir)
	if len(got) != 1 || got["a"] != "EPERM" {
		t.Fatalf("results %v", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("the work directory was left: %v", entries)
	}
}
