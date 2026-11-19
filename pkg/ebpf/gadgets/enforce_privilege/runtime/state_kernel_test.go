//go:build linux && privilege_kernel

// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	privpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/policy"
)

// TestPinnedStateSurvivesReload stops the gadget and loads it again with no
// policy and no binding: the new instance re-opens the pinned maps, so the
// container is still bound to its published policy and still denied.
func TestPinnedStateSurvivesReload(t *testing.T) {
	f := newKernelFixture(t)
	rule := privpolicy.Rule{Name: "no-mntns", Action: "deny", Target: privpolicy.Target{Syscall: []string{"unshare"}, Flags: []string{"CLONE_NEWNS"}}}
	doc := privpolicy.Document{Version: 1, Name: "pinned", Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.start(t, "privilege-pinned-1", compiled, nil)
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
		t.Fatal(err)
	}
	unshare := func() error { return f.exec("unshare", "-m", "true") }
	if unshare() == nil {
		t.Fatal("the bound container must be denied")
	}
	f.stop()
	if err := unshare(); err != nil {
		t.Fatalf("with no instance (links not pinned) nothing judges: %v", err)
	}
	empty, err := privpolicy.CompileSlots(nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	f.start(t, "privilege-pinned-2", empty, nil)
	if unshare() == nil {
		t.Fatal("the reloaded instance must re-open the pinned binding and policy")
	}
	if got := f.bindings.PublishedSlots(); got[0] != 1 {
		t.Fatalf("adopted slots %v", got)
	}
	if got := f.bindings.AdoptedBindings(); got[0] != 1 {
		t.Fatalf("adopted bindings %v", got)
	}
	if n, err := f.bindings.DropAdopted(nil); err != nil || n != 0 {
		t.Fatalf("drop: %d %v", n, err)
	}
	if err := unshare(); err != nil {
		t.Fatalf("a dropped adopted binding judges nothing: %v", err)
	}
}
