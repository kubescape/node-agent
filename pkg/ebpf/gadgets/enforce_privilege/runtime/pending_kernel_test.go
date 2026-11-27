//go:build linux && privilege_kernel

// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	privpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/policy"
)

// Same fixture and environment as runtime_kernel_test.go (the container needs
// util-linux unshare, as TestGadgetWithInspektorGadgetAlone). Run the fixture
// container without a healthcheck and nothing else exec'd into it during the
// test: the slot-0 step asserts the node-wide SECTION_ERROR counter does not
// move, and any other judged task in the cgroup could move it.

// pinnedBinding reads the kernel entry of a cgroup in the section's pinned
// binding map: its slot and flags (struct sandbox_binding, ../../common/bindings.h).
func pinnedBinding(t *testing.T, cgroup uint64) (slot, flags uint32) {
	t.Helper()
	m, err := ebpf.LoadPinnedMap(filepath.Join(enforcement.PinRoot, MapPrefix+enforcement.BindingsMap), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	var v struct{ Slot, Flags uint32 }
	if err := m.Lookup(cgroup, &v); err != nil {
		t.Fatalf("binding of cgroup %d: %v", cgroup, err)
	}
	return v.Slot, v.Flags
}

// bindingStrictFlag is BINDING_STRICT of ../../common/bindings.h.
const bindingStrictFlag = 1 << 1

// TestPendingSlotKernel binds the fixture container to PendingSlot, a slot
// that is never published (the start gate's mark). Strict: a judged call is
// a structural fault, denied with EPERM. Audit: it is allowed. Both count
// only in the node-wide SECTION_ERROR counter; there is no per-slot counter.
// Then one bind moves the entry to the published slot 0, whose policy
// decides from then on.
func TestPendingSlotKernel(t *testing.T) {
	f := newKernelFixture(t)
	rule := privpolicy.Rule{Name: "no-newns", Action: "deny", Target: privpolicy.Target{Syscall: []string{"unshare"}, Flags: []string{"CLONE_NEWNS"}}}
	doc := privpolicy.Document{Version: 1, Name: "pending", Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.start(t, "privilege-pending", compiled, nil)
	unshare := func() (string, error) {
		out, err := exec.CommandContext(f.ctx, "docker", "exec", f.id, "unshare", "-m", "true").CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	if out, err := unshare(); err != nil {
		t.Fatalf("an unbound container must not be judged: %v %s", err, out)
	}
	sectionErrors := func() uint64 {
		t.Helper()
		c, err := f.bindings.VerdictCounters()
		if err != nil {
			t.Fatal(err)
		}
		return c.SectionErrors
	}
	t.Cleanup(func() { f.bindings.Unbind(f.container) })

	// Strict pending: EPERM, a section error.
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: enforcement.PendingSlot, Strict: true}); err != nil {
		t.Fatal(err)
	}
	if slot, flags := pinnedBinding(t, f.container.CgroupID); slot != enforcement.PendingSlot || flags&bindingStrictFlag == 0 {
		t.Fatalf("Strict pending entry: slot %#x flags %#x", slot, flags)
	}
	before := sectionErrors()
	out, err := unshare()
	after := sectionErrors()
	t.Logf("Strict pending: unshare %v %s; section errors %d -> %d", err, out, before, after)
	if err == nil || !strings.Contains(out, "Operation not permitted") {
		t.Fatalf("a Strict pending binding must deny with EPERM: %v %s", err, out)
	}
	if after <= before {
		t.Fatalf("the structural fault counts a section error: %d -> %d", before, after)
	}
	if _, err := f.bindings.SlotFaults(enforcement.PendingSlot); err == nil {
		t.Fatal("SlotFaults(PendingSlot) must be an error, never zero")
	}
	if _, err := f.bindings.Counters(enforcement.PendingSlot); err == nil {
		t.Fatal("Counters(PendingSlot) must be an error, never zero")
	}

	// Audit pending: allowed, still a section error.
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: enforcement.PendingSlot}); err != nil {
		t.Fatal(err)
	}
	if slot, flags := pinnedBinding(t, f.container.CgroupID); slot != enforcement.PendingSlot || flags&bindingStrictFlag != 0 {
		t.Fatalf("Audit pending entry: slot %#x flags %#x", slot, flags)
	}
	before = sectionErrors()
	out, err = unshare()
	after = sectionErrors()
	t.Logf("Audit pending: unshare %v %s; section errors %d -> %d", err, out, before, after)
	if err != nil {
		t.Fatalf("an Audit pending binding must allow: %v %s", err, out)
	}
	if after <= before {
		t.Fatalf("the Audit structural fault counts a section error: %d -> %d", before, after)
	}

	// Pending -> slot 0 in one bind: the published policy decides (a
	// policy deny, not a fault).
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: 0}); err != nil {
		t.Fatal(err)
	}
	if slot, flags := pinnedBinding(t, f.container.CgroupID); slot != 0 || flags&bindingStrictFlag == 0 {
		t.Fatalf("bound entry: slot %d flags %#x", slot, flags)
	}
	counters, err := f.bindings.VerdictCounters()
	if err != nil {
		t.Fatal(err)
	}
	slotBefore, err := f.bindings.Counters(0)
	if err != nil {
		t.Fatal(err)
	}
	out, unshareErr := unshare()
	verdictsAfter, err := f.bindings.VerdictCounters()
	if err != nil {
		t.Fatal(err)
	}
	slotAfter, err := f.bindings.Counters(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("slot 0: unshare %v %s; verdicts %+v -> %+v; slot %+v -> %+v", unshareErr, out, counters, verdictsAfter, slotBefore, slotAfter)
	if unshareErr == nil || !strings.Contains(out, "Operation not permitted") {
		t.Fatalf("slot 0 denies unshare(CLONE_NEWNS) with EPERM: %v %s", unshareErr, out)
	}
	if verdictsAfter.SectionErrors != counters.SectionErrors {
		// A healthcheck or another exec in the cgroup moves this
		// node-wide counter too (see the header).
		t.Fatalf("slot 0's policy deny is not a fault: section errors moved by %d", verdictsAfter.SectionErrors-counters.SectionErrors)
	}
	if verdictsAfter.Denied <= counters.Denied || slotAfter.Faults != slotBefore.Faults || slotAfter.Attempts <= slotBefore.Attempts {
		t.Fatalf("slot 0's policy deny, not a fault: verdicts %+v -> %+v, slot %+v -> %+v", counters, verdictsAfter, slotBefore, slotAfter)
	}
}
