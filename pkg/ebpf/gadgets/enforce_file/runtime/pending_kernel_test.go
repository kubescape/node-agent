//go:build linux && file_kernel

// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	filepolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/policy"
)

// Same fixture and environment as runtime_kernel_test.go.
// TestForkMarkFaultErrno needs FILE_HELPER_BINARY with a `fork -` command
// (one fork, the child exits; on failure "fork -: <strerror>", exit 1).

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

// waitFaultSince waits for a fault verdict (hook "fault", sent only for an
// armed task) with mode (1 Audit, 2 Strict) among the verdicts after from.
func (f *kernelFixture) waitFaultSince(t *testing.T, from int, mode uint32) {
	t.Helper()
	for i := 0; i < 30; i++ {
		f.mu.Lock()
		for j := from; j < len(f.verdicts); j++ {
			// The hook enum is exported by name (as FILE_HOOK_ROOT_BARRIER in the suite).
			if f.hooks[j] == "FILE_HOOK_FAULT" && f.verdicts[j].mode == mode {
				f.mu.Unlock()
				return
			}
		}
		f.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	t.Errorf("no fault verdict with mode %d after %d; hooks %v", mode, from, f.hooks[from:])
}

// sectionErrors reads the node-wide SECTION_ERROR verdict counter.
func (f *kernelFixture) sectionErrors(t *testing.T) uint64 {
	t.Helper()
	c, err := f.bindings.VerdictCounters()
	if err != nil {
		t.Fatal(err)
	}
	return c.SectionErrors
}

// TestPendingSlotKernel binds the fixture container to PendingSlot, a slot
// that is never published (the start gate's mark). Strict: every judged file
// access of an armed task is a structural fault, denied with EPERM (the shell
// itself cannot load its libraries, so the command fails with that errno).
// Audit: allowed. Both send a fault verdict of their class and count only in
// the node-wide SECTION_ERROR counter. Then one bind moves the entry to the
// published slot 0 (the lab policy), whose rules decide from then on.
func TestPendingSlotKernel(t *testing.T) {
	f := newKernelFixture(t)
	compiled, err := filepolicy.CompileSlots([][]filepolicy.Document{{labDocument("pending", "enforce")}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.start(t, compiled)
	read := "cat /etc/hostname >/dev/null"
	f.ok(t, f.id, read) // unbound: not judged
	t.Cleanup(func() { f.bindings.Unbind(f.container) })

	// Strict pending: EPERM, a Strict fault verdict, a section error.
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: enforcement.PendingSlot, Strict: true}); err != nil {
		t.Fatal(err)
	}
	if slot, flags := pinnedBinding(t, f.container.CgroupID); slot != enforcement.PendingSlot || flags&bindingStrictFlag == 0 {
		t.Fatalf("Strict pending entry: slot %#x flags %#x", slot, flags)
	}
	before, from := f.sectionErrors(t), f.mark()
	f.denied(t, f.id, read)
	f.waitFaultSince(t, from, 2)
	after := f.sectionErrors(t)
	t.Logf("Strict pending: section errors %d -> %d", before, after)
	if after <= before {
		t.Fatalf("the structural fault counts a section error: %d -> %d", before, after)
	}
	if _, err := f.bindings.SlotFaults(enforcement.PendingSlot); err == nil {
		t.Fatal("SlotFaults(PendingSlot) must be an error, never zero")
	}
	if _, err := f.bindings.Counters(enforcement.PendingSlot); err == nil {
		t.Fatal("Counters(PendingSlot) must be an error, never zero")
	}

	// Audit pending: allowed (the lab policy would deny /etc/shadow; with
	// no policy the Audit mark allows it), an Audit fault verdict, a
	// section error.
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: enforcement.PendingSlot}); err != nil {
		t.Fatal(err)
	}
	if slot, flags := pinnedBinding(t, f.container.CgroupID); slot != enforcement.PendingSlot || flags&bindingStrictFlag != 0 {
		t.Fatalf("Audit pending entry: slot %#x flags %#x", slot, flags)
	}
	before, from = f.sectionErrors(t), f.mark()
	f.ok(t, f.id, read)
	f.ok(t, f.id, "cat /etc/shadow >/dev/null")
	f.waitFaultSince(t, from, 1)
	after = f.sectionErrors(t)
	t.Logf("Audit pending: section errors %d -> %d", before, after)
	if after <= before {
		t.Fatalf("the Audit structural fault counts a section error: %d -> %d", before, after)
	}

	// Pending -> slot 0 in one bind: the lab policy decides (a rule deny,
	// not a fault).
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: 0}); err != nil {
		t.Fatal(err)
	}
	if slot, flags := pinnedBinding(t, f.container.CgroupID); slot != 0 || flags&bindingStrictFlag == 0 {
		t.Fatalf("bound entry: slot %d flags %#x", slot, flags)
	}
	slotBefore, err := f.bindings.Counters(0)
	if err != nil {
		t.Fatal(err)
	}
	from = f.mark()
	f.ok(t, f.id, read)
	f.denied(t, f.id, "cat /etc/shadow >/dev/null")
	f.waitVerdictSince(t, from, verdict{rule: "pending/secret-read", deny: 1, mode: 2, access: accessRead, path: "/etc/shadow"})
	slotAfter, err := f.bindings.Counters(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("slot 0: counters %+v -> %+v", slotBefore, slotAfter)
	if slotAfter.Faults != slotBefore.Faults || slotAfter.Attempts <= slotBefore.Attempts {
		t.Fatalf("slot 0 judges with no fault: %+v -> %+v", slotBefore, slotAfter)
	}
}

// TestPendingSlotSubtreeKernel binds a parent cgroup outside the container
// with the start gate's mark shape (PendingSlot, Subtree, RuntimeHelpers)
// and moves the worker, an armed task and the only task there, into its
// child cgroup: the subtree lookup must find the pending entry. Audit: the
// worker runs and sends Audit fault verdicts. Strict: its accesses send
// Strict fault verdicts (it can no longer answer: every file access fails).
func TestPendingSlotSubtreeKernel(t *testing.T) {
	f := newKernelFixture(t)
	compiled, err := filepolicy.CompileSlots([][]filepolicy.Document{{labDocument("pending-subtree", "enforce")}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.start(t, compiled)
	parentPath := "/file-test-pending-parent"
	child := filepath.Join(parentPath, "child")
	for _, p := range []string{parentPath, child} {
		if err := os.Mkdir(cgroupDir(p), 0o755); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
	}
	parent := identity(t, "parent", "file-test-pending-parent", parentPath)
	w := startWorker(t, f)
	t.Cleanup(func() {
		f.bindings.Unbind(parent)
		unix.Kill(w.pid, unix.SIGKILL)
		for _, p := range []string{child, parentPath} {
			var err error
			for i := 0; i < 50; i++ {
				if err = os.Remove(cgroupDir(p)); err == nil || os.IsNotExist(err) {
					err = nil
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if err != nil {
				t.Logf("cleanup: cgroup %s left behind: %v", p, err)
			}
		}
	})
	w.moveTo(t, child)
	const readSecret = "read x < /etc/shadow"
	w.ok(t, readSecret) // unbound: not judged
	mark := enforcement.Binding{Container: parent, Slot: enforcement.PendingSlot, Subtree: true, RuntimeHelpers: true}

	// Audit pending subtree: allowed, an Audit fault verdict.
	if err := f.bindings.Bind(mark); err != nil {
		t.Fatal(err)
	}
	if slot, flags := pinnedBinding(t, parent.CgroupID); slot != enforcement.PendingSlot || flags&bindingStrictFlag != 0 {
		t.Fatalf("Audit pending subtree entry: slot %#x flags %#x", slot, flags)
	}
	before, from := f.sectionErrors(t), f.mark()
	w.ok(t, readSecret)
	f.waitFaultSince(t, from, 1)
	after := f.sectionErrors(t)
	t.Logf("Audit pending subtree: section errors %d -> %d", before, after)
	if after <= before {
		t.Fatalf("the Audit structural fault counts a section error: %d -> %d", before, after)
	}

	// Strict pending subtree (last: the worker cannot answer after it).
	mark.Strict = true
	before, from = f.sectionErrors(t), f.mark()
	if err := f.bindings.Bind(mark); err != nil {
		t.Fatal(err)
	}
	if slot, flags := pinnedBinding(t, parent.CgroupID); slot != enforcement.PendingSlot || flags&bindingStrictFlag == 0 {
		t.Fatalf("Strict pending subtree entry: slot %#x flags %#x", slot, flags)
	}
	f.waitFaultSince(t, from, 2) // the worker's own loop (sleep, /tmp/w.cmd)
	after = f.sectionErrors(t)
	t.Logf("Strict pending subtree: section errors %d -> %d", before, after)
	if after <= before {
		t.Fatalf("the Strict structural fault counts a section error: %d -> %d", before, after)
	}
}

// TestForkMarkFaultErrno: with every child mark failing, a Strict binding
// refuses the fork with EPERM (N1; the shell prints no errno, so the static
// helper forks). Audit allows it.
func TestForkMarkFaultErrno(t *testing.T) {
	helper := os.Getenv("FILE_HELPER_BINARY")
	for _, mode := range []string{"enforce", "audit"} {
		t.Run(mode, func(t *testing.T) {
			f := newKernelFixture(t)
			if helper == "" {
				t.Skip("FILE_HELPER_BINARY is not set")
			}
			compiled, err := filepolicy.CompileSlots([][]filepolicy.Document{{labDocument("fork-errno-"+mode, mode)}}, 1)
			if err != nil {
				t.Fatal(err)
			}
			f.startExtra(t, compiled, map[string]string{"arming-fail-fork-marks": "1"})
			// exec: the shell must not fork itself (its fork would fail first).
			fork := "exec " + helper + " fork -"
			f.ok(t, f.id, fork) // unbound: not judged
			if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
				t.Fatal(err)
			}
			defer f.bindings.Unbind(f.container)
			before, err := f.bindings.Counters(0)
			if err != nil {
				t.Fatal(err)
			}
			code, out := f.sh(t, f.id, fork)
			after, err := f.bindings.Counters(0)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s: rc %d %s; counters %+v -> %+v", fork, code, out, before, after)
			switch mode {
			case "enforce":
				if code == 0 || !strings.Contains(out, "fork -: Operation not permitted") || after.Faults <= before.Faults {
					t.Fatalf("Strict must refuse the fork with EPERM and count a fault: rc %d %s", code, out)
				}
			case "audit":
				if code != 0 || after.Faults != before.Faults || after.Unevaluated <= before.Unevaluated {
					t.Fatalf("audit mode must allow the fork, count no fault and count an unevaluated judgement: rc %d %s", code, out)
				}
			}
		})
	}
}

// TestCredRecordFailureErrno: with every credential record failing, a Strict
// binding refuses the exec (runc init's own credential changes, recorded at
// file_record_cred via cred_prepare) and counts a slot fault; Audit runs it.
// The hook returns EPERM, but prepare_creds() turns a security_prepare_creds
// failure into NULL and its callers return ENOMEM: the errno user space sees
// here is the kernel's. The match is case-insensitive on runc's (or nsexec's)
// "cannot allocate memory" for the refused credential change.
func TestCredRecordFailureErrno(t *testing.T) {
	for _, mode := range []string{"enforce", "audit"} {
		t.Run(mode, func(t *testing.T) {
			f := newKernelFixture(t)
			compiled, err := filepolicy.CompileSlots([][]filepolicy.Document{{labDocument("cred-errno-"+mode, mode)}}, 1)
			if err != nil {
				t.Fatal(err)
			}
			f.startExtra(t, compiled, map[string]string{"cred-record-fail": "1"})
			run := func() (string, error) {
				out, err := exec.CommandContext(f.ctx, "docker", "exec", f.id, "true").CombinedOutput()
				return strings.TrimSpace(string(out)), err
			}
			if out, err := run(); err != nil {
				t.Fatalf("an unbound container must not be judged: %v %s", err, out)
			}
			if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
				t.Fatal(err)
			}
			defer f.bindings.Unbind(f.container)
			before, err := f.bindings.Counters(0)
			if err != nil {
				t.Fatal(err)
			}
			out, runErr := run()
			after, err := f.bindings.Counters(0)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("docker exec true: %v %s; counters %+v -> %+v", runErr, out, before, after)
			switch mode {
			case "enforce":
				if runErr == nil || !strings.Contains(strings.ToLower(out), "cannot allocate memory") || after.Faults <= before.Faults {
					t.Fatalf("Strict must refuse unrecordable credentials (the kernel's ENOMEM from prepare_creds) and count a fault: %v %s", runErr, out)
				}
			case "audit":
				if runErr != nil || after.Faults != before.Faults || after.Unevaluated <= before.Unevaluated {
					t.Fatalf("audit mode must run the exec, count no fault and count an unevaluated judgement: %v %s", runErr, out)
				}
			}
		})
	}
}
