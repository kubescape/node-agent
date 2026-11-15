//go:build linux && network_kernel

// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	netpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/policy"
)

// Same fixture and environment as runtime_kernel_test.go.

// compileOne compiles one policy as a one-slot publication.
func compileOne(t *testing.T, doc netpolicy.Document, generation uint64) netpolicy.Compiled {
	t.Helper()
	c, err := netpolicy.CompileSlots([][]netpolicy.Document{{doc}}, generation)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestMissingPublicationDenies: a bound cgroup whose Strict slot lost its
// publication (a crash between a clear and a flip) is denied, counts a slot
// fault and sends a fault verdict; it is never treated as unbound.
func TestMissingPublicationDenies(t *testing.T) {
	f := newKernelFixture(t)
	if err := f.start(t, matrixPolicy(t)); err != nil {
		t.Fatal(err)
	}
	// Slot 1 is the Strict default deny.
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: 1}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.bindings.Unbind(f.container) })
	f.expect(t, f.id, "tcp4", "192.0.2.7", 80, "EPERM")
	before, err := f.bindings.Counters(1)
	if err != nil {
		t.Fatal(err)
	}
	state, err := ebpf.LoadPinnedMap(filepath.Join(enforcement.PinRoot, MapPrefix+enforcement.SlotStateMap), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if err := state.Put(uint32(1), enforcement.SlotState{}); err != nil {
		t.Fatal(err)
	}
	// Loopback is allowed by the policy; with no publication it is denied.
	f.expect(t, f.id, "tcp4", "127.0.0.1", 9, "EPERM")
	after, err := f.bindings.Counters(1)
	if err != nil {
		t.Fatal(err)
	}
	if after.Faults <= before.Faults || after.Attempts <= before.Attempts {
		t.Fatalf("a missing publication counts a fault and an attempt: %+v -> %+v", before, after)
	}
	f.waitFault(t)
}

// TestPublishUnderTraffic republishes a bound slot while the container
// connects in a loop. Every publication denies the destination, so no connect
// may pass during a flip, and the quarantined buffers are collected.
func TestPublishUnderTraffic(t *testing.T) {
	f := newKernelFixture(t)
	if err := f.start(t, matrixPolicy(t)); err != nil {
		t.Fatal(err)
	}
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: 1}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.bindings.Unbind(f.container) })
	explicit := defaultDeny
	explicit.Name = "explicit-deny"
	explicit.Policy.Egress.Rules = append(append([]netpolicy.Rule{}, defaultDeny.Policy.Egress.Rules...),
		netpolicy.Rule{Name: "test-net", Action: "deny", CIDRs: []string{"192.0.2.0/24"}})
	loop := `
import errno, socket, time
end, counts = time.time() + 8, {}
while time.time() < end:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    try:
        s.connect(("192.0.2.7", 80)); r = "OK"
    except PermissionError:
        r = "EPERM"
    except OSError as e:
        r = errno.errorcode.get(e.errno, "timeout") if e.errno else "timeout"
    s.close()
    counts[r] = counts.get(r, 0) + 1
print(" ".join("%s=%d" % kv for kv in sorted(counts.items())))
`
	done := make(chan string, 1)
	go func() {
		out, err := exec.CommandContext(f.ctx, "docker", "exec", f.id, "python3", "-c", loop).CombinedOutput()
		done <- fmt.Sprintf("%s %v", strings.TrimSpace(string(out)), err)
	}()
	publications := 0
	for gen := uint64(10); gen < 40; gen++ {
		doc := defaultDeny
		if gen%2 == 0 {
			doc = explicit
		}
		if err := f.publish(1, compileOne(t, doc, gen)); err != nil {
			t.Fatalf("publish %d: %v", gen, err)
		}
		publications++
		time.Sleep(200 * time.Millisecond)
		if err := f.bindings.Collect(); err != nil {
			t.Fatalf("collect: %v", err)
		}
	}
	result := <-done
	t.Logf("%d publications; connects: %s", publications, result)
	if !strings.Contains(result, "EPERM=") || strings.Contains(result, "OK=") {
		t.Fatalf("every connect must be denied during the flips: %s", result)
	}
	time.Sleep(enforcement.DefaultQuarantine + time.Second)
	if err := f.bindings.Collect(); err != nil {
		t.Fatalf("collect after the quarantine: %v", err)
	}
}
