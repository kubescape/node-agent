//go:build linux && privilege_kernel

// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	privpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/policy"
)

// TestPublishInPlaceUnderLoad republishes slot 0 in place, alternating two
// policies, while a workload in the bound container calls the judged hooks
// in a tight loop. Both policies deny a new mount namespace and allow a new
// UTS namespace. A call that read a half-written, deleted or missing buffer
// would be a structural fault of the Strict binding (denied, and a slot
// fault), so one allowed call that fails, one denied call that passes, or a
// slot fault is a race. It uses the default quarantine.
func TestPublishInPlaceUnderLoad(t *testing.T) {
	f := newKernelFixture(t)
	// The two policies judge the workload the same way but differ in
	// layout (race-b has more entries), so a call that mixed two buffers
	// would miss a lookup and count a fault.
	doc := func(name string) privpolicy.Document {
		rules := []privpolicy.Rule{{Name: name, Action: "deny", Target: privpolicy.Target{Syscall: []string{"unshare"}, Flags: []string{"CLONE_NEWNS"}}}}
		if name == "race-b" {
			rules = append(rules, privpolicy.Rule{Name: name + "-extra", Action: "deny", Target: privpolicy.Target{Syscall: []string{"init_module", "finit_module", "kexec_load"}}})
		}
		return privpolicy.Document{Version: 1, Name: name, Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow", Rules: rules}}}
	}
	first, err := privpolicy.CompileKernel(doc("race-a"), 1)
	if err != nil {
		t.Fatal(err)
	}
	f.start(t, "privilege-race", first, nil)
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
		t.Fatal(err)
	}
	defer f.bindings.Unbind(f.container)

	const seconds = 25
	script := `end=$(( $(date +%s) + ` + strconv.Itoa(seconds) + ` )); n=0
while [ $(date +%s) -lt $end ]; do
  unshare -m true 2>/dev/null && echo BAD-ALLOWED
  unshare -u true 2>/dev/null || echo BAD-DENIED
  n=$((n+1))
done
echo calls=$n`
	type result struct {
		out string
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := exec.CommandContext(f.ctx, "docker", "exec", f.id, "sh", "-c", script).CombinedOutput()
		done <- result{string(out), err}
	}()

	publishes := 0
	deadline := time.Now().Add((seconds + 10) * time.Second)
	var res result
loop:
	for generation := uint64(2); ; generation++ {
		name := "race-a"
		if generation%2 == 1 {
			name = "race-b"
		}
		c, err := privpolicy.CompileKernel(doc(name), generation)
		if err != nil {
			t.Fatal(err)
		}
		p := Publications(c)[0]
		for {
			select {
			case res = <-done:
				break loop
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("the workload did not finish")
			}
			err := f.bindings.Publish(p)
			if errors.Is(err, enforcement.ErrSlotBusy) {
				// The old buffer waits its quarantine.
				if err := f.bindings.Collect(); err != nil {
					t.Fatal(err)
				}
				time.Sleep(20 * time.Millisecond)
				continue
			}
			if err != nil {
				t.Fatalf("publish %d: %v", generation, err)
			}
			publishes++
			break
		}
	}
	t.Logf("%d publishes in place; workload: %s", publishes, strings.TrimSpace(res.out))
	if res.err != nil {
		t.Fatalf("workload: %v: %s", res.err, res.out)
	}
	if strings.Contains(res.out, "BAD") {
		t.Fatalf("a call saw a wrong policy during a publish: %s", res.out)
	}
	if !strings.Contains(res.out, "calls=") || strings.Contains(res.out, "calls=0") {
		t.Fatalf("no workload calls: %s", res.out)
	}
	if publishes < 5 {
		t.Fatalf("only %d publishes", publishes)
	}
	if n, err := f.bindings.SlotFaults(0); err != nil || n != 0 {
		t.Fatalf("slot faults during the publishes: %d %v", n, err)
	}
	if got := f.bindings.SlotGeneration(0); got < 2 {
		t.Fatalf("slot generation %d", got)
	}
}
