//go:build linux && sandboxpolicy_kernel

package igbackend

// Opt-in kernel test of the section hook canary with the real gadget images.
// Requires root and BPF LSM:
//
//	IG_CANARY_KERNEL_TEST=1
//	IG_SECTION_IMAGE_ARCHIVE  OCI archive from `ig image export` with the three images
//	IG_PRIVILEGE_IMAGE, IG_NETWORK_IMAGE, IG_FILE_IMAGE  image names in the archive
//
// For each section it loads an empty instance and requires the canary to
// pass, with only the documented hooks not proven. Then it requires a
// privilege canary that also tests the hooks with no trigger to report them
// silent (PrivilegeHooksSilent).
//
// It resets the sections' pinned maps (realPinReset): run it alone, or with
// go test -p 1, never in parallel with another package's kernel tests.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	orasoci "oras.land/oras-go/v2/content/oci"
)

type canaryKernelEngine interface {
	CanaryErr() error
}

type preparer interface {
	Prepare(context.Context, []sandboxpolicy.Plan) error
	Close(context.Context) error
}

func TestSectionCanaryKernel(t *testing.T) {
	if os.Getenv("IG_CANARY_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable kernel fixture opt-in required")
	}
	realPinReset(t)
	if err := CheckBPFLSM("/"); err != nil {
		t.Fatalf("this test needs an active BPF LSM: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	store, err := orasoci.NewFromTar(ctx, os.Getenv("IG_SECTION_IMAGE_ARCHIVE"))
	if err != nil {
		t.Fatal(err)
	}
	rt := local.New()
	if err = rt.Init(nil); err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	kube := simple.New("no-kubernetes")

	load := func(t *testing.T, section string, tweak func(*sectionCanary)) (canaryKernelEngine, *sectionCanary) {
		t.Helper()
		cleanStatePins(t)
		var engine canaryKernelEngine
		var canary *sectionCanary
		var backend preparer
		switch section {
		case sandboxpolicy.SectionPrivilege:
			e, err := NewNativePrivilegeEngine(rt, kube, store, os.Getenv("IG_PRIVILEGE_IMAGE"), nil)
			if err != nil {
				t.Fatal(err)
			}
			n := e.(*nativePrivilegeEngine)
			engine, canary = n, n.canary
			if tweak != nil {
				tweak(canary)
			}
			b, err := NewPrivilege(e, nil, "canary-test")
			if err != nil {
				t.Fatal(err)
			}
			backend = b
		case sandboxpolicy.SectionNetwork:
			e, err := NewNativeNetworkEngine(rt, kube, store, os.Getenv("IG_NETWORK_IMAGE"), nil)
			if err != nil {
				t.Fatal(err)
			}
			n := e.(*nativeNetworkEngine)
			engine, canary = n, n.canary
			b, err := NewNetwork(e, nil, "canary-test")
			if err != nil {
				t.Fatal(err)
			}
			backend = b
		case sandboxpolicy.SectionFile:
			e, err := NewNativeFileEngine(rt, kube, store, os.Getenv("IG_FILE_IMAGE"), nil)
			if err != nil {
				t.Fatal(err)
			}
			n := e.(*nativeFileEngine)
			engine, canary = n, n.canary
			b, err := NewFile(e, nil, "canary-test")
			if err != nil {
				t.Fatal(err)
			}
			backend = b
		}
		start := time.Now()
		// An instance with no slot loads; its start runs the canary.
		// Closed when the subtest ends, also after a Fatal below.
		t.Cleanup(func() { _ = backend.Close(context.Background()) })
		if err := backend.Prepare(ctx, nil); err != nil {
			t.Fatalf("%s: empty instance: %v", section, err)
		}
		t.Logf("%s: instance start took %v", section, time.Since(start))
		waitCanaryResult(t, canary)
		t.Logf("%s: first canary result after %v", section, time.Since(start))
		return engine, canary
	}

	notProven := map[string][]string{
		sandboxpolicy.SectionPrivilege: {"kernel_load_data", "kernel_module_request", "kernel_read_file"},
		sandboxpolicy.SectionNetwork:   nil,
		sandboxpolicy.SectionFile:      nil,
	}
	for _, section := range []string{sandboxpolicy.SectionPrivilege, sandboxpolicy.SectionNetwork, sandboxpolicy.SectionFile} {
		t.Run(section, func(t *testing.T) {
			engine, canary := load(t, section, nil)
			if err := engine.CanaryErr(); err != nil {
				t.Fatalf("canary failed on a working kernel: %v", err)
			}
			// The kernel-code hooks are never proven. io_uring and user
			// namespaces may be off on a node: those hooks are then not
			// proven too, with this node's reason.
			var got []string
			for hook, why := range canary.NotProven() {
				t.Logf("not proven: %s (%s)", hook, why)
				if (hook == "uring_override_creds" || hook == "userns_create") && why == canaryUnprovable(hook) && why != "" {
					continue
				}
				got = append(got, hook)
			}
			if !sameSet(got, notProven[section]) {
				t.Fatalf("not proven %v, want %v", got, notProven[section])
			}
		})
	}

	// The three kernel-code hooks have no trigger: tested anyway, they must
	// be reported silent, and the result latches.
	t.Run("silent", func(t *testing.T) {
		engine, _ := load(t, sandboxpolicy.SectionPrivilege, func(c *sectionCanary) {
			c.unprovable = func(string) string { return "" }
		})
		err := engine.CanaryErr()
		var u *sandboxpolicy.EnforcementUnavailableError
		if !errors.As(err, &u) || u.Reason != "PrivilegeHooksSilent" {
			t.Fatalf("untriggered hooks not reported silent: %v", err)
		}
		if !strings.Contains(err.Error(), "kernel_load_data") {
			t.Fatalf("silent hook not named: %v", err)
		}
		t.Logf("status detail: %v", err)
	})

	// With kernel.ftrace_enabled=0 the BPF LSM trampolines do not run. The
	// canary must not pass, whatever the attach does (it changes a node
	// sysctl, so it needs its own opt-in).
	t.Run("ftrace-off", func(t *testing.T) {
		if os.Getenv("IG_CANARY_FTRACE_TEST") != "1" {
			t.Skip("IG_CANARY_FTRACE_TEST=1 required: it turns ftrace off on this node")
		}
		const sysctl = "/proc/sys/kernel/ftrace_enabled"
		if err := os.WriteFile(sysctl, []byte("0"), 0); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.WriteFile(sysctl, []byte("1"), 0); err != nil {
				t.Errorf("restoring ftrace: %v", err)
			}
		}()
		cleanStatePins(t)
		e, err := NewNativeNetworkEngine(rt, kube, store, os.Getenv("IG_NETWORK_IMAGE"), nil)
		if err != nil {
			t.Fatal(err)
		}
		b, err := NewNetwork(e, nil, "canary-test")
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close(context.Background())
		if err := b.Prepare(ctx, nil); err != nil {
			t.Logf("the load itself fails with ftrace off: %v", err)
			return
		}
		waitCanaryResult(t, e.(*nativeNetworkEngine).canary)
		err = e.(*nativeNetworkEngine).CanaryErr()
		var u *sandboxpolicy.EnforcementUnavailableError
		if !errors.As(err, &u) || u.Reason != "NetworkHooksSilent" {
			t.Fatalf("ftrace off was not caught: %v", err)
		}
		t.Logf("status detail: %v", err)
	})
}

// waitCanaryResult waits for the canary's first result: it runs in the
// background after the start.
func waitCanaryResult(t *testing.T, c *sectionCanary) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		c.mu.Lock()
		done := c.recorded || c.latched != nil
		c.mu.Unlock()
		if done {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no canary result within 30 s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]bool{}
	for _, x := range a {
		m[x] = true
	}
	for _, x := range b {
		if !m[x] {
			return false
		}
	}
	return true
}
