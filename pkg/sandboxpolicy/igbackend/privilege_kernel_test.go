//go:build linux && sandboxpolicy_kernel

package igbackend

// Opt-in kernel test of the privilege backend with the real gadget image.
// Requires root, BPF LSM and a disposable Docker container started with
// seccomp=unconfined, apparmor=unconfined and --cap-add SYS_ADMIN:
//
//	IG_PRIVILEGE_KERNEL_TEST=1
//	IG_PRIVILEGE_IMAGE_ARCHIVE  OCI archive from `ig image export`
//	IG_PRIVILEGE_IMAGE          image name in the archive
//	IG_PRIVILEGE_CONTAINER_ID   full Docker container ID
//	IG_PRIVILEGE_CGROUP_PATH    its cgroup v2 path under /sys/fs/cgroup, with a leading "/" (as in /proc/<pid>/cgroup)
//	IG_PRIVILEGE_CONTAINER_ID2, IG_PRIVILEGE_CGROUP_PATH2  a second container
//
// With two containers it also checks the node-wide instance: the second
// container with the same policy is a live bind (no new instance), and a
// second container with another policy replaces the instance while the first
// container stays protected.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"golang.org/x/sys/unix"
	orasoci "oras.land/oras-go/v2/content/oci"
)

func TestPrivilegeBackendKernel(t *testing.T) {
	if os.Getenv("IG_PRIVILEGE_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable kernel fixture opt-in required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := CheckBPFLSM("/"); err != nil {
		t.Fatalf("this test needs an active BPF LSM: %v", err)
	}
	bindingOf := func(id, cgroupPath string) sandboxpolicy.Binding {
		var st unix.Stat_t
		if err := unix.Stat(filepath.Join("/sys/fs/cgroup", cgroupPath), &st); err != nil {
			t.Fatal(err)
		}
		return sandboxpolicy.Binding{Runtime: "docker", ContainerID: id, CgroupID: st.Ino, CgroupPath: cgroupPath}
	}
	id := os.Getenv("IG_PRIVILEGE_CONTAINER_ID")
	binding := bindingOf(id, os.Getenv("IG_PRIVILEGE_CGROUP_PATH"))

	store, err := orasoci.NewFromTar(ctx, os.Getenv("IG_PRIVILEGE_IMAGE_ARCHIVE"))
	if err != nil {
		t.Fatal(err)
	}
	rt := local.New()
	if err = rt.Init(nil); err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	engine, err := NewNativePrivilegeEngine(rt, simple.New("no-kubernetes"), store, os.Getenv("IG_PRIVILEGE_IMAGE"))
	if err != nil {
		t.Fatal(err)
	}
	backend, err := NewPrivilege(engine, nil, "kernel-test")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close(context.Background())

	unshareIn := func(id string) error {
		return exec.CommandContext(ctx, "docker", "exec", id, "unshare", "-m", "true").Run()
	}
	unshare := func() error { return unshareIn(id) }
	plan := func(revision string, action api.Action) sandboxpolicy.Plan {
		return sandboxpolicy.Plan{Revision: revision, Policies: []sandboxpolicy.CompiledPolicy{{Mode: api.ModeEnforce, Privilege: &api.PrivilegeSection{
			Default: api.ActionAllow,
			Rules: []api.PrivilegeRule{{Rule: api.Rule{Name: "mount-namespace", Action: action},
				Target: api.PrivilegeTarget{Syscall: []string{"unshare"}, Flags: []string{"CLONE_NEWNS"}}}},
		}}}}
	}

	if err = unshare(); err != nil {
		t.Fatalf("baseline unshare failed: %v", err)
	}
	// An instance with no slot loads before any container needs it.
	if err := backend.Prepare(ctx, nil); err != nil || backend.Stats().Replacements != 1 {
		t.Fatalf("empty instance: %v %+v", err, backend.Stats())
	}
	if err = unshare(); err != nil {
		t.Fatalf("an empty instance must judge nothing: %v", err)
	}
	if r, err := backend.Replace(ctx, binding, plan("deny", api.ActionDeny)); err != nil || !r.Committed {
		t.Fatalf("deny plan: %+v %v", r, err)
	}
	if err = backend.Attest(ctx, binding, "deny"); err != nil {
		t.Fatal(err)
	}
	if unshare() == nil {
		t.Fatal("unshare allowed under the deny plan")
	}
	if id2 := os.Getenv("IG_PRIVILEGE_CONTAINER_ID2"); id2 != "" {
		second := bindingOf(id2, os.Getenv("IG_PRIVILEGE_CGROUP_PATH2"))
		if r, err := backend.Replace(ctx, second, plan("deny", api.ActionDeny)); err != nil || !r.Committed {
			t.Fatalf("second container, same policy: %+v %v", r, err)
		}
		if s := backend.Stats(); s.Prepared != 1 || s.Replacements != 2 {
			t.Fatalf("same policy must be a live bind: %+v", s)
		}
		if unshareIn(id2) == nil {
			t.Fatal("second container not denied")
		}
		other := plan("other", api.ActionAllow)
		other.Policies[0].Identity.UID = "other"
		if r, err := backend.Replace(ctx, second, other); err != nil || !r.Committed {
			t.Fatalf("second container, other policy: %+v %v", r, err)
		}
		if s := backend.Stats(); s.Replacements != 3 {
			t.Fatalf("a new combination must replace the instance: %+v", s)
		}
		if unshareIn(id2) != nil {
			t.Fatal("second container must be allowed by its new policy")
		}
		if unshare() == nil {
			t.Fatal("first container lost protection across the replacement")
		}
		if r, err := backend.Withdraw(ctx, second); err != nil || !r.Committed {
			t.Fatalf("withdraw second: %+v %v", r, err)
		}
	}
	if r, err := backend.Replace(ctx, binding, plan("allow", api.ActionAllow)); err != nil || !r.Committed {
		t.Fatalf("allow plan: %+v %v", r, err)
	}
	if err = unshare(); err != nil {
		t.Fatalf("unshare denied under the allow plan: %v", err)
	}
	if r, err := backend.Withdraw(ctx, binding); err != nil || !r.Committed {
		t.Fatalf("withdraw: %+v %v", r, err)
	}
}
