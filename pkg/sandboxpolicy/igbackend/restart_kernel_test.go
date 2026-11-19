//go:build linux && sandboxpolicy_kernel

package igbackend

// Opt-in kernel test of restart survival with the real privilege, network and
// file gadgets. Same fixture as TestPrivilegeBackendKernel
// (IG_PRIVILEGE_KERNEL_TEST, IG_PRIVILEGE_IMAGE_ARCHIVE, IG_PRIVILEGE_IMAGE,
// IG_PRIVILEGE_CONTAINER_ID, IG_PRIVILEGE_CGROUP_PATH), plus a host bpffs at
// /sys/fs/bpf. IG_NETWORK_IMAGE and IG_FILE_IMAGE name the other two images in
// the same archive; a section without its image is skipped. The container
// needs busybox (unshare, cat), seccomp=unconfined, apparmor=unconfined
// and --cap-add SYS_ADMIN; the test copies a static connect helper into it.
//
// For each section, a loader process (this test binary, re-executed) binds
// the container to a policy that denies one action (privilege:
// unshare(CLONE_NEWNS); network: a connect to 192.0.2.1; file: a read of
// /etc/hostname), then is killed with SIGKILL:
//
//  1. without restart survival, the denial ends with the loader;
//  2. with restart survival, the denial stays after the loader's death;
//  3. the pinned set is valid in another process, and a set with an
//     unlisted pin or for another section does not;
//  4. a second loader adopts the set, settles (the old set goes, its own
//     instance is pinned) and is killed: the denial stays all the time;
//  5. a third loader adopts and shuts down cleanly (SIGTERM, Close): the
//     denial stays;
//  6. removing the pins ends the denial and leaves no program loaded.

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	filepolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/policy"
	fileruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/runtime"
	netpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/policy"
	netruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/runtime"
	privruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"golang.org/x/sys/unix"
	orasoci "oras.land/oras-go/v2/content/oci"
)

const (
	restartLoaderEnv  = "IG_RESTART_LOADER_ROOT" // "-": no restart survival
	restartSectionEnv = "IG_RESTART_SECTION"
	// restartPlanEnv: the loader's plan: "enforce" (default), "audit", or
	// "none" (no policy uses the section: no Replace).
	restartPlanEnv = "IG_RESTART_PLAN"
	// restartOtherEnv: bind the plan to this cgroup path (relative to
	// /sys/fs/cgroup) instead of the container, so the container's adopted
	// binding is never bound again.
	restartOtherEnv = "IG_RESTART_OTHER_CGROUP"
	// restartNoSettleEnv: "1" skips the converged Settle.
	restartNoSettleEnv = "IG_RESTART_NO_SETTLE"
	// restartDeadlineEnv: a settle deadline (a Go duration). The loader waits
	// past it, then runs a Prepare, which applies it.
	restartDeadlineEnv = "IG_RESTART_DEADLINE"
	// restartSnapshotEnv: "1" reports a complete binding snapshot.
	restartSnapshotEnv = "IG_RESTART_SNAPSHOT"
)

// restartImages are the image variables of each section.
var restartImages = map[string]string{
	sandboxpolicy.SectionPrivilege: "IG_PRIVILEGE_IMAGE",
	sandboxpolicy.SectionNetwork:   "IG_NETWORK_IMAGE",
	sandboxpolicy.SectionFile:      "IG_FILE_IMAGE",
}

// restartBackend is what the loader uses of a node backend.
type restartBackend interface {
	sandboxpolicy.Backend
	RestartSurvival(root string) error
	Settle(context.Context) error
	Close(context.Context) error
}

func restartBinding(t *testing.T) sandboxpolicy.Binding {
	var st unix.Stat_t
	path := os.Getenv("IG_PRIVILEGE_CGROUP_PATH")
	if err := unix.Stat(filepath.Join("/sys/fs/cgroup", path), &st); err != nil {
		t.Fatal(err)
	}
	return sandboxpolicy.Binding{Runtime: "docker", ContainerID: os.Getenv("IG_PRIVILEGE_CONTAINER_ID"), CgroupID: st.Ino, CgroupPath: path}
}

// restartDenyPlan denies the section's test action.
func restartDenyPlan(section string) sandboxpolicy.Plan { return restartPlan(section, "enforce") }

// restartPlan is the section's deny policy in mode (enforce or audit).
func restartPlan(section, mode string) sandboxpolicy.Plan {
	policy := sandboxpolicy.CompiledPolicy{Mode: api.PolicyMode(mode)}
	switch section {
	case sandboxpolicy.SectionPrivilege:
		policy.Privilege = &api.PrivilegeSection{Default: api.ActionAllow,
			Rules: []api.PrivilegeRule{{Rule: api.Rule{Name: "mount-namespace", Action: api.ActionDeny},
				Target: api.PrivilegeTarget{Syscall: []string{"unshare"}, Flags: []string{"CLONE_NEWNS"}}}}}
	case sandboxpolicy.SectionNetwork:
		policy.Network = &sandboxpolicy.NetworkPlan{Egress: netpolicy.Document{Version: 1, Policy: netpolicy.Policy{Mode: "enforce",
			Egress: netpolicy.Section{Default: "allow", Rules: []netpolicy.Rule{{Name: "test-net", Action: "deny", CIDRs: []string{"192.0.2.0/24"}}}}}}}
		policy.Network.Egress.Policy.Mode = mode
	case sandboxpolicy.SectionFile:
		defaults := map[string]filepolicy.Default{}
		for _, k := range filepolicy.AccessKinds {
			defaults[k] = filepolicy.Default{Action: "allow"}
		}
		policy.File = &sandboxpolicy.FilePlan{Doc: filepolicy.Document{Version: 1, Policy: filepolicy.Policy{Mode: mode, File: filepolicy.Section{Defaults: defaults,
			Rules: []filepolicy.Rule{{Name: "hostname", Action: "deny", Access: []string{filepolicy.AccessRead}, Paths: []string{"/etc/hostname"}}}}}}}
	}
	return sandboxpolicy.Plan{Revision: "deny-" + mode, Policies: []sandboxpolicy.CompiledPolicy{policy}}
}

// restartAction runs the section's test action in the container and returns
// an error when it is denied (or fails in another way).
func restartAction(ctx context.Context, section, id string) error {
	args := map[string][]string{
		sandboxpolicy.SectionPrivilege: {"unshare", "-m", "true"},
		// The helper prints the connect's errno; only EPERM is a deny (a
		// fast network error, such as an unreachable, is not).
		sandboxpolicy.SectionNetwork: {"/restart-connect", "192.0.2.1", "80"},
		sandboxpolicy.SectionFile:    {"cat", "/etc/hostname"},
	}[section]
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	start := time.Now()
	out, err := exec.CommandContext(c, "docker", append([]string{"exec", id}, args...)...).CombinedOutput()
	if section == sandboxpolicy.SectionNetwork {
		// Review 8: a deny is EPERM and nothing else.
		if strings.TrimSpace(string(out)) == "errno=1" {
			return fmt.Errorf("connect denied (EPERM) after %v", time.Since(start))
		}
		if err != nil && !strings.HasPrefix(strings.TrimSpace(string(out)), "errno=") {
			return fmt.Errorf("connect helper: %w: %s", err, out)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func restartLoaderBackend(t *testing.T, section string, rt *local.Runtime, store *orasoci.ReadOnlyStore) restartBackend {
	image := os.Getenv(restartImages[section])
	kube := simple.New("no-kubernetes")
	var backend restartBackend
	var err error
	switch section {
	case sandboxpolicy.SectionPrivilege:
		var e PrivilegeEngine
		if e, err = NewNativePrivilegeEngine(rt, kube, store, image, nil); err == nil {
			backend, err = NewPrivilege(e, nil, "restart-test")
		}
	case sandboxpolicy.SectionNetwork:
		var e NetworkEngine
		if e, err = NewNativeNetworkEngine(rt, kube, store, image, nil); err == nil {
			backend, err = NewNetwork(e, nil, "restart-test")
		}
	case sandboxpolicy.SectionFile:
		var e FileEngine
		if e, err = NewNativeFileEngine(rt, kube, store, image, nil); err == nil {
			backend, err = NewFile(e, nil, "restart-test")
		}
	default:
		err = fmt.Errorf("unknown section %q", section)
	}
	if err != nil {
		t.Fatal(err)
	}
	return backend
}

// TestRestartLoaderHelper is the loader process. It does nothing in a normal run.
func TestRestartLoaderHelper(t *testing.T) {
	root := os.Getenv(restartLoaderEnv)
	if root == "" {
		t.Skip("loader process only")
	}
	ctx := context.Background()
	store, err := orasoci.NewFromTar(ctx, os.Getenv("IG_PRIVILEGE_IMAGE_ARCHIVE"))
	if err != nil {
		t.Fatal(err)
	}
	rt := local.New()
	if err = rt.Init(nil); err != nil {
		t.Fatal(err)
	}
	section := os.Getenv(restartSectionEnv)
	backend := restartLoaderBackend(t, section, rt, store)
	if root != "-" {
		if err := backend.RestartSurvival(root); err != nil {
			t.Fatal(err)
		}
	}
	if d := os.Getenv(restartDeadlineEnv); d != "" {
		if settleDeadline, err = time.ParseDuration(d); err != nil {
			t.Fatal(err)
		}
	}
	mode := os.Getenv(restartPlanEnv)
	if mode == "" {
		mode = "enforce"
	}
	binding := restartBinding(t)
	if other := os.Getenv(restartOtherEnv); other != "" {
		var st unix.Stat_t
		if err := unix.Stat(filepath.Join("/sys/fs/cgroup", other), &st); err != nil {
			t.Fatal(err)
		}
		binding = sandboxpolicy.Binding{Runtime: "docker", ContainerID: "restart-other", CgroupID: st.Ino, CgroupPath: other}
	}
	plan := restartPlan(section, mode)
	if mode != "none" {
		if r, err := backend.Replace(ctx, binding, plan); err != nil || !r.Committed {
			t.Fatalf("%s plan: %+v %v", mode, r, err)
		}
	}
	if os.Getenv(restartSnapshotEnv) == "1" {
		backend.(sandboxpolicy.SnapshotObserver).SnapshotComplete()
	}
	if root != "-" && os.Getenv(restartNoSettleEnv) != "1" {
		if err := backend.Settle(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if os.Getenv(restartDeadlineEnv) != "" {
		// The service runs Prepare at most every 30 s; the deadline acts there.
		time.Sleep(settleDeadline + 200*time.Millisecond)
		if err := backend.(interface {
			Prepare(context.Context, []sandboxpolicy.Plan) error
		}).Prepare(ctx, []sandboxpolicy.Plan{plan}); err != nil {
			t.Fatal(err)
		}
	}
	// SIGTERM is the clean shutdown: close as node-agent does, then exit.
	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM)
	fmt.Println("LOADER-READY")
	<-term
	if err := backend.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}

// restartPrefixes are the sections' pinned map prefixes (common/pin.h).
var restartPrefixes = map[string]string{sandboxpolicy.SectionPrivilege: privruntime.MapPrefix, sandboxpolicy.SectionNetwork: netruntime.MapPrefix, sandboxpolicy.SectionFile: fileruntime.MapPrefix}

func TestRestartSurvivalKernel(t *testing.T) {
	if os.Getenv("IG_PRIVILEGE_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable kernel fixture opt-in required")
	}
	if !enforcement.IsBPFFS("/sys/fs/bpf") {
		t.Fatal("this test needs a bpffs at /sys/fs/bpf")
	}
	cleanStatePins(t)
	copyConnectHelper(t)
	for _, section := range []string{sandboxpolicy.SectionPrivilege, sandboxpolicy.SectionNetwork, sandboxpolicy.SectionFile} {
		t.Run(section, func(t *testing.T) {
			if os.Getenv(restartImages[section]) == "" {
				t.Skipf("%s is not set", restartImages[section])
			}
			restartSurvivalKernel(t, section)
		})
	}
}

func restartSurvivalKernel(t *testing.T, section string) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	id := os.Getenv("IG_PRIVILEGE_CONTAINER_ID")
	act := func() error { return restartAction(ctx, section, id) }
	root := fmt.Sprintf("/sys/fs/bpf/kubescape-sandbox-test-%d-%s", os.Getpid(), section)
	sectionDir := filepath.Join(root, section)
	defer enforcement.RemovePinned(root)
	// The section's state maps are pinned by name and outlive the loaders.
	defer enforcement.RemovePinnedMaps(restartPrefixes[section])
	// The kernel frees detached programs asynchronously: start from a count
	// that no longer changes (a previous section's programs can still go).
	lsmBefore := countLSMPrograms(t)
	for i, stable := 0, 0; i < 100 && stable < 10; i++ {
		time.Sleep(100 * time.Millisecond)
		if n := countLSMPrograms(t); n != lsmBefore {
			lsmBefore, stable = n, 0
		} else {
			stable++
		}
	}

	loaderEnv := func(root, mode string, env ...string) *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run", "^TestRestartLoaderHelper$", "-test.v")
		cmd.Env = append(append(os.Environ(), restartLoaderEnv+"="+root, restartSectionEnv+"="+section, restartPlanEnv+"="+mode), env...)
		cmd.Stderr = os.Stderr
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		// A failed check must not leave a loader (and its enforcement) behind.
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		ready := make(chan struct{})
		go func() {
			scanner := bufio.NewScanner(out)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, "LOADER-READY") {
					close(ready)
				} else if strings.Contains(line, "_test.go") || strings.Contains(line, "FAIL") {
					fmt.Fprintln(os.Stderr, "loader:", line)
				}
			}
		}()
		select {
		case <-ready:
		case <-time.After(2 * time.Minute):
			_ = cmd.Process.Kill()
			t.Fatal("loader not ready")
		}
		return cmd
	}
	loaderPlan := func(root, mode string) *exec.Cmd { return loaderEnv(root, mode) }
	loader := func(root string) *exec.Cmd { return loaderPlan(root, "enforce") }
	kill := func(cmd *exec.Cmd) {
		_ = cmd.Process.Signal(syscall.SIGKILL)
		_ = cmd.Wait()
	}
	terminate := func(cmd *exec.Cmd) {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		if err := cmd.Wait(); err != nil {
			t.Fatalf("clean shutdown of the loader: %v", err)
		}
	}
	// stays waits up to 5 s for the result (the kernel detaches a link
	// shortly after its last reference goes), then checks it a few times over
	// two seconds.
	stays := func(denied bool) error {
		start := time.Now()
		for (act() != nil) != denied {
			if time.Since(start) > 5*time.Second {
				return fmt.Errorf("denied=%v after 5s", !denied)
			}
			time.Sleep(100 * time.Millisecond)
		}
		for i := 0; i < 5; i++ {
			if err := act(); (err != nil) != denied {
				return fmt.Errorf("check %d: denied=%v (%v)", i, !denied, err)
			}
			time.Sleep(400 * time.Millisecond)
		}
		return nil
	}

	// watch checks the action in the background until stopped and returns
	// how many checks were allowed, and how many ran.
	watch := func() func() (int, int) {
		var allowed, total int
		done, stopped := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(stopped)
			for {
				select {
				case <-done:
					return
				default:
				}
				if act() == nil {
					allowed++
				}
				total++
				time.Sleep(200 * time.Millisecond)
			}
		}()
		return func() (int, int) { close(done); <-stopped; return allowed, total }
	}

	if err := act(); err != nil {
		t.Fatalf("baseline action failed: %v", err)
	}

	// 1. No pins: the kernel detaches everything when the loader dies.
	cmd := loader("-")
	if act() == nil {
		t.Fatal("loader without pins: action allowed")
	}
	kill(cmd)
	if err := stays(false); err != nil {
		t.Fatalf("without pins the denial must end with the loader: %v", err)
	}

	// 2. Pins: the denial stays after SIGKILL.
	cmd = loader(root)
	if act() == nil {
		t.Fatal("pinning loader: action allowed")
	}
	kill(cmd)
	if err := stays(true); err != nil {
		t.Fatalf("a pinned instance must keep enforcing after SIGKILL: %v", err)
	}

	// 3. Authentication in another process.
	sets, rejected, err := enforcement.LoadPinned(sectionDir, section)
	if err != nil || len(sets) != 1 || len(rejected) != 0 {
		t.Fatalf("pinned set: %+v rejected %v err %v", sets, rejected, err)
	}
	first := sets[0]
	t.Logf("pinned set %s: generation %d, %d links, image digest %q", first.Manifest.Instance, first.Manifest.Generation, len(first.Manifest.Links), first.Manifest.ImageDigest)
	other := sandboxpolicy.SectionFile
	if section == other {
		other = sandboxpolicy.SectionPrivilege
	}
	if _, rejected, _ := enforcement.LoadPinned(sectionDir, other); len(rejected) != 1 {
		t.Fatalf("a set must not be valid for another section: %v", rejected)
	}
	extra, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	extraPin := filepath.Join(first.Dir, "link_99_extra")
	if err := extra.Pin(extraPin); err != nil {
		t.Fatal(err)
	}
	_ = extra.Close()
	if sets, rejected, _ := enforcement.LoadPinned(sectionDir, section); len(sets) != 0 || len(rejected) != 1 {
		t.Fatalf("a set with an unlisted pin must not be valid: %+v %v", sets, rejected)
	}
	if err := os.Remove(extraPin); err != nil {
		t.Fatal(err)
	}
	// Review 8, S6: an unrelated program's link at a listed link name, a
	// lookalike map at a listed map name, and another boot id are each
	// rejected. The originals are held open and pinned back.
	rejectedWith := func(what string, tamper, undo func()) {
		t.Helper()
		tamper()
		sets, rejected, _ := enforcement.LoadPinned(sectionDir, section)
		undo()
		if len(sets) != 0 || len(rejected) != 1 {
			t.Fatalf("a set with %s must not be valid: %+v %v", what, sets, rejected)
		}
		if sets, rejected, _ := enforcement.LoadPinned(sectionDir, section); len(sets) != 1 || len(rejected) != 0 {
			t.Fatalf("the set must be valid again after %s is undone: %+v %v", what, sets, rejected)
		}
	}
	linkPath := filepath.Join(first.Dir, first.Manifest.Links[0].Pin)
	held, err := link.LoadPinnedLink(linkPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	unrelated := unrelatedLink(t)
	rejectedWith("an unrelated program at a listed link name", func() {
		// Unpin, not os.Remove: the library records the pinned path, and a
		// Pin to the recorded path does nothing.
		if err := held.Unpin(); err != nil {
			t.Fatal(err)
		}
		if err := unrelated.Pin(linkPath); err != nil {
			t.Fatal(err)
		}
	}, func() {
		if err := unrelated.Unpin(); err != nil {
			t.Fatal(err)
		}
		if err := held.Pin(linkPath); err != nil {
			t.Fatal(err)
		}
	})
	_ = unrelated.Close()
	_ = held.Close()
	// A plain hash or array state map (a task storage map needs BTF).
	var (
		mapPath string
		heldMap *ebpf.Map
		info    *ebpf.MapInfo
	)
	for _, sm := range first.Manifest.StateMaps {
		m, err := ebpf.LoadPinnedMap(filepath.Join(first.Dir, sm.Pin), nil)
		if err != nil {
			t.Fatal(err)
		}
		if mi, err := m.Info(); err == nil && (mi.Type == ebpf.Hash || mi.Type == ebpf.Array) {
			mapPath, heldMap, info = filepath.Join(first.Dir, sm.Pin), m, mi
			break
		}
		_ = m.Close()
	}
	if heldMap == nil {
		t.Fatal("no hash or array state map to replace")
	}
	lookalike, err := ebpf.NewMap(&ebpf.MapSpec{Type: info.Type, KeySize: info.KeySize, ValueSize: info.ValueSize, MaxEntries: info.MaxEntries, Flags: info.Flags})
	if err != nil {
		t.Fatal(err)
	}
	rejectedWith("a lookalike map at a listed map name", func() {
		if err := heldMap.Unpin(); err != nil {
			t.Fatal(err)
		}
		if err := lookalike.Pin(mapPath); err != nil {
			t.Fatal(err)
		}
	}, func() {
		if err := lookalike.Unpin(); err != nil {
			t.Fatal(err)
		}
		if err := heldMap.Pin(mapPath); err != nil {
			t.Fatal(err)
		}
	})
	_ = lookalike.Close()
	_ = heldMap.Close()
	bootID := first.Manifest.BootID
	rejectedWith("another boot id", func() {
		if err := enforcement.UpdateManifest(first.Dir, func(m *enforcement.PinManifest) { m.BootID = "another-boot" }); err != nil {
			t.Fatal(err)
		}
	}, func() {
		if err := enforcement.UpdateManifest(first.Dir, func(m *enforcement.PinManifest) { m.BootID = bootID }); err != nil {
			t.Fatal(err)
		}
	})

	// 4. Re-adopt: a new loader adopts, settles and is killed. The action
	// stays denied from the loader's start to its settle.
	stop := watch()
	cmd = loader(root)
	allowed, total := stop()
	t.Logf("while the loader adopts and settles: %d of %d checks allowed", allowed, total)
	if allowed != 0 || total == 0 {
		t.Fatalf("protection gap while the loader adopts and settles: %d of %d checks allowed", allowed, total)
	}
	sets, rejected, err = enforcement.LoadPinned(sectionDir, section)
	if err != nil || len(sets) != 1 || len(rejected) != 0 || sets[0].Dir == first.Dir {
		t.Fatalf("after settle only the new loader's set must remain: %+v %v %v", sets, rejected, err)
	}
	if act() == nil {
		t.Fatal("re-adopting loader: action allowed")
	}
	kill(cmd)
	if err := stays(true); err != nil {
		t.Fatalf("the re-adopted state must keep enforcing after SIGKILL: %v", err)
	}

	// 5. Clean shutdown: a third loader adopts, settles and gets SIGTERM.
	stop = watch()
	cmd = loader(root)
	terminate(cmd)
	allowed, total = stop()
	t.Logf("around a clean restart: %d of %d checks allowed", allowed, total)
	if allowed != 0 || total == 0 {
		t.Fatalf("protection gap around a clean restart: %d of %d checks allowed", allowed, total)
	}
	if err := stays(true); err != nil {
		t.Fatalf("a clean shutdown must keep the pinned enforcement: %v", err)
	}
	if sets, rejected, _ := enforcement.LoadPinned(sectionDir, section); len(sets) != 1 || len(rejected) != 0 {
		t.Fatalf("after a clean shutdown one set must remain: %+v %v", sets, rejected)
	}

	// Review 8, B2 and S1: a loader that binds only another cgroup, so the
	// container's binding of the previous run is never bound again, with a
	// short settle deadline and no converged Settle.
	otherCgroup := fmt.Sprintf("kubescape-restart-other-%d-%s", os.Getpid(), section)
	if err := os.Mkdir(filepath.Join("/sys/fs/cgroup", otherCgroup), 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(filepath.Join("/sys/fs/cgroup", otherCgroup))
	unsettled := func(snapshot bool) *exec.Cmd {
		env := []string{restartOtherEnv + "=" + otherCgroup, restartNoSettleEnv + "=1", restartDeadlineEnv + "=3s"}
		if snapshot {
			env = append(env, restartSnapshotEnv+"=1")
		}
		return loaderEnv(root, "enforce", env...)
	}
	latest := func() enforcement.PinnedSet {
		t.Helper()
		sets, _, err := enforcement.LoadPinned(sectionDir, section)
		if err != nil || len(sets) == 0 {
			t.Fatalf("pinned sets: %+v %v", sets, err)
		}
		last := sets[0]
		for _, s := range sets {
			if s.Manifest.RunStart > last.Manifest.RunStart {
				last = s
			}
		}
		return last
	}
	otherImage := func(set enforcement.PinnedSet) {
		t.Helper()
		if err := enforcement.UpdateManifest(set.Dir, func(m *enforcement.PinManifest) { m.ImageDigest = "sha256:another-image" }); err != nil {
			t.Fatal(err)
		}
	}
	exists := func(dir string) bool { _, err := os.Stat(dir); return err == nil }

	// 6. A failed restore (the set was pinned by another image): the new
	// run starts fresh, and past the deadline the old set still binds the
	// container, which has no binding of this run: it is kept (fail closed).
	failed := latest()
	otherImage(failed)
	cmd = unsettled(false)
	if err := stays(true); err != nil {
		t.Fatalf("a failed restore must keep the old set past the deadline: %v", err)
	}
	if !exists(failed.Dir) {
		t.Fatal("a failed restore removed the old set")
	}
	kill(cmd)
	// 7. The same after a complete binding snapshot: the container has no
	// plan, so its policy is gone; every old set is covered and removed.
	otherImage(latest())
	cmd = unsettled(true)
	if err := stays(false); err != nil {
		t.Fatalf("after a complete snapshot the old sets must go: %v", err)
	}
	if sets, _, _ := enforcement.LoadPinned(sectionDir, section); len(sets) != 1 || exists(failed.Dir) {
		t.Fatalf("only the new run's set must remain: %+v", sets)
	}
	kill(cmd)
	// 8. The restored path: a loader binds the container and settles, then
	// a loader that never binds it again keeps the adopted binding past the
	// deadline while no complete snapshot was seen ...
	cmd = loader(root)
	kill(cmd)
	cmd = unsettled(false)
	if err := stays(true); err != nil {
		t.Fatalf("an adopted Strict binding must stay before a complete snapshot: %v", err)
	}
	kill(cmd)
	// ... and drops it after one (its policy is gone).
	cmd = unsettled(true)
	if err := stays(false); err != nil {
		t.Fatalf("an adopted binding with no plan after a complete snapshot must go at the deadline: %v", err)
	}
	kill(cmd)

	// 9. Review 8, S6: the policy turns Audit during the downtime: the next
	// loader adopts, binds the container with the Audit plan and settles;
	// the action runs.
	cmd = loaderPlan(root, "audit")
	if err := stays(false); err != nil {
		t.Fatalf("an Audit policy after the restart must not deny: %v", err)
	}
	kill(cmd)
	// 10. Review 8, B1 and S6: the policy is removed during the downtime: a
	// loader with no plan for the section settles and removes the old sets.
	cmd = loaderPlan(root, "none")
	if sets, _, _ := enforcement.LoadPinned(sectionDir, section); len(sets) != 0 {
		t.Fatalf("a section with no policy must remove the old sets at Settle: %+v", sets)
	}
	if err := stays(false); err != nil {
		t.Fatalf("a removed policy must not deny after Settle: %v", err)
	}
	terminate(cmd)

	// 11. Cleanup.
	if err := enforcement.RemovePinned(root); err != nil {
		t.Fatal(err)
	}
	if err := stays(false); err != nil {
		t.Fatalf("removing the pins must end the denial: %v", err)
	}
	// The kernel frees detached programs asynchronously.
	after := countLSMPrograms(t)
	for i := 0; i < 50 && after != lsmBefore; i++ {
		time.Sleep(100 * time.Millisecond)
		after = countLSMPrograms(t)
	}
	if after != lsmBefore {
		t.Fatalf("LSM programs before %d, after %d", lsmBefore, after)
	}
}

func countLSMPrograms(t *testing.T) int {
	t.Helper()
	n := 0
	var id ebpf.ProgramID
	for {
		next, err := ebpf.ProgramGetNextID(id)
		if err != nil {
			return n
		}
		id = next
		p, err := ebpf.NewProgramFromID(id)
		if err != nil {
			continue
		}
		if info, err := p.Info(); err == nil && info.Type == ebpf.LSM {
			n++
		}
		_ = p.Close()
	}
}

// unrelatedLink attaches a trivial program (a raw tracepoint on sys_enter
// that returns 0) for the authentication test: a link of another program.
func unrelatedLink(t *testing.T) link.Link {
	t.Helper()
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.RawTracepoint, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()
	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_enter", Program: prog})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// connectHelper connects to argv[1]:argv[2] with a 1 s timeout and prints
// "errno=N" (0 when it connected). The network probe counts only EPERM as a
// deny.
const connectHelper = `#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	struct sockaddr_in a = { .sin_family = AF_INET };
	struct timeval tv = { 1, 0 };
	int s, e = 0;

	if (argc != 3) return 3;
	a.sin_port = htons(atoi(argv[2]));
	if (inet_pton(AF_INET, argv[1], &a.sin_addr) != 1) return 3;
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) { printf("errno=%d\n", errno); return 0; }
	setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (connect(s, (struct sockaddr *)&a, sizeof(a))) e = errno;
	printf("errno=%d\n", e);
	return 0;
}
`

// copyConnectHelper builds the connect helper and copies it into the
// container.
func copyConnectHelper(t *testing.T) {
	t.Helper()
	helper := filepath.Join(t.TempDir(), "restart-connect")
	if err := os.WriteFile(helper+".c", []byte(connectHelper), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cc", "-O2", "-static", "-o", helper, helper+".c").CombinedOutput(); err != nil {
		t.Fatalf("build the connect helper: %v: %s", err, out)
	}
	if out, err := exec.Command("docker", "cp", helper, os.Getenv("IG_PRIVILEGE_CONTAINER_ID")+":/restart-connect").CombinedOutput(); err != nil {
		t.Fatalf("copy the connect helper: %v: %s", err, out)
	}
}
