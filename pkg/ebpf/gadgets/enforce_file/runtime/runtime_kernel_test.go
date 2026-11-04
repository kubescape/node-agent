//go:build linux && file_kernel

// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

// Opt-in test of the gadget with Inspektor Gadget alone: it starts the gadget
// from an OCI archive and binds Docker containers through this package's
// operator. Requires root, BPF LSM, cgroup v2, an overlay root file system,
// and disposable containers of a Debian-like image (sh, coreutils), started
// before the test:
//
//	FILE_KERNEL_TEST=1
//	FILE_IMAGE_ARCHIVE       OCI archive from `ig image export`
//	FILE_IMAGE               image name in the archive
//	FILE_CONTAINER_ID        full ID of the container to bind; it should have a
//	                         healthcheck such as `cat /etc/hostname >/dev/null`
//	FILE_CGROUP_PATH         its cgroup v2 path, for example /system.slice/docker-<id>.scope
//	FILE_OTHER_CONTAINER_ID  a container that is never bound
//
// Optional: FILE_BENCH_BINARY, a static open+close loop in the bound container
// (arguments: iterations, path; output: ns per open+close), measures the cost
// with no program loaded, unbound, and bound to a ~50 pattern policy.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"golang.org/x/sys/unix"
	orasoci "oras.land/oras-go/v2/content/oci"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	filepolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/policy"
)

type verdict struct {
	rule              string
	deny, mode, isDef uint32
	access            uint32 // enum file_access; anyAccess: not compared
	path              string
	fromImage         uint32
}

// Values of enum file_access in the verdict event.
const (
	accessRead uint32 = iota
	accessWrite
	accessCreate
	accessDelete
	accessRename
	accessChmod
	accessMoveSource
	anyAccess = 99
)

type kernelFixture struct {
	ctx       context.Context
	id, other string
	container ContainerIdentity
	compiled  filepolicy.Compiled
	bindings  *enforcement.Bindings
	mu        sync.Mutex
	verdicts  []verdict
}

func identity(t *testing.T, runtime, id, cgroupPath string) ContainerIdentity {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join("/sys/fs/cgroup", cgroupPath), &st); err != nil {
		t.Fatal(err)
	}
	return ContainerIdentity{Runtime: runtime, ID: id, CgroupID: st.Ino, CgroupPath: cgroupPath}
}

func newKernelFixture(t *testing.T) *kernelFixture {
	t.Helper()
	if os.Getenv("FILE_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable kernel fixture opt-in required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	t.Cleanup(cancel)
	id := os.Getenv("FILE_CONTAINER_ID")
	return &kernelFixture{ctx: ctx, id: id, other: os.Getenv("FILE_OTHER_CONTAINER_ID"),
		container: identity(t, "docker", id, os.Getenv("FILE_CGROUP_PATH"))}
}

func (f *kernelFixture) start(t *testing.T, compiled filepolicy.Compiled) {
	t.Helper()
	f.compiled = compiled
	store, err := orasoci.NewFromTar(f.ctx, os.Getenv("FILE_IMAGE_ARCHIVE"))
	if err != nil {
		t.Fatal(err)
	}
	rt := local.New()
	if err := rt.Init(nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rt.Close() })
	manager, err := instancemanager.New(rt)
	if err != nil {
		t.Fatal(err)
	}
	handler := ocihandler.New()
	params := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
	if err := params.Set("allow-enforcement", "true"); err != nil {
		t.Fatal(err)
	}
	if err := handler.Init(params); err != nil {
		t.Fatal(err)
	}
	events := simple.New("file-test-verdicts", simple.WithPriority(100), simple.OnInit(func(gc operators.GadgetContext) error {
		var err error
		if f.bindings, err = GetBindings(gc); err != nil {
			return err
		}
		ds := gc.GetDataSources()["verdict"]
		ruleID, deny, mode, isDef := ds.GetField("rule_id"), ds.GetField("deny"), ds.GetField("mode"), ds.GetField("is_default")
		access, path, fromImage := ds.GetField("access_raw"), ds.GetField("path"), ds.GetField("from_image")
		return ds.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
			var v verdict
			r, _ := ruleID.Uint32(data)
			v.deny, _ = deny.Uint32(data)
			v.mode, _ = mode.Uint32(data)
			v.isDef, _ = isDef.Uint32(data)
			v.fromImage, _ = fromImage.Uint32(data)
			v.access, _ = access.Uint32(data)
			v.path, _ = path.String(data)
			if int(r) < len(f.compiled.RuleNames) {
				v.rule = f.compiled.RuleNames[r]
			}
			f.mu.Lock()
			f.verdicts = append(f.verdicts, v)
			f.mu.Unlock()
			return nil
		}, 100)
	}))
	desired := &api.GadgetInstance{Id: "file-kernel-test", GadgetConfig: &api.GadgetRunRequest{Version: api.VersionGadgetRunProtocol,
		ImageName: os.Getenv("FILE_IMAGE")}}
	if err := manager.StartGadget(f.ctx, desired, gadgetcontext.WithOrasReadonlyTarget(store),
		gadgetcontext.WithAdditionalDataOperators(handler, New(), events),
		WithConfig(Config{Policy: compiled})); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.StopGadget(context.Background(), desired.Id) })
}

// sh runs a shell command in a container and returns its exit code and output.
func (f *kernelFixture) sh(t *testing.T, container, cmd string) (int, string) {
	t.Helper()
	out, err := exec.CommandContext(f.ctx, "docker", "exec", container, "sh", "-c", cmd).CombinedOutput()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("docker exec: %v: %s", err, out)
		}
		code = ee.ExitCode()
	}
	return code, strings.TrimSpace(string(out))
}

// ok expects the command to succeed.
func (f *kernelFixture) ok(t *testing.T, container, cmd string) string {
	t.Helper()
	code, out := f.sh(t, container, cmd)
	t.Logf("%.12s: %s -> rc %d %s", container, cmd, code, out)
	if code != 0 {
		t.Errorf("%s: rc %d: %s", cmd, code, out)
	}
	return out
}

// denied expects the command to fail with EPERM.
func (f *kernelFixture) denied(t *testing.T, container, cmd string) {
	t.Helper()
	code, out := f.sh(t, container, cmd)
	t.Logf("%.12s: %s -> rc %d %s", container, cmd, code, out)
	if code == 0 || !strings.Contains(out, "Operation not permitted") {
		t.Errorf("%s: want EPERM, got rc %d: %s", cmd, code, out)
	}
}

// waitVerdict waits for a verdict event that matches want (fields left empty
// in want are not compared, except deny and mode).
func (f *kernelFixture) waitVerdict(t *testing.T, want verdict) {
	t.Helper()
	for i := 0; i < 30; i++ {
		f.mu.Lock()
		for _, v := range f.verdicts {
			if v.rule == want.rule && v.deny == want.deny && v.mode == want.mode &&
				(want.access == anyAccess || v.access == want.access) && (want.path == "" || v.path == want.path) &&
				(want.fromImage == 0 || v.fromImage == 1) {
				f.mu.Unlock()
				return
			}
		}
		f.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	t.Errorf("no verdict event %+v; have %+v", want, f.verdicts)
}

// labDocument is the policy of the matrix: write default deny with a
// workspace, a read deny, agent configuration and image files protected.
func labDocument(name, mode string) filepolicy.Document {
	all := []string{filepolicy.AccessWrite, filepolicy.AccessCreate, filepolicy.AccessDelete, filepolicy.AccessRename, filepolicy.AccessChmod}
	deny := filepolicy.Default{Action: "deny"}
	return filepolicy.Document{Version: 1, Name: name, Policy: filepolicy.Policy{Mode: mode, File: filepolicy.Section{
		Defaults: map[string]filepolicy.Default{filepolicy.AccessRead: {Action: "allow"}, filepolicy.AccessWrite: deny,
			filepolicy.AccessCreate: deny, filepolicy.AccessDelete: deny, filepolicy.AccessRename: deny, filepolicy.AccessChmod: deny},
		Rules: []filepolicy.Rule{
			{Name: "workspace", Action: "allow", Access: all, Paths: []string{"/work/**", "/tmp/**"}},
			{Name: "etc", Action: "allow", Access: all, Paths: []string{"/etc/**"}},
			{Name: "devices", Action: "allow", Access: []string{filepolicy.AccessRead, filepolicy.AccessWrite},
				Paths: []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty", "/dev/ptmx", "/dev/pts/**"}},
			{Name: "secret-read", Action: "deny", Access: []string{filepolicy.AccessRead},
				Paths: []string{"/etc/shadow", "/work/secret/**", "/work/deep/x/**"}},
			{Name: "agent-config", Action: "deny", Access: []string{filepolicy.AccessWrite, filepolicy.AccessCreate, filepolicy.AccessDelete, filepolicy.AccessRename},
				Paths: []string{"**/.claude/**"}, Except: []string{"/work/.claude/ok"}},
			{Name: "image", Action: "deny", Access: []string{filepolicy.AccessWrite, filepolicy.AccessDelete, filepolicy.AccessRename}, FromImage: true},
		},
	}}}
}

// rules50 is the ~50 pattern policy of the cost measurement.
func rules50(t *testing.T) filepolicy.Document {
	t.Helper()
	data, err := os.ReadFile("../policy/testdata/rules50.txt")
	if err != nil {
		t.Fatal(err)
	}
	d := filepolicy.Document{Version: 1, Name: "rules50", Policy: filepolicy.Policy{Mode: "enforce", File: filepolicy.Section{Defaults: map[string]filepolicy.Default{}}}}
	for _, k := range filepolicy.AccessKinds {
		d.Policy.File.Defaults[k] = filepolicy.Default{Action: "allow"}
	}
	d.Policy.File.Defaults[filepolicy.AccessWrite] = filepolicy.Default{Action: "deny"}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || strings.HasPrefix(line, "#") {
			continue
		}
		kinds := map[string][]string{"rw": {filepolicy.AccessRead, filepolicy.AccessWrite}, "read": {filepolicy.AccessRead}, "write": {filepolicy.AccessWrite}}[f[1]]
		d.Policy.File.Rules = append(d.Policy.File.Rules, filepolicy.Rule{Name: fmt.Sprint(len(d.Policy.File.Rules)), Action: f[0], Access: kinds, Paths: []string{f[2]}})
	}
	return d
}

const benchPath = "/work/project/src/main/file.txt"

// bench returns the median ns per open+close of 5 runs in the bound container.
func (f *kernelFixture) bench(t *testing.T) float64 {
	t.Helper()
	bin := os.Getenv("FILE_BENCH_BINARY")
	var runs []float64
	for i := 0; i < 5; i++ {
		out, err := exec.CommandContext(f.ctx, "docker", "exec", f.id, bin, "1000000", benchPath).CombinedOutput()
		if err != nil {
			t.Fatalf("bench: %v: %s", err, out)
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
		if err != nil {
			t.Fatalf("bench output %q", out)
		}
		runs = append(runs, v)
	}
	sort.Float64s(runs)
	return runs[2]
}

func TestGadgetWithInspektorGadgetAlone(t *testing.T) {
	f := newKernelFixture(t)

	// Fixture files, made before the gadget loads: the bound container's
	// writable layer only.
	f.ok(t, f.id, "mkdir -p /work/secret /work/deep/x /work/.claude /work/project/src/main && echo k > /work/secret/key && "+
		"echo f > /work/deep/x/f && echo u > /var/upper.txt && echo b > /work/b && echo a > /work/a && "+
		"echo s > /work/.claude/settings.json && echo o > /work/.claude/ok && echo m > "+benchPath+" && rm -f /newfile")
	var baseline float64
	if os.Getenv("FILE_BENCH_BINARY") != "" {
		baseline = f.bench(t)
		t.Logf("BENCH no program: %.0f ns per open+close", baseline)
	}

	compiled, err := filepolicy.CompileSlots([][]filepolicy.Document{
		{labDocument("lab", "enforce")}, {labDocument("lab-audit", "audit")}, {rules50(t)}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.start(t, compiled)

	if os.Getenv("FILE_BENCH_BINARY") != "" {
		unbound := f.bench(t)
		t.Logf("BENCH loaded, not bound: %.0f ns (%+.0f)", unbound, unbound-baseline)
		if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: 2}); err != nil {
			t.Fatal(err)
		}
		boundNs := f.bench(t)
		t.Logf("BENCH bound, 51 rules: %.0f ns (%+.0f over not bound)", boundNs, boundNs-unbound)
	}

	// Healthchecks from here on run under slot 0 (the bench policy has no
	// /dev/null allow).
	bound := time.Now()
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: 0}); err != nil {
		t.Fatal(err)
	}

	t.Run("read deny", func(t *testing.T) {
		f.denied(t, f.id, "cat /etc/shadow")
		f.ok(t, f.id, "cat /etc/passwd >/dev/null")
		f.waitVerdict(t, verdict{rule: "lab/secret-read", deny: 1, mode: 2, access: accessRead, path: "/etc/shadow"})
	})
	t.Run("write default deny, workspace allow", func(t *testing.T) {
		f.denied(t, f.id, "echo x >> /var/upper.txt")
		f.ok(t, f.id, "echo x >> /work/a && echo y > /tmp/t")
		f.waitVerdict(t, verdict{rule: "default", deny: 1, mode: 2, access: accessWrite, path: "/var/upper.txt"})
	})
	t.Run("create denied at path_mknod", func(t *testing.T) {
		f.denied(t, f.id, "echo x > /newfile")
		f.denied(t, f.id, "mkdir /newdir")
		f.denied(t, f.id, "mkfifo /newfifo")
		f.denied(t, f.id, "ln -s /etc/passwd /newlink")
		f.ok(t, f.id, "test ! -e /newfile && test ! -e /newdir && test ! -e /newfifo && test ! -L /newlink")
		f.ok(t, f.id, "echo x > /work/new && mkdir /work/newdir")
		f.waitVerdict(t, verdict{rule: "default", deny: 1, mode: 2, access: accessCreate, path: "/newfile"})
	})
	t.Run("delete", func(t *testing.T) {
		f.denied(t, f.id, "rm /var/upper.txt")
		f.ok(t, f.id, "rm /work/new && rmdir /work/newdir")
		f.waitVerdict(t, verdict{rule: "default", deny: 1, mode: 2, access: accessDelete, path: "/var/upper.txt"})
	})
	t.Run("rename both ends", func(t *testing.T) {
		f.denied(t, f.id, "mv /work/b /var/b")         // new name
		f.denied(t, f.id, "mv /var/upper.txt /work/u") // old name
		f.ok(t, f.id, "mv /work/b /work/c && mv /work/c /work/b")
		f.ok(t, f.id, "test -e /work/b && test -e /var/upper.txt && test ! -e /var/b && test ! -e /work/u")
	})
	t.Run("chmod", func(t *testing.T) {
		f.denied(t, f.id, "chmod 600 /var/upper.txt")
		f.ok(t, f.id, "chmod 600 /work/a")
		f.waitVerdict(t, verdict{rule: "default", deny: 1, mode: 2, access: accessChmod, path: "/var/upper.txt"})
	})
	t.Run("hard link and rename source guard", func(t *testing.T) {
		// The workspace allows create and rename there; only the guard of
		// the read deny refuses a second name for the protected file.
		f.denied(t, f.id, "ln /work/secret/key /work/key2")
		f.denied(t, f.id, "mv /work/secret/key /work/key3")
		f.ok(t, f.id, "test ! -e /work/key2 && test ! -e /work/key3")
		f.ok(t, f.id, "ln /work/a /work/a2 && rm /work/a2")
		f.waitVerdict(t, verdict{rule: "lab/secret-read", deny: 1, mode: 2, access: accessMoveSource, path: "/work/secret/key"})
	})
	t.Run("parent directory rename guard", func(t *testing.T) {
		f.denied(t, f.id, "mv /work/secret /work/s2")
		f.denied(t, f.id, "mv /work/deep /work/deep2")
		f.ok(t, f.id, "mkdir /work/plain && mv /work/plain /work/plain2 && rmdir /work/plain2")
		f.waitVerdict(t, verdict{rule: "lab/secret-read", deny: 1, mode: 2, access: accessMoveSource, path: "/work/deep"})
	})
	t.Run("agent config except", func(t *testing.T) {
		f.denied(t, f.id, "echo x >> /work/.claude/settings.json")
		f.ok(t, f.id, "echo x >> /work/.claude/ok")
	})
	t.Run("fromImage", func(t *testing.T) {
		// /etc is writable by rule; its image files are not.
		f.denied(t, f.id, "echo x >> /etc/issue")
		f.denied(t, f.id, ": > /etc/debian_version")
		f.ok(t, f.id, "echo x > /etc/upper.conf && echo y >> /etc/upper.conf")
		f.waitVerdict(t, verdict{rule: "lab/image", deny: 1, mode: 2, access: accessWrite, path: "/etc/issue", fromImage: 1})
	})
	t.Run("overlay copy-up", func(t *testing.T) {
		// chmod of an image file under an allow: overlayfs copies it up with
		// internal opens in this task, which are not judged.
		f.ok(t, f.id, "chmod 600 /etc/issue.net && test \"$(stat -c %a /etc/issue.net)\" = 600")
		// Once copied up, the file is no longer an image file.
		f.ok(t, f.id, "echo x >> /etc/issue.net")
	})
	t.Run("unresolved path fails closed", func(t *testing.T) {
		// 16 levels of 250-byte names fit in 4096 bytes, the 17th does not.
		code, out := f.sh(t, f.id, `n=$(printf 'd%.0s' $(seq 250)); cd /work; i=0; while [ $i -lt 17 ]; do mkdir $n 2>&1 || break; cd $n; i=$((i+1)); done; echo levels=$i`)
		t.Logf("long path: rc %d %s", code, out)
		if !strings.Contains(out, "levels=16") || !strings.Contains(out, "Operation not permitted") {
			t.Errorf("want 16 levels then EPERM, got %s", out)
		}
		f.waitVerdict(t, verdict{rule: "unresolved-path", deny: 1, mode: 2, access: accessCreate})
	})
	t.Run("exec and healthcheck under write default deny", func(t *testing.T) {
		f.ok(t, f.id, "true")
		f.ok(t, f.id, "echo hi >/dev/null")
		out, err := exec.CommandContext(f.ctx, "docker", "inspect", "-f", "{{if .State.Health}}{{.State.Health.Status}}{{end}}", f.id).CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) == "" {
			t.Skipf("no healthcheck on the bound container: %s", out)
		}
		since := bound
		time.Sleep(7 * time.Second)
		out, _ = exec.CommandContext(f.ctx, "docker", "inspect", "-f",
			`{{.State.Health.Status}}{{range .State.Health.Log}} {{.Start.UnixNano}}:{{.ExitCode}}{{end}}`, f.id).CombinedOutput()
		t.Logf("health: %s", out)
		fields := strings.Fields(string(out))
		if len(fields) == 0 || fields[0] != "healthy" {
			t.Errorf("container is not healthy: %s", out)
		}
		checked := 0
		for _, entry := range fields[1:] {
			start, code, _ := strings.Cut(entry, ":")
			s, _ := strconv.ParseInt(start, 10, 64)
			if s > since.UnixNano() {
				checked++
				if code != "0" {
					t.Errorf("healthcheck failed while bound: %s", entry)
				}
			}
		}
		if checked == 0 {
			t.Error("no healthcheck ran while bound")
		}
		f.mu.Lock()
		for _, v := range f.verdicts {
			if v.path == "/dev/null" {
				t.Logf("verdict on /dev/null: %+v", v)
			}
		}
		f.mu.Unlock()
	})
	t.Run("unselected container", func(t *testing.T) {
		f.ok(t, f.other, "cat /etc/shadow >/dev/null && echo x > /newfile && rm /newfile && echo x >> /etc/issue")
	})
	t.Run("audit reports without denying", func(t *testing.T) {
		if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: 1}); err != nil {
			t.Fatal(err)
		}
		f.ok(t, f.id, "cat /etc/shadow >/dev/null")
		f.ok(t, f.id, "echo x > /auditfile && rm /auditfile")
		f.waitVerdict(t, verdict{rule: "lab-audit/secret-read", deny: 1, mode: 1, access: accessRead, path: "/etc/shadow"})
		f.waitVerdict(t, verdict{rule: "default", deny: 1, mode: 1, access: accessCreate, path: "/auditfile"})
	})
	t.Run("unbind", func(t *testing.T) {
		if err := f.bindings.Unbind(f.container); err != nil {
			t.Fatal(err)
		}
		f.ok(t, f.id, "cat /etc/shadow >/dev/null && echo x > /newfile && rm /newfile")
	})
	if faults, err := f.bindings.SlotFaults(0); err != nil || faults != 0 {
		t.Errorf("tracking faults: %d %v", faults, err)
	}
}

// workerScript runs one command at a time from /tmp/w.cmd with eval, so a
// builtin with a redirection (read x < FILE, echo x > FILE) opens the file in
// the worker's own task: the same task opens files before and after a binding
// change or a cgroup move.
const workerScript = `while :; do
	if [ -e /tmp/w.cmd ]; then
		read -r c < /tmp/w.cmd
		rm -f /tmp/w.cmd
		eval "$c" > /tmp/w.out 2>&1
		echo $? > /tmp/w.rc
	fi
	sleep 0.05
done`

const workerMarker = "file-test-worker"

type worker struct {
	f   *kernelFixture
	pid int // host pid
}

func cgroupDir(path string) string { return filepath.Join("/sys/fs/cgroup", path) }

// startWorker starts the worker in the bound container and finds its host pid.
func startWorker(t *testing.T, f *kernelFixture) *worker {
	t.Helper()
	if out, err := exec.CommandContext(f.ctx, "docker", "exec", "-d", f.id, "sh", "-c", workerScript, workerMarker).CombinedOutput(); err != nil {
		t.Fatalf("starting worker: %v: %s", err, out)
	}
	for i := 0; i < 50; i++ {
		data, err := os.ReadFile(filepath.Join(cgroupDir(f.container.CgroupPath), "cgroup.procs"))
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range strings.Fields(string(data)) {
			cmdline, _ := os.ReadFile(filepath.Join("/proc", field, "cmdline"))
			args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
			if len(args) == 4 && args[0] == "sh" && args[3] == workerMarker {
				pid, _ := strconv.Atoi(field)
				w := &worker{f: f, pid: pid}
				t.Cleanup(func() { unix.Kill(w.pid, unix.SIGKILL) })
				return w
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("worker not found in the container cgroup")
	return nil
}

// moveTo moves the worker to a cgroup v2 path.
func (w *worker) moveTo(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(cgroupDir(path), "cgroup.procs"), []byte(strconv.Itoa(w.pid)), 0); err != nil {
		t.Fatalf("moving worker to %s: %v", path, err)
	}
	data, _ := os.ReadFile(filepath.Join("/proc", strconv.Itoa(w.pid), "cgroup"))
	t.Logf("worker cgroup: %s", strings.TrimSpace(string(data)))
}

// run runs one command in the worker task and returns its status and output.
func (w *worker) run(t *testing.T, cmd string) (int, string) {
	t.Helper()
	send := exec.CommandContext(w.f.ctx, "docker", "exec", "-i", w.f.id, "sh", "-c", "cat > /tmp/w.cmd.tmp && mv /tmp/w.cmd.tmp /tmp/w.cmd")
	send.Stdin = strings.NewReader(cmd + "\n")
	if out, err := send.CombinedOutput(); err != nil {
		t.Fatalf("sending %q to the worker: %v: %s", cmd, err, out)
	}
	for i := 0; i < 100; i++ {
		code, out := w.f.sh(t, w.f.id, "test -s /tmp/w.rc && cat /tmp/w.rc /tmp/w.out && rm -f /tmp/w.rc")
		if code == 0 {
			lines := strings.SplitN(out, "\n", 2)
			rc, err := strconv.Atoi(strings.TrimSpace(lines[0]))
			if err != nil {
				t.Fatalf("worker status %q", out)
			}
			rest := ""
			if len(lines) == 2 {
				rest = lines[1]
			}
			return rc, rest
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("worker did not run %q", cmd)
	return 0, ""
}

func (w *worker) ok(t *testing.T, cmd string) {
	t.Helper()
	rc, out := w.run(t, cmd)
	t.Logf("worker: %s -> rc %d %s", cmd, rc, out)
	if rc != 0 {
		t.Errorf("worker %s: rc %d: %s", cmd, rc, out)
	}
}

func (w *worker) denied(t *testing.T, cmd string) {
	t.Helper()
	rc, out := w.run(t, cmd)
	t.Logf("worker: %s -> rc %d %s", cmd, rc, out)
	if rc == 0 || !strings.Contains(out, "Operation not permitted") {
		t.Errorf("worker %s: want EPERM, got rc %d: %s", cmd, rc, out)
	}
}

// TestGadgetBindingChanges checks that a binding change or a cgroup move takes
// effect on the next open of a task that already opened files: bind after the
// task ran, moves into child cgroups of the bound container, out of it and
// back, unbind, and bind again.
func TestGadgetBindingChanges(t *testing.T) {
	f := newKernelFixture(t)
	compiled, err := filepolicy.CompileSlots([][]filepolicy.Document{{labDocument("lab", "enforce")}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.start(t, compiled)

	child := filepath.Join(f.container.CgroupPath, "file-test-child")
	grand := filepath.Join(child, "file-test-grand")
	outside := "/file-test-outside"
	for _, p := range []string{child, grand, outside} {
		if err := os.Mkdir(cgroupDir(p), 0o755); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
	}
	w := startWorker(t, f)
	t.Cleanup(func() {
		unix.Kill(w.pid, unix.SIGKILL)
		for _, p := range []string{grand, child, outside} {
			for i := 0; i < 50; i++ {
				if err := os.Remove(cgroupDir(p)); err == nil || os.IsNotExist(err) {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	})

	const readSecret = "read x < /etc/shadow"
	t.Run("unbound task opens files", func(t *testing.T) {
		w.ok(t, readSecret)
		w.ok(t, readSecret)
	})
	t.Run("bind after the task opened files", func(t *testing.T) {
		if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: 0}); err != nil {
			t.Fatal(err)
		}
		w.denied(t, readSecret)
		w.denied(t, "echo x > /file-test-new")
		w.ok(t, "read x < /etc/passwd")
	})
	t.Run("move into a child cgroup of the bound container", func(t *testing.T) {
		w.moveTo(t, child)
		w.denied(t, readSecret)
		w.moveTo(t, grand)
		w.denied(t, readSecret)
	})
	t.Run("move out of the bound container", func(t *testing.T) {
		w.moveTo(t, outside)
		w.ok(t, readSecret)
	})
	t.Run("move into the bound container", func(t *testing.T) {
		w.moveTo(t, grand)
		w.denied(t, readSecret)
		w.moveTo(t, outside)
		w.ok(t, readSecret)
		w.moveTo(t, f.container.CgroupPath)
		w.denied(t, readSecret)
	})
	t.Run("unbind", func(t *testing.T) {
		if err := f.bindings.Unbind(f.container); err != nil {
			t.Fatal(err)
		}
		w.ok(t, readSecret)
		w.moveTo(t, child)
		w.ok(t, readSecret)
		w.ok(t, "echo x > /file-test-new && rm /file-test-new")
	})
	t.Run("bind again", func(t *testing.T) {
		if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: 0}); err != nil {
			t.Fatal(err)
		}
		w.denied(t, readSecret)
		w.moveTo(t, f.container.CgroupPath)
		w.denied(t, readSecret)
		if err := f.bindings.Unbind(f.container); err != nil {
			t.Fatal(err)
		}
		w.ok(t, readSecret)
	})
}
