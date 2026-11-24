package integration

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

const testPodUID = types.UID("0f3c2a1b-1111-2222-3333-444455556666")

func TestPodCgroupLayout(t *testing.T) {
	u := "0f3c2a1b_1111_2222_3333_444455556666"
	other := types.UID("9e8d7c6b-aaaa-bbbb-cccc-ddddeeeeffff")
	o := "9e8d7c6b_aaaa_bbbb_cccc_ddddeeeeffff"
	for _, tc := range []struct {
		name, container string
		want            map[corev1.PodQOSClass]string
	}{
		{"systemd besteffort", "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + u + ".slice/cri-containerd-abc.scope", map[corev1.PodQOSClass]string{
			corev1.PodQOSBestEffort: "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + o + ".slice",
			corev1.PodQOSBurstable:  "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + o + ".slice",
			corev1.PodQOSGuaranteed: "/kubepods.slice/kubepods-pod" + o + ".slice",
		}},
		{"systemd guaranteed, kind root", "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod" + u + ".slice/cri-containerd-abc.scope", map[corev1.PodQOSClass]string{
			corev1.PodQOSBurstable:  "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod" + o + ".slice",
			corev1.PodQOSGuaranteed: "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod" + o + ".slice",
		}},
		{"cgroupfs burstable", "/kubepods/burstable/pod" + string(testPodUID) + "/abc", map[corev1.PodQOSClass]string{
			corev1.PodQOSBestEffort: "/kubepods/besteffort/pod" + string(other),
			corev1.PodQOSGuaranteed: "/kubepods/pod" + string(other),
		}},
		{"cgroupfs guaranteed", "/kubepods/pod" + string(testPodUID) + "/abc", map[corev1.PodQOSClass]string{
			corev1.PodQOSBurstable: "/kubepods/burstable/pod" + string(other),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout, ok := learnPodCgroupLayout(tc.container, testPodUID)
			if !ok {
				t.Fatalf("layout not learned from %s", tc.container)
			}
			for qos, want := range tc.want {
				if got := layout.path(other, qos); got != want {
					t.Errorf("%s: got %s, want %s", qos, got, want)
				}
			}
			if got := layout.path(other, ""); got != "" {
				t.Errorf("unknown QoS class must give no path: %s", got)
			}
		})
	}
}

func TestPodCgroupLayoutRefusesOtherPaths(t *testing.T) {
	for _, path := range []string{
		"/system.slice/docker-abc.scope",
		"/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podother.slice/cri-containerd-abc.scope",
		"kubepods/pod" + string(testPodUID),
		"/kubepods/../pod" + string(testPodUID),
		"/pod" + string(testPodUID),
	} {
		if layout, ok := learnPodCgroupLayout(path, testPodUID); ok {
			t.Errorf("%s: unexpected layout %+v", path, layout)
		}
	}
	if _, ok := learnPodCgroupLayout("/kubepods/pod"+string(testPodUID), ""); ok {
		t.Error("a container without a pod UID must not give a layout")
	}
	if got := (podCgroupLayout{root: "/kubepods"}).path("a/b", corev1.PodQOSGuaranteed); got != "" {
		t.Errorf("a UID with a separator must give no path: %s", got)
	}
}

// fakeCgroups is a fake host: a /proc with one process, and the cgroup IDs
// of the cgroup paths that exist.
type fakeCgroups struct {
	procRoot string
	ids      map[string]uint64
	asked    []string
}

func newFakeCgroups(t *testing.T, pid string, procCgroup string, ids map[string]uint64) *fakeCgroups {
	t.Helper()
	root := t.TempDir()
	if procCgroup != "" {
		if err := os.MkdirAll(filepath.Join(root, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, pid, "cgroup"), []byte(procCgroup), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &fakeCgroups{procRoot: root, ids: ids}
}

func (f *fakeCgroups) resolver(layout podCgroupLayout, known bool) podCgroupResolver {
	read := func(pid uint32) ([]byte, error) {
		return os.ReadFile(filepath.Join(f.procRoot, strconv.FormatUint(uint64(pid), 10), "cgroup"))
	}
	return podCgroupResolver{layout: layout, layoutKnown: known, readCgroup: read, id: func(path string) (uint64, error) {
		f.asked = append(f.asked, path)
		if id, ok := f.ids[path]; ok {
			return id, nil
		}
		return 0, fs.ErrNotExist
	}}
}

func TestResolvePodCgroup(t *testing.T) {
	u := strings.ReplaceAll(string(testPodUID), "-", "_")
	systemdPod := "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + u + ".slice"
	systemd := podCgroupLayout{root: "/kubepods.slice", systemd: true}
	cgroupfsPod := "/kubepods/besteffort/pod" + string(testPodUID)
	cgroupfs := podCgroupLayout{root: "/kubepods"}
	pause := func(p string) string { return "0::" + p + "/cri-containerd-pause.scope\n" }
	for _, tc := range []struct {
		name       string
		layout     podCgroupLayout
		known      bool
		sandbox    podSandbox
		procCgroup string
		ids        map[string]uint64
		want       string
		wantID     uint64
		wantErr    string
	}{
		{name: "layout and QoS", layout: systemd, known: true,
			sandbox:    podSandbox{UID: testPodUID, QoS: corev1.PodQOSBurstable, PausePID: 42},
			procCgroup: "12:cpu:/ignored\n" + pause(systemdPod), ids: map[string]uint64{systemdPod: 7}, want: systemdPod, wantID: 7},
		{name: "layout, QoS unknown: the pause process picks it", layout: cgroupfs, known: true,
			sandbox:    podSandbox{UID: testPodUID, PausePID: 42},
			procCgroup: pause(cgroupfsPod), ids: map[string]uint64{cgroupfsPod: 9}, want: cgroupfsPod, wantID: 9},
		{name: "pause process in the pod cgroup itself", layout: cgroupfs, known: true,
			sandbox:    podSandbox{UID: testPodUID, QoS: corev1.PodQOSBestEffort, PausePID: 42},
			procCgroup: "0::" + cgroupfsPod + "\n", ids: map[string]uint64{cgroupfsPod: 9}, want: cgroupfsPod, wantID: 9},
		{name: "systemd CgroupParent fallback",
			sandbox:    podSandbox{UID: testPodUID, CgroupParent: "kubepods-burstable-pod" + u + ".slice", PausePID: 42},
			procCgroup: pause(systemdPod), ids: map[string]uint64{systemdPod: 7}, want: systemdPod, wantID: 7},
		{name: "cgroupfs CgroupParent fallback",
			sandbox:    podSandbox{UID: testPodUID, CgroupParent: cgroupfsPod, PausePID: 42},
			procCgroup: pause(cgroupfsPod), ids: map[string]uint64{cgroupfsPod: 9}, want: cgroupfsPod, wantID: 9},
		{name: "layout disagrees with the pause process", layout: systemd, known: true,
			sandbox:    podSandbox{UID: testPodUID, QoS: corev1.PodQOSGuaranteed, CgroupParent: "kubepods-burstable-pod" + u + ".slice", PausePID: 42},
			procCgroup: pause(systemdPod), ids: map[string]uint64{systemdPod: 7}, wantErr: "not under the pod cgroup"},
		{name: "pause process of another pod", layout: cgroupfs, known: true,
			sandbox:    podSandbox{UID: testPodUID, QoS: corev1.PodQOSBestEffort, PausePID: 42},
			procCgroup: pause("/kubepods/besteffort/pod" + string(testPodUID) + "x"), ids: map[string]uint64{cgroupfsPod: 9}, wantErr: "not under the pod cgroup"},
		{name: "no PID", layout: cgroupfs, known: true,
			sandbox: podSandbox{UID: testPodUID, QoS: corev1.PodQOSBestEffort}, ids: map[string]uint64{cgroupfsPod: 9}, wantErr: "no PID"},
		{name: "process gone", layout: cgroupfs, known: true,
			sandbox: podSandbox{UID: testPodUID, QoS: corev1.PodQOSBestEffort, PausePID: 43}, procCgroup: pause(cgroupfsPod), ids: map[string]uint64{cgroupfsPod: 9}, wantErr: "pause process"},
		{name: "path outside the cgroup namespace", layout: cgroupfs, known: true,
			sandbox:    podSandbox{UID: testPodUID, QoS: corev1.PodQOSBestEffort, PausePID: 42},
			procCgroup: "0::/../../kubepods/besteffort/pod" + string(testPodUID) + "/pause\n", ids: map[string]uint64{cgroupfsPod: 9}, wantErr: "not a host path"},
		{name: "cgroup v1 only", layout: cgroupfs, known: true,
			sandbox:    podSandbox{UID: testPodUID, QoS: corev1.PodQOSBestEffort, PausePID: 42},
			procCgroup: "4:memory:" + cgroupfsPod + "\n", ids: map[string]uint64{cgroupfsPod: 9}, wantErr: "no cgroup v2 path"},
		{name: "cgroup gone", layout: cgroupfs, known: true,
			sandbox:    podSandbox{UID: testPodUID, QoS: corev1.PodQOSBestEffort, PausePID: 42},
			procCgroup: pause(cgroupfsPod), wantErr: "file does not exist"},
		{name: "cgroup ID 0", layout: cgroupfs, known: true,
			sandbox:    podSandbox{UID: testPodUID, QoS: corev1.PodQOSBestEffort, PausePID: 42},
			procCgroup: pause(cgroupfsPod), ids: map[string]uint64{cgroupfsPod: 0}, wantErr: "no ID"},
		{name: "no layout, no CgroupParent",
			sandbox:    podSandbox{UID: testPodUID, PausePID: 42},
			procCgroup: pause(cgroupfsPod), ids: map[string]uint64{cgroupfsPod: 9}, wantErr: "neither a path nor a slice"},
		{name: "CgroupParent of another pod",
			sandbox:    podSandbox{UID: testPodUID, CgroupParent: "/kubepods/besteffort/podother", PausePID: 42},
			procCgroup: pause(cgroupfsPod), ids: map[string]uint64{cgroupfsPod: 9}, wantErr: "is not the cgroup of pod"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeCgroups(t, "42", tc.procCgroup, tc.ids)
			got, id, err := f.resolver(tc.layout, tc.known).resolve(tc.sandbox)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("got %s %d %v, want error %q", got, id, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want || id != tc.wantID {
				t.Fatalf("got %s %d %v, want %s %d", got, id, err, tc.want, tc.wantID)
			}
		})
	}
	if _, _, err := (podCgroupResolver{}).resolve(podSandbox{UID: testPodUID, PausePID: 1}); err == nil {
		t.Fatal("a resolver without a cgroup reader must fail")
	}
}

func TestCgroupParentPath(t *testing.T) {
	u := strings.ReplaceAll(string(testPodUID), "-", "_")
	for _, tc := range []struct {
		parent string
		uid    string
		want   string
	}{
		{"kubepods-burstable-pod" + u + ".slice", string(testPodUID), "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + u + ".slice"},
		{"kubepods-pod" + u + ".slice", string(testPodUID), "/kubepods.slice/kubepods-pod" + u + ".slice"},
		{"kubelet-kubepods-besteffort-pod" + u + ".slice", string(testPodUID), "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod" + u + ".slice"},
		{"/kubepods/burstable/pod" + string(testPodUID), string(testPodUID), "/kubepods/burstable/pod" + string(testPodUID)},
		// Refused.
		{"kubepods-burstable-podother.slice", string(testPodUID), ""},
		{"kubepods--pod" + u + ".slice", string(testPodUID), ""},
		{"pod" + u + ".slice", string(testPodUID), ""},
		{"a/kubepods-pod" + u + ".slice", string(testPodUID), ""},
		{"/kubepods/../pod" + string(testPodUID), string(testPodUID), ""},
		{"kubepods/pod" + string(testPodUID), string(testPodUID), ""},
		{"/kubepods/pod" + string(testPodUID), "", ""},
		{"/kubepods/poda/b", "a/b", ""},
	} {
		got, err := cgroupParentPath(tc.parent, types.UID(tc.uid))
		if tc.want == "" {
			if err == nil {
				t.Errorf("%s: got %s, want an error", tc.parent, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: got %s %v, want %s", tc.parent, got, err, tc.want)
		}
	}
}

// The default reader of a resolver is cgroupID, which refuses a directory
// that is not on cgroup v2 (a fake root is not).
func TestCgroupIDRefusesNonCgroupFS(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "kubepods"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := cgroupID(root, "/kubepods"); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a tmpfs directory: %v", err)
	}
	if _, err := cgroupID(root, "/missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a missing directory: %v", err)
	}
}

// The production resolver reads the pause process's cgroup with igbackend's
// pinned initial-cgroupns reader, not a plain read of /proc in node-agent's
// own cgroup namespace: a fake (non-procfs) proc root that a plain read
// accepts is refused.
func TestPodCgroupResolverUsesPinnedReader(t *testing.T) {
	pid := strconv.Itoa(os.Getpid())
	pod := "/kubepods/besteffort/pod" + string(testPodUID)
	f := newFakeCgroups(t, pid, "0::"+pod+"/pause\n", map[string]uint64{pod: 9})
	sandbox := podSandbox{UID: testPodUID, QoS: corev1.PodQOSBestEffort, PausePID: uint32(os.Getpid())}
	layout := podCgroupLayout{root: "/kubepods"}
	if got, id, err := f.resolver(layout, true).resolve(sandbox); err != nil || got != pod || id != 9 {
		t.Fatalf("the plain fake reader accepts the fake root: %s %d %v", got, id, err)
	}
	r := newPodCgroupResolver(layout, true, f.procRoot, f.resolver(layout, true).id)
	if _, _, err := r.resolve(sandbox); err == nil || !strings.Contains(err.Error(), "not procfs") {
		t.Fatalf("the production reader must refuse a non-procfs root: %v", err)
	}
}

func TestReadPauseCgroup(t *testing.T) {
	read := func() ([]byte, error) { return []byte("0::/x\n"), nil }
	if data, err := readPauseCgroup(uint32(os.Getpid()), read); err != nil || string(data) != "0::/x\n" {
		t.Fatalf("live process: %q %v", data, err)
	}
	if _, err := readPauseCgroup(0, read); err == nil {
		t.Fatal("PID 0 must fail")
	}
	if _, err := readPauseCgroup(uint32(os.Getpid()), func() ([]byte, error) { return nil, errors.New("read failed") }); err == nil {
		t.Fatal("a read error must fail")
	}
	// A process that exits (and is reaped) during the read: its PID may
	// name another process by then.
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	pid := uint32(child.Process.Pid)
	_, err := readPauseCgroup(pid, func() ([]byte, error) {
		_ = child.Process.Kill()
		_ = child.Wait()
		return []byte("0::/x\n"), nil
	})
	if err == nil || !strings.Contains(err.Error(), "exited during the read") {
		t.Fatalf("exited during the read: %v", err)
	}
	// Gone before: no pidfd.
	if _, err := readPauseCgroup(pid, read); err == nil {
		t.Fatal("a reaped PID must fail")
	}
}

// Finding G: procRoot must be the procfs of node-agent's PID namespace.
func TestHostPIDNamespace(t *testing.T) {
	if err := HostPIDNamespace("/proc"); err != nil {
		t.Fatalf("this process's /proc: %v", err)
	}
	other := t.TempDir()
	if err := os.Symlink("1", filepath.Join(other, "self")); err != nil {
		t.Fatal(err)
	}
	if err := HostPIDNamespace(other); err == nil || !strings.Contains(err.Error(), "not node-agent's PID namespace") {
		t.Fatalf("another PID namespace: %v", err)
	}
	if err := HostPIDNamespace(t.TempDir()); err == nil {
		t.Fatal("a root without self must fail")
	}
}
