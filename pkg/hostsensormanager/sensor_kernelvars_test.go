//go:build linux

package hostsensormanager

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// fakeProcSysKernel builds <root>/proc/sys/kernel with flatVars regular files
// directly under it plus a "random" sub-directory, and points the sensor's host
// root at <root>.
func fakeProcSysKernel(t *testing.T, flatVars int) {
	t.Helper()
	root := t.TempDir()
	kernelDir := filepath.Join(root, "proc", "sys", "kernel")
	if err := os.MkdirAll(filepath.Join(kernelDir, "random"), 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < flatVars; i++ {
		name := filepath.Join(kernelDir, fmt.Sprintf("var%03d", i))
		if err := os.WriteFile(name, []byte(fmt.Sprintf("%d\n", i)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"boot_id", "uuid", "entropy_avail"} {
		if err := os.WriteFile(filepath.Join(kernelDir, "random", name), []byte("x-"+name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(SetHostFSPrefixForTest(root))
}

// limitOpenFiles lowers RLIMIT_NOFILE to (currently open fds + headroom) for the
// duration of the test.
func limitOpenFiles(t *testing.T, headroom uint64) {
	t.Helper()
	open, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot count open file descriptors: %v", err)
	}
	var orig syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &orig); err != nil {
		t.Skipf("cannot read RLIMIT_NOFILE: %v", err)
	}
	limit := uint64(len(open)) + headroom
	if limit >= orig.Cur {
		t.Skipf("RLIMIT_NOFILE (%d) is already lower than the limit this test needs (%d)", orig.Cur, limit)
	}
	lowered := syscall.Rlimit{Cur: limit, Max: orig.Max}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lowered); err != nil {
		t.Skipf("cannot lower RLIMIT_NOFILE: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &orig) })
}

func senseKernelVars(t *testing.T) []KernelVariable {
	t.Helper()
	got, err := NewLinuxKernelVariablesSensor("node-1").Sense()
	if err != nil {
		t.Fatalf("Sense() error: %v", err)
	}
	spec, ok := got.(*LinuxKernelVariablesSpec)
	if !ok {
		t.Fatalf("Sense() returned %T, want *LinuxKernelVariablesSpec", got)
	}
	if spec.NodeName != "node-1" {
		t.Errorf("NodeName = %q, want node-1", spec.NodeName)
	}
	return spec.KernelVariables
}

func TestKernelVariablesSense_CollectsFilesAndSubdirectories(t *testing.T) {
	fakeProcSysKernel(t, 5)

	vars := senseKernelVars(t)
	if len(vars) != 8 {
		t.Fatalf("got %d variables, want 8 (5 flat + 3 under random/)", len(vars))
	}

	bySource := make(map[string]KernelVariable, len(vars))
	for _, v := range vars {
		bySource[v.Source] = v
	}
	for source, want := range map[string]KernelVariable{
		"/proc/sys/kernel/var003":         {Key: "var003", Value: "3\n", Source: "/proc/sys/kernel/var003"},
		"/proc/sys/kernel/random/boot_id": {Key: "boot_id", Value: "x-boot_id\n", Source: "/proc/sys/kernel/random/boot_id"},
	} {
		if got, ok := bySource[source]; !ok || got != want {
			t.Errorf("variable %s = %+v (present=%v), want %+v", source, got, ok, want)
		}
	}
}

func TestKernelVariablesSense_EmptyDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "proc", "sys", "kernel"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(SetHostFSPrefixForTest(root))

	if vars := senseKernelVars(t); len(vars) != 0 {
		t.Errorf("got %d variables from an empty directory, want 0", len(vars))
	}
}

func TestKernelVariablesSense_MissingProcSysKernel(t *testing.T) {
	t.Cleanup(SetHostFSPrefixForTest(t.TempDir()))

	if _, err := NewLinuxKernelVariablesSensor("node-1").Sense(); err == nil {
		t.Fatal("Sense() succeeded without /proc/sys/kernel, want an error")
	}
}

// Regression test: file handles used to be released with a defer inside the
// per-entry loop, so every /proc/sys file stayed open until its whole directory
// had been read. Reading a directory with more entries than the process has
// spare file descriptors then failed with "too many open files".
func TestKernelVariablesSense_DoesNotHoldFileHandlesAcrossDirectory(t *testing.T) {
	const flatVars = 300
	fakeProcSysKernel(t, flatVars)
	limitOpenFiles(t, 64) // far fewer spare descriptors than the 300+ files read below

	vars := senseKernelVars(t)

	if len(vars) != flatVars+3 {
		t.Fatalf("got %d variables, want %d", len(vars), flatVars+3)
	}
}
