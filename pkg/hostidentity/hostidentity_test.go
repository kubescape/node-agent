package hostidentity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
)

func TestResolveHostID_NodeNamePresent(t *testing.T) {
	cfg := &config.Config{NodeName: "node-1"}

	hostID, err := ResolveHostID(cfg)
	if err != nil {
		t.Fatalf("ResolveHostID() unexpected error = %v", err)
	}
	if hostID != "node-1" {
		t.Fatalf("ResolveHostID() = %q, want %q", hostID, "node-1")
	}
}

func TestResolveHostID_FallsBackToMachineIDWhenNodeNameEmpty(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "etc", "machine-id"), []byte("abc123\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOST_ROOT", tmp)

	cfg := &config.Config{NodeName: ""}

	hostID, err := ResolveHostID(cfg)
	if err != nil {
		t.Fatalf("ResolveHostID() unexpected error = %v", err)
	}
	if hostID != "abc123" {
		t.Fatalf("ResolveHostID() = %q, want %q", hostID, "abc123")
	}
}

func TestResolveHostID_NilConfigFallsBackToMachineID(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "etc", "machine-id"), []byte("def456"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOST_ROOT", tmp)

	hostID, err := ResolveHostID(nil)
	if err != nil {
		t.Fatalf("ResolveHostID() unexpected error = %v", err)
	}
	if hostID != "def456" {
		t.Fatalf("ResolveHostID() = %q, want %q", hostID, "def456")
	}
}

// TestResolveHostID_NeverSilentlyEmpty proves the "never silently return
// empty" invariant: when NodeName is empty and the machine-id file is
// missing, ResolveHostID must return an error, not "", nil.
func TestResolveHostID_NeverSilentlyEmpty(t *testing.T) {
	tmp := t.TempDir() // deliberately no etc/machine-id file underneath
	t.Setenv("HOST_ROOT", tmp)

	cfg := &config.Config{NodeName: ""}

	hostID, err := ResolveHostID(cfg)
	if err == nil {
		t.Fatalf("ResolveHostID() error = nil, want non-nil when both NodeName and machine-id are unavailable")
	}
	if hostID != "" {
		t.Fatalf("ResolveHostID() = %q, want empty string alongside the error", hostID)
	}
}

// TestResolveHostID_NeverSilentlyEmpty_EmptyMachineIDFile covers the case
// where the machine-id file exists but is empty (as opposed to missing).
func TestResolveHostID_NeverSilentlyEmpty_EmptyMachineIDFile(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "etc", "machine-id"), []byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOST_ROOT", tmp)

	cfg := &config.Config{NodeName: ""}

	hostID, err := ResolveHostID(cfg)
	if err == nil {
		t.Fatalf("ResolveHostID() error = nil, want non-nil for an empty machine-id file")
	}
	if hostID != "" {
		t.Fatalf("ResolveHostID() = %q, want empty string alongside the error", hostID)
	}
}

// TestMachineIDHostRoot_DefaultsMatchDeployedMount proves the machine-id
// fallback's default host root is "/host" -- matching the DaemonSet's actual
// mount and pkg/sbommanager/v1's own CreateSbomManager resolution -- not
// hostsensormanager.HostFSPrefix()'s "/host_fs" default, a different fallback
// for the same HOST_ROOT env var that would otherwise make this fallback
// always fail to find /etc/machine-id even though the host filesystem is
// correctly mounted.
func TestMachineIDHostRoot_DefaultsMatchDeployedMount(t *testing.T) {
	if orig, ok := os.LookupEnv("HOST_ROOT"); ok {
		t.Cleanup(func() { _ = os.Setenv("HOST_ROOT", orig) })
	}
	if err := os.Unsetenv("HOST_ROOT"); err != nil {
		t.Fatal(err)
	}

	if got := machineIDHostRoot(); got != "/host" {
		t.Fatalf("machineIDHostRoot() = %q, want %q", got, "/host")
	}
}

func TestBuildHostWlid(t *testing.T) {
	got := BuildHostWlid("node-1")
	want := "wlid://cluster-unknown/namespace-host/host-node-1"
	if got != want {
		t.Fatalf("BuildHostWlid() = %q, want %q", got, want)
	}
}

func TestBuildHostInstanceID(t *testing.T) {
	instanceID := BuildHostInstanceID("node-1")
	if instanceID == nil {
		t.Fatal("BuildHostInstanceID() returned nil")
	}

	if got := instanceID.GetName(); got == "" {
		t.Error("GetName() is empty")
	}
	if got := instanceID.GetContainerName(); got != armotypes.HostContainerID {
		t.Errorf("GetContainerName() = %q, want %q", got, armotypes.HostContainerID)
	}
	if got := instanceID.GetInstanceType(); string(got) == "" {
		t.Error("GetInstanceType() is empty")
	}
	if got := instanceID.GetTemplateHash(); got == "" {
		t.Error("GetTemplateHash() is empty")
	}
	if got := instanceID.GetStringFormatted(); got == "" {
		t.Error("GetStringFormatted() is empty")
	}

	labels := instanceID.GetLabels()
	if len(labels) == 0 {
		t.Fatal("GetLabels() returned no labels")
	}
	// InstanceType and TemplateHash must surface via GetLabels(), so both
	// must be set explicitly.
	if labels[helpersv1.TemplateHashKey] == "" {
		t.Errorf("GetLabels() missing/empty template-hash label, got: %#v", labels)
	}
}

func TestBuildHostWatchedContainerData(t *testing.T) {
	data := BuildHostWatchedContainerData("node-1")
	if data == nil {
		t.Fatal("BuildHostWatchedContainerData() returned nil")
	}

	if data.InstanceID == nil {
		t.Error("InstanceID is nil")
	}
	if data.ContainerID != armotypes.HostContainerID {
		t.Errorf("ContainerID = %q, want %q", data.ContainerID, armotypes.HostContainerID)
	}
	if data.PodName == "" {
		t.Error("PodName is empty")
	}
	if data.Namespace == "" {
		t.Error("Namespace is empty")
	}
	if data.Wlid == "" {
		t.Error("Wlid is empty")
	}
	if data.ParentWorkloadSelector == nil {
		t.Error("ParentWorkloadSelector is nil")
	}
	if data.PreRunningContainer {
		t.Error("PreRunningContainer = true, want false")
	}
	if data.UserDefinedProfile != "" {
		t.Errorf("UserDefinedProfile = %q, want empty string", data.UserDefinedProfile)
	}
}
