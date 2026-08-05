package containerprofilemanager

import (
	"testing"

	"github.com/DmitriyVTitov/size"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
)

// newTestManager builds a ContainerProfileManager with a single, pre-registered
// container entry, large enough MaxTsProfileSize that these tests never trip the
// split path, and no watchedContainerData - so a threshold crossing is a no-op
// instead of blocking on an unbuffered SyncChannel send.
func newTestManager(t *testing.T, containerID string) (*ContainerProfileManager, *ContainerEntry) {
	t.Helper()
	cpm := &ContainerProfileManager{
		cfg:        config.Config{MaxTsProfileSize: 10 * 1024 * 1024},
		containers: map[string]*ContainerEntry{},
	}
	entry := &ContainerEntry{data: &containerData{}}
	cpm.addContainerEntry(containerID, entry)
	return cpm, entry
}

func TestReportSyscallSizeAccounting(t *testing.T) {
	cpm, entry := newTestManager(t, "container1")

	cpm.ReportSyscall("container1", "execve")
	assert.Equal(t, int64(size.Of("execve")), entry.data.size.Load(),
		"size must grow by the syscall's byte size, not by the set's element-count delta")

	// Re-reporting an already-known syscall is a set-dedup no-op and must not grow the estimate.
	cpm.ReportSyscall("container1", "execve")
	assert.Equal(t, int64(size.Of("execve")), entry.data.size.Load())

	cpm.ReportSyscall("container1", "openat")
	assert.Equal(t, int64(size.Of("execve")+size.Of("openat")), entry.data.size.Load())
}

func TestReportNetworkEventSizeAccounting(t *testing.T) {
	cpm, entry := newTestManager(t, "container1")

	event := &utils.StructEvent{
		DstEndpoint: types.L3Endpoint{
			Addr: "10.0.0.5",
		},
		DstPort: 8080,
		Proto:   "tcp",
		PktType: utils.OutgoingPktType,
	}

	cpm.ReportNetworkEvent("container1", event)

	networkEvent := NetworkEvent{
		Port:     8080,
		Protocol: "tcp",
		PktType:  utils.OutgoingPktType,
		Destination: Destination{
			IPAddress: "10.0.0.5",
		},
	}
	want := int64(size.Of(networkEvent) + networkNeighborExpansionEstimate)
	assert.Equal(t, want, entry.data.size.Load(),
		"estimate must include the networkNeighborExpansionEstimate surcharge for the DNS/selector/identifier fields createNetworkNeighbor adds at serialization time")

	// Re-reporting the identical event is a set-dedup no-op and must not grow the estimate.
	cpm.ReportNetworkEvent("container1", event)
	assert.Equal(t, want, entry.data.size.Load())
}

func TestResolveExecPath(t *testing.T) {
	tests := []struct {
		name    string
		exepath string
		comm    string
		args    []string
		want    string
	}{
		{
			name:    "exepath present (canonical exec)",
			exepath: "/usr/sbin/unix_chkpwd",
			comm:    "unix_chkpwd",
			args:    []string{"/usr/sbin/unix_chkpwd", "root"},
			want:    "/usr/sbin/unix_chkpwd",
		},
		{
			name:    "fexecve / execveat AT_EMPTY_PATH — pathname empty, argv[0] non-empty",
			exepath: "",
			comm:    "unix_chkpwd",
			args:    []string{"unix_chkpwd", "root"},
			want:    "unix_chkpwd",
		},
		{
			name:    "fexecve with empty argv[0] (older PAM convention)",
			exepath: "",
			comm:    "unix_chkpwd",
			args:    []string{"", "root"},
			want:    "unix_chkpwd",
		},
		{
			name:    "no exepath, no args — fall back to comm",
			exepath: "",
			comm:    "some_proc",
			args:    nil,
			want:    "some_proc",
		},
		{
			name:    "exepath wins even when argv[0] disagrees (argv[0] spoofing)",
			exepath: "/usr/bin/curl",
			comm:    "curl",
			args:    []string{"sshd", "-i"},
			want:    "/usr/bin/curl",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveExecPath(tt.exepath, tt.comm, tt.args)
			if got != tt.want {
				t.Errorf("resolveExecPath(%q, %q, %v) = %q, want %q", tt.exepath, tt.comm, tt.args, got, tt.want)
			}
		})
	}
}
