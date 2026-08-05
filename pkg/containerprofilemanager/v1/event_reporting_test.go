package containerprofilemanager

import (
	"strings"
	"testing"

	"github.com/DmitriyVTitov/size"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
)

// fakeDNSResolver resolves every address to a fixed domain, so tests can exercise
// createNetworkNeighbor's DNS branch without a real dnsmanager.
type fakeDNSResolver struct{ domain string }

func (f fakeDNSResolver) ResolveIPAddress(string) (string, bool) { return f.domain, true }
func (f fakeDNSResolver) ResolveContainerProcessToCloudServices(string, uint32) mapset.Set[string] {
	return nil
}

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

// TestNetworkNeighborExpansionEstimateCoversMaxDNSName confirms the report-time estimate
// does not undercount a NetworkNeighbor carrying the longest legal DNS name (RFC 1035
// §3.1, 253 bytes) once DNS resolution actually runs at serialization time.
func TestNetworkNeighborExpansionEstimateCoversMaxDNSName(t *testing.T) {
	maxDNSName := strings.Repeat("a", 253)

	networkEvent := NetworkEvent{
		Port:     443,
		Protocol: "tcp",
		PktType:  utils.OutgoingPktType,
		Destination: Destination{
			Kind:      EndpointKindRaw,
			IPAddress: "203.0.113.10",
		},
	}

	cd := &containerData{}
	neighbor := cd.createNetworkNeighbor(networkEvent, "default", nil, fakeDNSResolver{domain: maxDNSName})
	if !assert.NotNil(t, neighbor) {
		return
	}

	estimate := size.Of(networkEvent) + networkNeighborExpansionEstimate
	assert.GreaterOrEqual(t, estimate, size.Of(*neighbor),
		"report-time estimate must cover a resolved NetworkNeighbor with the longest legal DNS name")
}

// TestNetworkNeighborExpansionEstimateCoversSelectorPayload confirms the report-time
// estimate does not undercount a NetworkNeighbor whose PodSelector/NamespaceSelector are
// populated from the destination pod's labels at serialization time.
func TestNetworkNeighborExpansionEstimateCoversSelectorPayload(t *testing.T) {
	podLabels := map[string]string{
		"app.kubernetes.io/name":       "web",
		"app.kubernetes.io/instance":   "web-abc123",
		"app.kubernetes.io/version":    "1.4.2",
		"app.kubernetes.io/component":  "frontend",
		"app.kubernetes.io/part-of":    "shop",
		"app.kubernetes.io/managed-by": "helm",
	}

	networkEvent := NetworkEvent{
		Port:     8080,
		Protocol: "tcp",
		PktType:  utils.OutgoingPktType,
		Destination: Destination{
			Kind:      EndpointKindPod,
			Namespace: "other-ns",
			Name:      "web",
		},
	}
	networkEvent.SetDestinationPodLabels(podLabels)

	cd := &containerData{}
	// namespace "default" differs from the destination's "other-ns", so both PodSelector and
	// NamespaceSelector get populated - matching a real cross-namespace neighbor.
	neighbor := cd.createNetworkNeighbor(networkEvent, "default", nil, nil)
	if !assert.NotNil(t, neighbor) {
		return
	}

	estimate := size.Of(networkEvent) + networkNeighborExpansionEstimate
	assert.GreaterOrEqual(t, estimate, size.Of(*neighbor),
		"report-time estimate must cover a NetworkNeighbor with a populated selector payload")
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
