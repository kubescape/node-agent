package containerprofilemanager

import (
	"context"
	"strings"
	"testing"

	"github.com/DmitriyVTitov/size"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

// fakeDNSResolver resolves every address to a fixed domain, so tests can exercise
// createNetworkNeighbor's DNS branch without a real dnsmanager.
type fakeDNSResolver struct{ domain string }

func (f fakeDNSResolver) ResolveIPAddress(string, string) (string, bool) { return f.domain, true }
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

func TestReportSyscallsSizeAccounting(t *testing.T) {
	cpm, entry := newTestManager(t, "container1")

	cpm.ReportSyscalls("container1", []string{"execve"})
	assert.Equal(t, int64(size.Of("execve")), entry.data.size.Load(),
		"size must grow by the syscall's byte size, not by the set's element-count delta")

	// Re-reporting an already-known syscall is a set-dedup no-op and must not grow the estimate.
	cpm.ReportSyscalls("container1", []string{"execve"})
	assert.Equal(t, int64(size.Of("execve")), entry.data.size.Load())

	cpm.ReportSyscalls("container1", []string{"openat"})
	assert.Equal(t, int64(size.Of("execve")+size.Of("openat")), entry.data.size.Load())
}

func TestReportSyscallsBatchInOneCall(t *testing.T) {
	cpm, entry := newTestManager(t, "container1")

	// A single batch call mixing a duplicate ("execve" appears twice) and a genuinely new
	// syscall must dedup within the batch and only charge size for what's actually new.
	cpm.ReportSyscalls("container1", []string{"execve", "execve", "openat"})

	assert.ElementsMatch(t, []string{"execve", "openat"}, entry.data.syscalls.ToSlice())
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
	want := int64(size.Of(networkEvent) + networkNeighborIncrement(entry.data, networkEvent))
	assert.Equal(t, want, entry.data.size.Load(),
		"estimate must include the networkNeighborIncrement surcharge for the identifier/Ports/DNS fields createNetworkNeighbor adds at serialization time")

	// Re-reporting the identical event is a set-dedup no-op and must not grow the estimate.
	cpm.ReportNetworkEvent("container1", event)
	assert.Equal(t, want, entry.data.size.Load())
}

// TestNetworkNeighborIncrementCoversMaxDNSName confirms the report-time estimate does not
// undercount a NetworkNeighbor carrying the longest legal DNS name (RFC 1035 §3.1, 253
// bytes) once DNS resolution actually runs at serialization time.
func TestNetworkNeighborIncrementCoversMaxDNSName(t *testing.T) {
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
	neighbor := cd.createNetworkNeighbor("", networkEvent, "default", nil, fakeDNSResolver{domain: maxDNSName})
	if !assert.NotNil(t, neighbor) {
		return
	}

	estimate := size.Of(networkEvent) + networkNeighborIncrement(cd, networkEvent)
	assert.GreaterOrEqual(t, estimate, size.Of(*neighbor),
		"report-time estimate must cover a resolved NetworkNeighbor with the longest legal DNS name")
}

// TestNetworkNeighborIncrementCoversSelectorPayload confirms the report-time estimate does
// not undercount a NetworkNeighbor whose PodSelector/NamespaceSelector are populated from
// the destination pod's labels at serialization time.
func TestNetworkNeighborIncrementCoversSelectorPayload(t *testing.T) {
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

	// The container's own namespace ("default") differs from the destination's ("other-ns"),
	// so both PodSelector and NamespaceSelector get populated - matching a real cross-namespace
	// neighbor. watchedContainerData.Namespace is what networkNeighborIncrement reads to make
	// the same "different namespace" call createNetworkNeighbor's own namespace arg does below.
	cd := &containerData{watchedContainerData: &objectcache.WatchedContainerData{Namespace: "default"}}
	neighbor := cd.createNetworkNeighbor("", networkEvent, "default", nil, nil)
	if !assert.NotNil(t, neighbor) {
		return
	}

	estimate := size.Of(networkEvent) + networkNeighborIncrement(cd, networkEvent)
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

type trackingDNSResolver struct {
	lastContainerID string
	lastIPAddress   string
}

func (r *trackingDNSResolver) ResolveIPAddress(containerID string, ipAddr string) (string, bool) {
	r.lastContainerID = containerID
	r.lastIPAddress = ipAddr
	return "resolved.domain", true
}

func (r *trackingDNSResolver) ResolveContainerProcessToCloudServices(string, uint32) mapset.Set[string] {
	return nil
}

func TestCreateNetworkNeighbor_EmptyContainerIDWithWatchedContainerData(t *testing.T) {
	cd := &containerData{
		watchedContainerData: &objectcache.WatchedContainerData{
			ContainerID: "watched-container-456",
		},
	}

	networkEvent := NetworkEvent{
		Port:    80,
		PktType: utils.OutgoingPktType,
		Destination: Destination{
			IPAddress: "93.184.216.34",
		},
	}

	resolver := &trackingDNSResolver{}
	neighbor := cd.createNetworkNeighbor("", networkEvent, "default", nil, resolver)
	assert.NotNil(t, neighbor)
	assert.Equal(t, "", resolver.lastContainerID, "empty containerID must be preserved without falling back to watchedContainerData")
	assert.Equal(t, "93.184.216.34", resolver.lastIPAddress)
	assert.Equal(t, "resolved.domain", neighbor.DNS)
}

func TestReportNetworkEventServicePortMultiplicity(t *testing.T) {
	cpm, entry := newTestManager(t, "container1")
	client := &servicePortTestClient{
		service: newServiceWorkload("api", map[string]interface{}{"app": "api"}, map[string]interface{}{
			"name": "web", "port": 80, "targetPort": "http", "protocol": "TCP",
		}),
	}
	var objects []runtime.Object
	for i, port := range []int32{8080, 9090, 10000} {
		objects = append(objects, newEndpointSlice(string(rune('a'+i)), "api", discoveryv1.EndpointPort{
			Name: ptr.To("web"), Port: ptr.To(port),
		}))
	}
	client.kubeClient = fake.NewClientset(objects...)
	cpm.k8sClient = client
	event := &utils.StructEvent{
		DstEndpoint: types.L3Endpoint{Namespace: "default", Name: "api", Kind: types.EndpointKind(EndpointKindService)},
		DstPort:     80, Proto: "tcp", PktType: utils.OutgoingPktType,
	}
	cpm.ReportNetworkEvent("container1", event)
	neighbor := entry.data.createNetworkNeighbor("", serviceNetworkEvent(80, "tcp"), "default", client, nil)
	require.NotNil(t, neighbor)
	require.Equal(t, []int32{8080, 9090, 10000}, networkPortValues(neighbor.Ports))
	// Isolate the port budget so unused selector headroom cannot hide an undercount.
	want := size.Of(serviceNetworkEvent(80, "tcp")) + neighborFixedOverhead +
		maxServiceSelectorEstimate + size.Of(&metav1.LabelSelector{MatchLabels: getNamespaceMatchLabels("default", "")}) + size.Of(neighbor.Ports)
	require.GreaterOrEqual(t, entry.data.size.Load(), int64(want))
	recordedSize := entry.data.size.Load()
	cpm.ReportNetworkEvent("container1", event)
	require.Equal(t, recordedSize, entry.data.size.Load(), "duplicate events must not be charged again")

	// The third port must count toward the split threshold, not just serialization.
	splitManager, splitEntry := newTestManager(t, "container2")
	splitManager.k8sClient = client
	splitManager.cfg.MaxTsProfileSize = int64(want - 1)
	splitEntry.data.watchedContainerData = &objectcache.WatchedContainerData{SyncChannel: make(chan error, 1)}
	splitManager.ReportNetworkEvent("container2", event)
	select {
	case signal := <-splitEntry.data.watchedContainerData.SyncChannel:
		require.Equal(t, ProfileRequiresSplit, signal)
	default:
		t.Fatal("expected profile split after accounting for all three ports")
	}

	// Endpoint changes after reporting must not change the budgeted port list.
	require.NoError(t, client.kubeClient.DiscoveryV1().EndpointSlices("default").Delete(context.Background(), "c", metav1.DeleteOptions{}))
	neighbor = entry.data.createNetworkNeighbor("", serviceNetworkEvent(80, "tcp"), "default", client, nil)
	require.Equal(t, []int32{8080, 9090, 10000}, networkPortValues(neighbor.Ports))

	// A new profile batch resolves fresh ports instead of keeping the old snapshot.
	entry.data.emptyEvents()
	cpm.ReportNetworkEvent("container1", event)
	neighbor = entry.data.createNetworkNeighbor("", serviceNetworkEvent(80, "tcp"), "default", client, nil)
	require.Equal(t, []int32{8080, 9090}, networkPortValues(neighbor.Ports))
	require.Less(t, entry.data.size.Load(), recordedSize)
}
