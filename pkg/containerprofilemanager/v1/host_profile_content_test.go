package containerprofilemanager

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHostContainerProfile_ContentPopulated is the acceptance-criterion
// automated proof that a ContainerProfile CR for host actually carries
// runtime-behavior data once produced -- not just an empty shell reaching
// storage.
//
// This is a strictly stronger claim than
// TestContainerCallback_HostReachesStorage's (pkg/objectcache/
// containerprofilecache/host_shared_data_test.go): that test only exercises
// the READ/overlay cache path (GetContainerProfile being called at all). This
// test drives real events (exec/open/syscall/capability) through this
// package's WRITE path -- ContainerProfileManager, the component that
// actually assembles and submits the CR -- for the host pseudo-container, and
// asserts on the resulting CR's Spec content.
//
// It also caught a real bug while being written: hostidentity.
// BuildHostWatchedContainerData did not set ContainerInfos/ContainerIndex,
// which monitoring.go's saveContainerProfile unconditionally indexes when
// assembling the CR -- host's first save panicked on a nil-map/out-of-range
// index. Fixed alongside this test (see pkg/hostidentity/hostidentity.go).
func TestHostContainerProfile_ContentPopulated(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "host-profile-queue-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	t.Setenv("QUEUE_DIR", tempDir)

	cfg := config.Config{
		// Long enough that the automatic UpdateDataTicker in monitorContainer
		// cannot fire during this test's window and race an extra
		// status-transition-only save in ahead of the explicit forced save
		// below (monitorContainer's first tick always saves once, even with
		// no behavior data yet, because isEmpty() also compares
		// lastReportedStatus/-Completion -- that is real, correct product
		// behavior, just not what this test is trying to isolate).
		InitialDelay:        time.Minute,
		UpdateDataPeriod:    time.Minute,
		MaxSniffingTime:     time.Hour, // must not fire during this test
		MaxJitterPercentage: 0,
		MaxTsProfileSize:    10 * 1024 * 1024,
	}

	k8sObjectCacheMock := &objectcache.K8sObjectCacheMock{}
	hostData := hostidentity.BuildHostWatchedContainerData("node-1")
	k8sObjectCacheMock.SetSharedContainerData(armotypes.HostContainerID, hostData)

	storageClient := &storage.StorageHttpClientMock{}

	cpm, err := NewContainerProfileManager(
		context.Background(),
		cfg,
		&k8sclient.K8sClientMock{},
		k8sObjectCacheMock,
		storageClient,
		&dnsmanager.DNSManagerMock{},
		&seccompmanager.SeccompManagerMock{},
		nil,
		nil,
		nil,
	)
	require.NoError(t, err)
	defer cpm.Close()

	hostContainer := newHostPseudoContainer()

	cpm.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: hostContainer,
	})

	// Shared data is already primed, so addContainer resolves near-instantly.
	// Wait for the container entry to exist (the entry itself is created
	// synchronously in addContainerEntry, but ContainerCallback dispatches
	// addContainerWithTimeout on its own goroutine), then wait on the entry's
	// ready channel rather than polling its internal fields directly: addContainer
	// writes watchedContainerData and other shared fields (via setContainerData)
	// from its own goroutine and only closes ready once that is done, so
	// synchronizing on the channel (instead of racily reading entry.data.* from
	// the test goroutine) gives us the required happens-before relationship.
	var entry *ContainerEntry
	require.Eventually(t, func() bool {
		e, ok := cpm.getContainerEntry(armotypes.HostContainerID)
		if !ok {
			return false
		}
		entry = e
		return true
	}, 2*time.Second, 10*time.Millisecond, "host container entry was never created in the profile manager")

	select {
	case <-entry.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("host container was never fully registered in the profile manager")
	}

	// Drive realistic runtime-behavior events through the host pipeline.
	cpm.ReportFileExec(armotypes.HostContainerID, &utils.StructEvent{
		ExePath: "/usr/bin/systemd",
		Comm:    "systemd",
		Args:    []string{"/usr/bin/systemd", "--switched-root"},
	})
	cpm.ReportFileOpen(armotypes.HostContainerID, &utils.StructEvent{
		Path:  "/etc/passwd",
		Flags: []string{"O_RDONLY"},
	})
	cpm.ReportSyscalls(armotypes.HostContainerID, []string{"execve", "openat"})
	cpm.ReportCapability(armotypes.HostContainerID, "CAP_SYS_ADMIN")

	// Force an immediate save (mirrors the termination/max-time forced-save
	// callers already in monitoring.go) rather than waiting on the real
	// UpdateDataTicker, whose exact fire time is not worth racing. This call
	// bypasses addContainer (which already applied hostContainerWithIdentity
	// to the container it passes to startContainerMonitoring), so apply the
	// same patch here -- otherwise this direct save would use the raw,
	// empty-K8s hostContainer and this test's own Namespace assertion below
	// would no longer be exercising what production actually saves.
	require.NoError(t, cpm.saveProfile(hostData, hostContainerWithIdentity(hostContainer, hostData), true))

	// The queue is disk-backed; the storage client is only invoked from the
	// queue's own background processing loop, so poll for delivery instead of
	// asserting synchronously. Use the snapshot accessor rather than reading
	// ContainerProfiles directly, since CreateContainerProfileDirect can still
	// be writing to it concurrently from that background goroutine.
	var profiles []*v1beta1.ContainerProfile
	require.Eventually(t, func() bool {
		profiles = storageClient.ContainerProfilesSnapshot()
		return len(profiles) > 0
	}, 8*time.Second, 100*time.Millisecond, "host ContainerProfile was never delivered to storage")

	require.Len(t, profiles, 1)
	cr := profiles[0]

	assert.Equal(t, "host", cr.Namespace)
	assert.NotEmpty(t, cr.Name)

	assert.NotEmpty(t, cr.Spec.Execs, "host CR must carry real exec data, not an empty shell")
	assert.NotEmpty(t, cr.Spec.Opens, "host CR must carry real open data, not an empty shell")
	assert.NotEmpty(t, cr.Spec.Syscalls, "host CR must carry real syscall data, not an empty shell")
	assert.NotEmpty(t, cr.Spec.Capabilities, "host CR must carry real capability data, not an empty shell")
}
