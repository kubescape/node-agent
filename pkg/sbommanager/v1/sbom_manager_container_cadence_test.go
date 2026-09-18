package v1

import (
	"sync/atomic"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite" // required by syft's RPM cataloger, mirrors sbom_manager.go
)

// Test_ContainerPath_RemainsOneShot is a regression guard for the
// container SBOM cadence.
//
// The container path must stay one-shot plus tool-version-bump reprocessing.
// The host rescan ticker (cfg.HostSBOMRescanInterval,
// hostSbomLoop) is scoped exclusively to the host branch; if a future change
// ever attached it to the container branch -- or made the container path
// re-scan an already-completed SBOM on any other trigger -- the second
// same-version call below would produce a second ReplaceSBOM and this test
// fails.
func Test_ContainerPath_RemainsOneShot(t *testing.T) {
	fake := newFakeSbomClient()
	imageStatus, mounts := testImageStatusWithLayer(t, "quay.io/kubescape/kubevuln:v0.3.2")
	imageTag := "quay.io/kubescape/kubevuln:v0.3.2"
	imageID := "sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a"

	sm := newTestManagerInProcess(fake, "v1.0.0", 1<<30)
	sm.cfg.MaxSBOMSize = 20 * 1024 * 1024
	notif := containercollection.PubSubEvent{
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID:        "container-1",
					ContainerImageName: imageTag,
				},
			},
			K8s: containercollection.K8sMetadata{
				BasicK8sMetadata: types.BasicK8sMetadata{Namespace: "default", PodName: "pod-1", ContainerName: "container-1"},
			},
		},
	}

	// 1. First scan persists the SBOM.
	sm.processContainerWithMetadata(notif, mounts, imageStatus, imageTag, imageID)
	fake.mu.Lock()
	afterFirst := fake.replaceCalls
	fake.mu.Unlock()
	require.Equal(t, 1, afterFirst, "the first container scan must persist an SBOM")

	var sbomName string
	fake.mu.Lock()
	for name := range fake.sboms {
		sbomName = name
	}
	fake.mu.Unlock()
	require.NotEmpty(t, sbomName)
	require.Equal(t, helpersv1.Learning, fake.get(sbomName).Annotations[helpersv1.StatusMetadataKey])

	// 2. Repeated notifications at the same tool version must NOT rescan.
	for range 3 {
		sm.processContainerWithMetadata(notif, mounts, imageStatus, imageTag, imageID)
	}
	fake.mu.Lock()
	afterRepeats := fake.replaceCalls
	fake.mu.Unlock()
	assert.Equal(t, 1, afterRepeats,
		"the container SBOM path must be one-shot: a completed SBOM is never rescanned at the same tool version")

	// 3. A tool-version bump is the ONLY reprocessing trigger.
	bumped := newTestManagerInProcess(fake, "v2.0.0", 1<<30)
	bumped.cfg.MaxSBOMSize = 20 * 1024 * 1024
	bumped.processContainerWithMetadata(notif, mounts, imageStatus, imageTag, imageID)
	fake.mu.Lock()
	afterBump := fake.replaceCalls
	fake.mu.Unlock()
	assert.Equal(t, 2, afterBump, "a tool-version bump must reprocess the container SBOM exactly once")
}

// Test_ContainerCallback_StartsNoRescanLoop is the structural half of the same
// guard: a container notification must never start the host rescan lifecycle.
func Test_ContainerCallback_StartsNoRescanLoop(t *testing.T) {
	cfg := hostCfg("node-1")
	cfg.HostSBOMRescanInterval = 5 * time.Millisecond
	sm, _, _ := newHostSbomManager(t, cfg, t.TempDir())
	sm.appFs = afero.NewMemMapFs()
	sm.procDir = "/proc"

	var hostScans atomic.Int32
	sm.hostScanFn = func(string) { hostScans.Add(1) }

	sm.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID:        "container-1",
					ContainerImageName: "quay.io/kubescape/kubevuln:v0.3.2",
					ContainerPID:       1234,
				},
			},
			K8s: containercollection.K8sMetadata{
				BasicK8sMetadata: types.BasicK8sMetadata{Namespace: "default", PodName: "pod-1", ContainerName: "container-1"},
			},
		},
	})

	time.Sleep(100 * time.Millisecond) // ~20 ticks, had a ticker been started

	assert.Zero(t, hostScans.Load(), "a container must never start the host rescan loop")
	assert.False(t, sm.hostLoopStarted.Load(), "a container must never claim the host SBOM lifecycle")
}
