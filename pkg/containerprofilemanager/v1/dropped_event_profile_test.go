package containerprofilemanager

import (
	"context"
	"testing"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/stretchr/testify/require"
)

// TestReportDroppedEvent_MarksOnlyAffectedProfilePartial covers the profile side of ordered-queue
// overflow accounting: the container watcher reports a drop through ReportDroppedEvent, and the
// next flush of that container's profile must be Partial while an unaffected container stays Full.
func TestReportDroppedEvent_MarksOnlyAffectedProfilePartial(t *testing.T) {
	t.Setenv("QUEUE_DIR", t.TempDir())
	sink := &storage.StorageHttpClientMock{}
	cpm, err := NewContainerProfileManager(context.Background(), config.Config{}, nil, nil,
		sink, nil, &seccompmanager.SeccompManagerMock{}, nil, nil, nil)
	require.NoError(t, err)
	t.Cleanup(cpm.Close)

	register := func(containerID string) *objectcache.WatchedContainerData {
		watched := hostidentity.BuildHostWatchedContainerData("node-1")
		watched.ContainerID = containerID
		watched.SetCompletionStatus(objectcache.WatchedContainerCompletionStatusFull)
		cpm.addContainerEntryIfAbsent(containerID, &ContainerEntry{data: &containerData{watchedContainerData: watched}})
		return watched
	}
	affected := register("affected")
	unaffected := register("unaffected")
	container := hostContainerWithIdentity(newHostPseudoContainer(), affected, "kubescape")

	cpm.ReportDroppedEvent("affected")
	cpm.ReportDroppedEvent("not-registered") // unknown containers are ignored, not an error

	require.NoError(t, cpm.saveProfile(affected, container, true))
	require.NoError(t, cpm.saveProfile(unaffected, container, true))

	require.Equal(t, objectcache.WatchedContainerCompletionStatusPartial, affected.GetCompletionStatus())
	require.Equal(t, objectcache.WatchedContainerCompletionStatusFull, unaffected.GetCompletionStatus())

	require.Eventually(t, func() bool { return len(sink.ContainerProfilesSnapshot()) == 2 }, 8*time.Second, 10*time.Millisecond)
	var completion []string
	for _, p := range sink.ContainerProfilesSnapshot() {
		completion = append(completion, p.Annotations[helpersv1.CompletionMetadataKey])
	}
	require.ElementsMatch(t, []string{string(objectcache.WatchedContainerCompletionStatusPartial), string(objectcache.WatchedContainerCompletionStatusFull)}, completion)
}
