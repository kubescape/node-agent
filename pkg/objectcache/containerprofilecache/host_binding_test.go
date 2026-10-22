package containerprofilecache

import (
	"context"
	"errors"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
)

func hostBindingCache(t *testing.T, label *string, sourceErr *error) (*ContainerProfileCacheImpl, *countingProfileClient, func() bool) {
	t.Helper()
	client := &countingProfileClient{
		cp:     &v1beta1.ContainerProfile{Name: "learned", Namespace: "kubescape", ResourceVersion: "1", Annotations: map[string]string{helpersv1.StatusMetadataKey: helpersv1.Completed, helpersv1.CompletionMetadataKey: helpersv1.Full}},
		userCP: &v1beta1.ContainerProfile{Name: "authored", Namespace: "kubescape", ResourceVersion: "1"},
	}
	client.cp.Spec.Capabilities = []string{"NET_ADMIN"}
	client.userCP.Spec.Capabilities = []string{"SYS_PTRACE"}
	c, k8s := newTestCache(t, client)
	c.SetHostLabelSource(func(ctx context.Context) (map[string]string, error) {
		_, bounded := ctx.Deadline()
		require.True(t, bounded, "Node reads must have a deadline")
		return map[string]string{helpersv1.UserDefinedProfileMetadataKey: *label}, *sourceErr
	})
	container := hostEventContainer()
	// Match GetHostAsContainer: the runtime does not supply a host name.
	container.Runtime.ContainerName = ""
	container.K8s.Namespace = "kubescape"
	data := hostidentity.BuildHostWatchedContainerData("node-1")
	k8s.SetSharedContainerData(armotypes.HostContainerID, data)
	populate := func() bool {
		populated := c.tryPopulateEntry(context.Background(), armotypes.HostContainerID, container, data, "learned", "host-node-1")
		require.Empty(t, container.Runtime.ContainerName, "cache must not mutate collection metadata")
		return populated
	}
	return c, client, populate
}

func hostBindingEntry(t *testing.T, c *ContainerProfileCacheImpl) *CachedContainerProfile {
	t.Helper()
	entry, ok := c.entries.Load(armotypes.HostContainerID)
	require.True(t, ok)
	return entry
}

func TestHostNodeLabelBindingLifecycle(t *testing.T) {
	label := ""
	var sourceErr error
	c, client, populate := hostBindingCache(t, &label, &sourceErr)
	require.True(t, populate())
	require.Nil(t, hostBindingEntry(t, c).UserCPRef)
	refresh := func() { c.refreshOneEntry(context.Background(), armotypes.HostContainerID, hostBindingEntry(t, c)) }

	label = "authored"
	refresh()
	entry := hostBindingEntry(t, c)
	require.Equal(t, &namespacedName{Namespace: "kubescape", Name: "authored"}, entry.UserCPRef)
	require.Equal(t, "learned", entry.CPName)
	require.Equal(t, map[string]struct{}{"SYS_PTRACE": {}}, entry.Projected.Capabilities.Values)
	require.Equal(t, &objectcache.ProfileState{Name: "authored", Status: helpersv1.Completed, Completion: helpersv1.Full}, entry.State)

	// Repointing must rebuild even when both profiles have the same RV.
	label = "replacement"
	client.userCP = &v1beta1.ContainerProfile{Name: label, Namespace: "kubescape", ResourceVersion: "1", Spec: v1beta1.ContainerProfileSpec{Capabilities: []string{"SYS_ADMIN"}}}
	refresh()
	require.Equal(t, label, hostBindingEntry(t, c).State.Name)
	require.Equal(t, map[string]struct{}{"SYS_ADMIN": {}}, hostBindingEntry(t, c).Projected.Capabilities.Values)

	// A failed Node GET is not evidence that its binding was removed.
	previous := hostBindingEntry(t, c)
	label = ""
	sourceErr = errors.New("Node API unavailable")
	refresh()
	require.Same(t, previous, hostBindingEntry(t, c))
	sourceErr = nil
	refresh()
	require.Nil(t, hostBindingEntry(t, c).UserCPRef)
	require.Equal(t, "learned", hostBindingEntry(t, c).State.Name)
	require.Equal(t, map[string]struct{}{"NET_ADMIN": {}}, hostBindingEntry(t, c).Projected.Capabilities.Values)
}

func TestHostNodeLabelInitialFailureAndRetry(t *testing.T) {
	label := "authored"
	sourceErr := errors.New("Node API unavailable")
	c, _, populate := hostBindingCache(t, &label, &sourceErr)
	require.False(t, populate())
	require.False(t, c.entries.Has(armotypes.HostContainerID))
	sourceErr = nil
	require.True(t, populate())
	require.Equal(t, label, hostBindingEntry(t, c).State.Name)
}

func TestHostNodeLabelRemovalWithoutLearnedProfileRetries(t *testing.T) {
	label := "authored"
	var sourceErr error
	c, client, populate := hostBindingCache(t, &label, &sourceErr)
	client.cp = nil
	require.True(t, populate())
	label = ""
	c.refreshOneEntry(context.Background(), armotypes.HostContainerID, hostBindingEntry(t, c))
	require.False(t, c.entries.Has(armotypes.HostContainerID))
	require.True(t, c.pending.Has(armotypes.HostContainerID))
	label = "authored"
	c.retryPendingEntries(context.Background())
	require.Equal(t, label, hostBindingEntry(t, c).State.Name)
}

func TestHostNodeBindingStorageFailureRetainsPreviousProfile(t *testing.T) {
	for _, target := range []string{"replacement", ""} {
		t.Run("target="+target, func(t *testing.T) {
			label := "authored"
			var sourceErr error
			c, client, populate := hostBindingCache(t, &label, &sourceErr)
			require.True(t, populate())
			previous := hostBindingEntry(t, c)
			failureName := "replacement"
			if target == "" {
				failureName = "learned"
			}
			scripted := &scriptedProfileClient{
				byName:    map[string]*v1beta1.ContainerProfile{"learned": client.cp, "authored": client.userCP},
				errByName: map[string]error{failureName: errors.New("storage unavailable")},
			}
			c.storageClient = scripted
			label = target
			c.refreshOneEntry(context.Background(), armotypes.HostContainerID, previous)
			require.Same(t, previous, hostBindingEntry(t, c))
			require.Equal(t, "authored", previous.UserCPRef.Name)
			require.Equal(t, map[string]struct{}{"SYS_PTRACE": {}}, previous.Projected.Capabilities.Values)
		})
	}
}

func TestHostNodeBindingUnresolvedProfileFallsBackAndRetries(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "learned-instead-of-authored"}[invalid], func(t *testing.T) {
			label := "authored"
			var sourceErr error
			c, client, populate := hostBindingCache(t, &label, &sourceErr)
			require.True(t, populate())
			label = "unresolved"
			if invalid {
				client.userCP = client.cp.DeepCopy()
				client.userCP.Name = label
			}
			c.refreshOneEntry(context.Background(), armotypes.HostContainerID, hostBindingEntry(t, c))
			entry := hostBindingEntry(t, c)
			require.Equal(t, label, entry.UserCPRef.Name)
			require.Equal(t, "learned", entry.State.Name)
			require.Equal(t, map[string]struct{}{"NET_ADMIN": {}}, entry.Projected.Capabilities.Values)
			client.userCP = &v1beta1.ContainerProfile{Name: label, Namespace: "kubescape", ResourceVersion: "2", Spec: v1beta1.ContainerProfileSpec{Capabilities: []string{"SYS_ADMIN"}}}
			c.refreshOneEntry(context.Background(), armotypes.HostContainerID, entry)
			require.Equal(t, map[string]struct{}{"SYS_ADMIN": {}}, hostBindingEntry(t, c).Projected.Capabilities.Values)
		})
	}
}

func TestHostNodeGroupedProfileBindingWithEmptyRuntimeName(t *testing.T) {
	for _, initiallyBound := range []bool{true, false} {
		t.Run(map[bool]string{true: "initial-binding", false: "later-binding"}[initiallyBound], func(t *testing.T) {
			label := ""
			if initiallyBound {
				label = "authored"
			}
			var sourceErr error
			c, client, populate := hostBindingCache(t, &label, &sourceErr)
			client.userCP.Spec = v1beta1.ContainerProfileSpec{
				Containers: []v1beta1.ContainerProfileContainer{
					{Name: "other", Capabilities: []string{"SYS_ADMIN"}},
					{Name: "host", Capabilities: []string{"SYS_PTRACE"}},
				},
			}
			require.True(t, populate())
			require.Equal(t, "host", hostBindingEntry(t, c).ContainerName)
			if !initiallyBound {
				require.Equal(t, map[string]struct{}{"NET_ADMIN": {}}, hostBindingEntry(t, c).Projected.Capabilities.Values)
				label = "authored"
				c.refreshOneEntry(context.Background(), armotypes.HostContainerID, hostBindingEntry(t, c))
			}
			entry := hostBindingEntry(t, c)
			require.Equal(t, &namespacedName{Namespace: "kubescape", Name: "authored"}, entry.UserCPRef)
			require.Equal(t, "authored", entry.State.Name)
			require.Equal(t, map[string]struct{}{"SYS_PTRACE": {}}, entry.Projected.Capabilities.Values)

			// Refresh must retain the normalized name when reselecting the section.
			client.userCP.ResourceVersion = "2"
			client.userCP.Spec.Containers[1].Capabilities = []string{"NET_RAW"}
			c.refreshOneEntry(context.Background(), armotypes.HostContainerID, entry)
			require.Equal(t, map[string]struct{}{"NET_RAW": {}}, hostBindingEntry(t, c).Projected.Capabilities.Values)
		})
	}
}
