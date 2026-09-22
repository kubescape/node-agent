package containerprofilecache

import (
	"context"
	"sync"
	"testing"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hostEventContainer builds the host pseudo-container event
// (ContainerPID == 1 is what utils.IsHostContainer keys on).
func hostEventContainer() *containercollection.Container {
	return &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
			ContainerID:   armotypes.HostContainerID,
			ContainerName: "host",
			ContainerPID:  1,
		}},
		K8s: containercollection.K8sMetadata{BasicK8sMetadata: eventtypes.BasicK8sMetadata{
			Namespace: "host",
			PodName:   "host-node-1",
		}},
	}
}

// Test_waitForSharedContainerData_HostDoesNotStall verifies that
// containerprofilecache.go's waitForSharedContainerData is the site the spec
// identifies as PREVIOUSLY STALLING for host — it spun on exponential backoff
// because GetSharedContainerData("host") returned nil forever.
//
// With the synthetic host entry it must resolve immediately, and resolve
// to the host's own identity: a half-populated entry would make addContainer
// fail later on a nil InstanceID rather than stall, which is not a fix.
func Test_waitForSharedContainerData_HostDoesNotStall(t *testing.T) {
	c, k8s := newTestCache(t, &fakeProfileClient{})
	k8s.SetSharedContainerData(armotypes.HostContainerID, hostidentity.BuildHostWatchedContainerData("node-1"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	data, err := c.waitForSharedContainerData(armotypes.HostContainerID, ctx)

	require.NoError(t, err, "host must no longer stall in this wait")
	require.NotNil(t, data)
	assert.Less(t, time.Since(start), time.Second, "must return on the first attempt, not after a backoff cycle")
	assert.Equal(t, armotypes.HostContainerID, data.ContainerID)
	assert.Equal(t, "host-node-1", data.PodName)
	assert.Equal(t, "host", data.Namespace)
	require.NotNil(t, data.InstanceID, "addContainer calls GetOneTimeSlug/GetTemplateHash on this")
	assert.NotEmpty(t, data.InstanceID.GetTemplateHash())
	slug, err := data.InstanceID.GetSlug(false)
	require.NoError(t, err, "the synthetic InstanceID must produce a usable slug for the host CP name")
	assert.NotEmpty(t, slug)
}

// Test_waitForSharedContainerData_HostStillStallsWithoutInjection is the
// negative control proving the test above measures the injection, not the
// clock: without the synthetic host entry the same wait does NOT resolve, and only the
// context deadline ends it.
func Test_waitForSharedContainerData_HostStillStallsWithoutInjection(t *testing.T) {
	c, _ := newTestCache(t, &fakeProfileClient{})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	type result struct {
		data *objectcache.WatchedContainerData
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data, err := c.waitForSharedContainerData(armotypes.HostContainerID, ctx)
		done <- result{data, err}
	}()

	select {
	case r := <-done:
		assert.ErrorIs(t, r.err, context.DeadlineExceeded)
		assert.Nil(t, r.data)
	case <-time.After(3 * time.Second):
		t.Fatal("wait did not honor the context deadline")
	}
}

// TestContainerCallback_HostReachesStorage proves the non-stalling behaviour
// end-to-end through the real ContainerCallback -> addContainer path: with the
// synthetic shared data primed, the host container gets past the wait and
// actually queries storage for its ContainerProfile. Before the host
// identity/synthetic-entry work this never happened — the goroutine parked
// on backoff and no storage call was ever made.
func TestContainerCallback_HostReachesStorage(t *testing.T) {
	client := &signallingProfileClient{
		cp:      &v1beta1.ContainerProfile{Name: "cp", Namespace: "host", ResourceVersion: "1"},
		reached: make(chan struct{}, 1),
	}
	c, k8s := newTestCache(t, client)
	// Host must bypass IgnoreContainer even with every namespace excluded.
	c.cfg.ExcludeNamespaces = []string{"default", "host"}
	k8s.SetSharedContainerData(armotypes.HostContainerID, hostidentity.BuildHostWatchedContainerData("node-1"))

	c.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: hostEventContainer(),
	})

	select {
	case <-client.reached:
	case <-time.After(5 * time.Second):
		t.Fatal("host container never reached storage: the shared-data wait is still stalling")
	}
}

// signallingProfileClient signals the first time GetContainerProfile is called,
// so the test can observe the storage call without racing on a plain counter.
type signallingProfileClient struct {
	cp      *v1beta1.ContainerProfile
	reached chan struct{}
	once    sync.Once
}

var _ storage.ProfileClient = (*signallingProfileClient)(nil)

func (c *signallingProfileClient) GetContainerProfile(_ context.Context, _, _ string) (*v1beta1.ContainerProfile, error) {
	c.once.Do(func() { close(c.reached) })
	return c.cp, nil
}

// The cache queries the same stable child identity the producer consolidates,
// stays pending while learning, and never reuses a predecessor on replacement.
func TestKubernetesHostGenerationCacheLifecycle(t *testing.T) {
	identity := armotypes.KubernetesHostIdentity{Version: 1, ClusterUID: "cluster-uid", ClusterName: "cluster-a", NodeUID: "node-uid", NodeName: "node-a"}
	var err error
	identity.MachineFingerprint, err = armotypes.KubernetesHostMachineFingerprint("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	identity.Key, err = armotypes.KubernetesHostKey(identity.ClusterUID, identity.NodeUID, identity.MachineFingerprint)
	require.NoError(t, err)
	data := hostidentity.BuildKubernetesHostWatchedContainerData(identity)
	child, err := data.InstanceID.GetSlug(false)
	require.NoError(t, err)
	cp := &v1beta1.ContainerProfile{Name: child, Namespace: "kubescape", ResourceVersion: "1", Annotations: map[string]string{helpersv1.StatusMetadataKey: helpersv1.Learning, helpersv1.CompletionMetadataKey: helpersv1.Full}, Spec: v1beta1.ContainerProfileSpec{Syscalls: []string{"openat"}}}
	client := &generationProfileClient{t: t, profiles: map[string]*v1beta1.ContainerProfile{child: cp}}
	c, k8s := newTestCache(t, client)
	c.cfg.NamespaceName = "kubescape"
	c.SetProjectionSpec(objectcache.RuleProjectionSpec{Hash: "syscalls", Syscalls: objectcache.FieldSpec{InUse: true, All: true}})
	k8s.SetSharedContainerData(armotypes.HostContainerID, data)
	// addContainer is the synchronous part of the callback, after its namespace
	// rewrite. Running it directly makes reconciliation assertions deterministic.
	container := hostEventContainer()
	container.K8s.Namespace = c.cfg.NamespaceName
	require.NoError(t, c.addContainer(container, t.Context()))
	require.Nil(t, c.GetProjectedContainerProfile(armotypes.HostContainerID))
	require.Equal(t, 1, c.pending.Len())
	cp.Annotations[helpersv1.StatusMetadataKey] = helpersv1.Completed
	c.retryPendingEntries(t.Context())
	actual := c.GetProjectedContainerProfile(armotypes.HostContainerID)
	require.NotNil(t, actual)
	require.Contains(t, actual.Syscalls.Values, "openat")
	require.NotContains(t, actual.Syscalls.Values, "execve")
	require.Equal(t, child, c.GetContainerProfileState(armotypes.HostContainerID).Name)
	// A new cache after restart reloads exactly this eligible child.
	restart, restartK8s := newTestCache(t, client)
	restartK8s.SetSharedContainerData(armotypes.HostContainerID, hostidentity.BuildKubernetesHostWatchedContainerData(identity))
	require.NoError(t, restart.addContainer(container, t.Context()))
	require.NotNil(t, restart.GetProjectedContainerProfile(armotypes.HostContainerID))
	identity.NodeUID = "replacement-node"
	identity.Key, err = armotypes.KubernetesHostKey(identity.ClusterUID, identity.NodeUID, identity.MachineFingerprint)
	require.NoError(t, err)
	replacement, replacementK8s := newTestCache(t, client)
	replacementK8s.SetSharedContainerData(armotypes.HostContainerID, hostidentity.BuildKubernetesHostWatchedContainerData(identity))
	require.NoError(t, replacement.addContainer(container, t.Context()))
	require.Nil(t, replacement.GetProjectedContainerProfile(armotypes.HostContainerID))
	require.Equal(t, 1, replacement.pending.Len())
	require.Contains(t, client.profiles, child, "predecessor retained")
}

type generationProfileClient struct {
	t        *testing.T
	profiles map[string]*v1beta1.ContainerProfile
}

func (c *generationProfileClient) GetContainerProfile(_ context.Context, namespace, name string) (*v1beta1.ContainerProfile, error) {
	require.Equal(c.t, "kubescape", namespace)
	if cp, ok := c.profiles[name]; ok {
		return cp, nil
	}
	return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "containerprofiles"}, name)
}
