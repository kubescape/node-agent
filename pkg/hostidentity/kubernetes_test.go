package hostidentity

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func identityNode() *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-uid")}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{MachineID: "0123456789abcdef0123456789abcdef"}}}
}

func TestResolveKubernetesHostIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, machine, mounted string
		absent, wantError      bool
	}{
		{name: "bare metal", machine: "0123456789abcdef0123456789abcdef", absent: true},
		{name: "normalized match", machine: "0123456789abcdef0123456789abcdef", mounted: "01234567-89AB-CDEF-0123-456789ABCDEF\n"},
		{name: "mismatch", machine: "0123456789abcdef0123456789abcdef", mounted: strings.Repeat("1", 32), wantError: true},
		{name: "malformed mounted", machine: "0123456789abcdef0123456789abcdef", mounted: "bad", wantError: true},
		{name: "node missing despite mount", mounted: "0123456789abcdef0123456789abcdef", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := identityNode()
			node.Status.NodeInfo.MachineID = tc.machine
			identity, err := resolveKubernetesHostIdentity("cluster-uid", "cluster-a", "node-a", node, func(path string) ([]byte, error) {
				require.NotEqual(t, "/etc/machine-id", path)
				if tc.absent {
					return nil, os.ErrNotExist
				}
				return []byte(tc.mounted), nil
			})
			if tc.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NoError(t, identity.Validate())
			require.Empty(t, identity.ProviderID)
		})
	}
}

func TestKubernetesIdentityRestartReplacementAndSlugs(t *testing.T) {
	missing := func(string) ([]byte, error) { return nil, os.ErrNotExist }
	original, err := resolveKubernetesHostIdentity("cluster-uid", "cluster-a", "node-a", identityNode(), missing)
	require.NoError(t, err)
	restart, err := resolveKubernetesHostIdentity("cluster-uid", "cluster-a", "node-a", identityNode(), missing)
	require.NoError(t, err)
	require.Equal(t, original, restart)
	for _, change := range []func(*corev1.Node){func(n *corev1.Node) { n.UID = "new-node" }, func(n *corev1.Node) { n.Status.NodeInfo.MachineID = strings.Repeat("1", 32) }} {
		node := identityNode()
		change(node)
		replacement, err := resolveKubernetesHostIdentity("cluster-uid", "cluster-a", "node-a", node, missing)
		require.NoError(t, err)
		require.NotEqual(t, original.Key, replacement.Key)
		a, err := BuildKubernetesHostWatchedContainerData(original).InstanceID.GetSlug(false)
		require.NoError(t, err)
		b, err := BuildKubernetesHostWatchedContainerData(replacement).InstanceID.GetSlug(false)
		require.NoError(t, err)
		require.NotEqual(t, a, b)
	}
	data := BuildKubernetesHostWatchedContainerData(original)
	child, err := data.InstanceID.GetSlug(false)
	require.NoError(t, err)
	require.NotEmpty(t, child)
	workload, err := data.InstanceID.GetSlug(true)
	require.NoError(t, err)
	require.NotEmpty(t, workload)
	require.NotEqual(t, child, workload)
	require.Contains(t, data.Wlid, "cluster-cluster-a/")
	require.Equal(t, original.Key, objectcache.GetLabels(nil, data, false)[armotypes.KubernetesHostKeyLabel])
	data.ContainerID = "ordinary-pod"
	require.NotContains(t, objectcache.GetLabels(&armotypes.CloudMetadata{KubernetesHostIdentity: &original}, data, false), armotypes.KubernetesHostKeyLabel)
}

func TestKubernetesCoordinatorRetriesAndPublishesCopy(t *testing.T) {
	t.Setenv("HOST_ROOT", t.TempDir())
	var calls atomic.Int32
	c := &KubernetesHostCoordinator{ready: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.resolve(t.Context(), func(context.Context) (string, error) {
			if calls.Add(1) < 4 {
				return "", errors.New("registry pending")
			}
			return "cluster-uid", nil
		}, "cluster-a", "node-a", func(context.Context) (*corev1.Node, error) { return identityNode(), nil }, func(string) ([]byte, error) { return nil, os.ErrNotExist }, time.Millisecond)
	}()
	select {
	case <-c.Ready():
	case <-time.After(time.Second):
		t.Fatal("identity did not recover")
	}
	<-done
	identity, ok := c.Identity()
	require.True(t, ok)
	key := identity.Key
	identity.Key = "mutated"
	again, ok := c.Identity()
	require.True(t, ok)
	require.Equal(t, key, again.Key)
	require.EqualValues(t, 4, calls.Load())
	cfg := &config.Config{RequireKubernetesHostIdentity: true, KubernetesHostIdentity: c, NodeName: "unsafe-fallback"}
	got, err := ResolveHostID(cfg)
	require.NoError(t, err)
	require.Equal(t, key, got)
}

func TestKubernetesCoordinatorCancellationNeverFallsBack(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c := NewKubernetesHostCoordinator(ctx, func(context.Context) (string, error) { t.Error("called after cancellation"); return "", nil }, "cluster-a", "node-a", func(context.Context) (*corev1.Node, error) { return identityNode(), nil })
	_, ok := c.Identity()
	require.False(t, ok)
	_, err := ResolveHostID(&config.Config{RequireKubernetesHostIdentity: true, KubernetesHostIdentity: c, NodeName: "unsafe-fallback"})
	require.Error(t, err)
	select {
	case <-c.Ready():
		t.Fatal("cancelled identity became ready")
	case <-time.After(10 * time.Millisecond):
	}
}

func TestKubernetesCoordinatorRecoversAfterRegistrationTimeout(t *testing.T) {
	t.Setenv("HOST_ROOT", t.TempDir())
	synctest.Test(t, func(t *testing.T) {
		var nodeReady, mountMatches atomic.Bool
		c := &KubernetesHostCoordinator{ready: make(chan struct{})}
		go c.resolve(t.Context(), func(context.Context) (string, error) { return "cluster-uid", nil }, "cluster-a", "node-a", func(context.Context) (*corev1.Node, error) {
			node := identityNode()
			if !nodeReady.Load() {
				node.Status.NodeInfo.MachineID = ""
			}
			return node, nil
		}, func(string) ([]byte, error) {
			if mountMatches.Load() {
				return []byte(identityNode().Status.NodeInfo.MachineID), nil
			}
			return []byte(strings.Repeat("1", 32)), nil
		}, time.Second)
		time.Sleep(11 * time.Minute)
		_, ready := c.Identity()
		require.False(t, ready, "must not fall back after old registration timeout")
		nodeReady.Store(true)
		time.Sleep(time.Minute)
		_, ready = c.Identity()
		require.False(t, ready, "API/mount disagreement must stay pending")
		mountMatches.Store(true)
		time.Sleep(31 * time.Second)
		identity, ready := c.Identity()
		require.True(t, ready)
		require.NoError(t, identity.Validate())
		select {
		case <-c.Ready():
		default:
			t.Fatal("Ready was not published")
		}
	})
}

func TestKubernetesIdentityRejectsContainerLocalMachineID(t *testing.T) {
	for _, root := range []string{"/", "."} {
		t.Run(root, func(t *testing.T) {
			t.Setenv("HOST_ROOT", root)
			_, err := resolveKubernetesHostIdentity("cluster-uid", "cluster-a", "node-a", identityNode(), func(string) ([]byte, error) { t.Fatal("must not read container-local machine-id"); return nil, nil })
			require.Error(t, err)
		})
	}
}
