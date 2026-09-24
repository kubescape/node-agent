package containerwatcher

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	runtimeconfig "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type blockedNamespaceRuntime struct {
	runtimeapi.UnimplementedRuntimeServiceServer
	entered chan struct{}
	active  atomic.Int32
}

func (s *blockedNamespaceRuntime) ContainerStatus(ctx context.Context, _ *runtimeapi.ContainerStatusRequest) (*runtimeapi.ContainerStatusResponse, error) {
	s.active.Add(1)
	defer s.active.Add(-1)
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func namespaceBlockedRuntimeWatcher(t *testing.T) (*ContainerWatcher, *blockedNamespaceRuntime, func(string)) {
	t.Helper()
	// Unix socket paths must fit sockaddr_un, independently of the test name.
	dir, err := os.MkdirTemp("", "na-cri-")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "runtime.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	server := grpc.NewServer()
	service := &blockedNamespaceRuntime{entered: make(chan struct{}, 10)}
	runtimeapi.RegisterRuntimeServiceServer(server, service)
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	path := filepath.Join(dir, "filter.json")
	write := func(contents string) { t.Helper(); require.NoError(t, os.WriteFile(path, []byte(contents), 0600)) }
	write(`{"includeNamespaces":[],"excludeNamespaces":["payments"]}`)
	cfg := config.Config{NamespaceFilterFile: path, NodeName: "node-one"}
	require.NoError(t, cfg.InitializeNamespaceFilter())
	pod := &corev1.Pod{Name: "pay", Namespace: "payments", Spec: corev1.PodSpec{NodeName: "node-one"}, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "app", ContainerID: "containerd://late", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	cw := &ContainerWatcher{
		cfg: cfg, containerCollection: &containercollection.ContainerCollection{},
		k8sClient:   &k8sinterface.KubernetesApi{KubernetesClient: fake.NewClientset(pod)},
		objectCache: &countingObjectCache{k8sCache: &countingK8sObjectCache{}},
		runtime:     &runtimeconfig.RuntimeConfig{Name: igtypes.RuntimeNameContainerd, SocketPath: socket, RuntimeProtocol: runtimeconfig.RuntimeProtocolCRI},
	}
	return cw, service, write
}

func TestNamespaceFilterBlockedRuntimeDoesNotBlockExclusionOrShutdown(t *testing.T) {
	cw, runtime, write := namespaceBlockedRuntimeWatcher(t)
	cw.containerCollection.AddContainer(makeTestContainer("existing", "default", "web", "app", 1))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ticks := make(chan time.Time)
	done := make(chan struct{})
	go func() { defer close(done); cw.watchNamespaceFilter(ctx, ticks) }()
	write(`{"includeNamespaces":[],"excludeNamespaces":[]}`)
	ticks <- time.Now()
	select {
	case <-runtime.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("runtime request did not start")
	}
	write(`{"includeNamespaces":[],"excludeNamespaces":["default"]}`)
	select {
	case ticks <- time.Now():
	case <-time.After(time.Second):
		t.Fatal("blocked CRI froze filter publication")
	}
	require.Eventually(t, func() bool {
		return cw.cfg.SkipNamespace("default") && cw.containerCollection.GetContainer("existing") == nil
	}, time.Second, time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown waited for unresponsive runtime")
	}
	require.Eventually(t, func() bool { return runtime.active.Load() == 0 }, time.Second, time.Millisecond, "the RPC must actually be canceled, not abandoned in a goroutine")
	require.Nil(t, cw.containerCollection.GetContainer("late"))
}

func TestNamespaceFilterRuntimeDiscoveryHonorsDeadline(t *testing.T) {
	cw, runtime, write := namespaceBlockedRuntimeWatcher(t)
	previous := cw.cfg.NamespaceFilterSnapshot()
	write(`{"includeNamespaces":[],"excludeNamespaces":[]}`)
	_, err := cw.cfg.ReloadNamespaceFilter()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := cw.runningContainersForNamespace(ctx, previous); result <- err }()
	select {
	case <-runtime.entered:
	case <-time.After(time.Second):
		t.Fatal("runtime request did not start")
	}
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("runtime discovery ignored its deadline")
	}
	require.Eventually(t, func() bool { return runtime.active.Load() == 0 }, time.Second, time.Millisecond)
}

// Embedded methods panic if discovery unexpectedly uses anything besides details.
type namespaceRuntimeDetails struct {
	runtimeclient.ContainerRuntimeClient
}

func (namespaceRuntimeDetails) GetContainerDetails(id string) (*runtimeclient.ContainerDetailsData, error) {
	return &runtimeclient.ContainerDetailsData{Pid: os.Getpid(), ContainerData: runtimeclient.ContainerData{Runtime: runtimeclient.RuntimeContainerData{
		RuntimeName: igtypes.RuntimeNameContainerd, ContainerID: id, ContainerName: "app", ContainerImageName: "image", ContainerImageDigest: "sha256:abc",
	}}}, nil
}
func TestNamespaceFilterDiscoveryFullyEnrichesUnlabelledPods(t *testing.T) {
	running := func(id string) []corev1.ContainerStatus {
		return []corev1.ContainerStatus{{Name: "app", ContainerID: id, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}
	}
	pod := &corev1.Pod{Name: "pay", Namespace: "payments", Status: corev1.PodStatus{
		InitContainerStatuses: running("init"), ContainerStatuses: running("regular"), EphemeralContainerStatuses: running("ephemeral"),
	}}
	containers, err := runningNamespacePodContainers(t.Context(), namespaceRuntimeDetails{}, pod)
	require.NoError(t, err)
	require.Len(t, containers, 3)
	for _, container := range containers {
		require.True(t, runtimeclient.IsEnrichedWithRuntimeMetadata(container.Runtime.BasicRuntimeMetadata))
		require.True(t, runtimeclient.IsEnrichedWithK8sMetadata(container.K8s.BasicK8sMetadata), "must not trigger shared-client runtime enrichment")
		require.Equal(t, uint32(os.Getpid()), container.Runtime.ContainerPID)
	}
}
