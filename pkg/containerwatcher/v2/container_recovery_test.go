package containerwatcher

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	runtimeconfig "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type recoveryRuntime struct {
	runtimeapi.UnimplementedRuntimeServiceServer
	calls atomic.Int32
}

func (r *recoveryRuntime) ContainerStatus(_ context.Context, req *runtimeapi.ContainerStatusRequest) (*runtimeapi.ContainerStatusResponse, error) {
	r.calls.Add(1)
	return &runtimeapi.ContainerStatusResponse{Status: &runtimeapi.ContainerStatus{Id: req.ContainerId, Metadata: &runtimeapi.ContainerMetadata{Name: "app"}, Image: &runtimeapi.ImageSpec{Image: "image"}, ImageRef: "sha256:abc"}, Info: map[string]string{"pid": strconv.Itoa(os.Getpid())}}, nil
}
func (*recoveryRuntime) ListContainers(_ context.Context, req *runtimeapi.ListContainersRequest) (*runtimeapi.ListContainersResponse, error) {
	return &runtimeapi.ListContainersResponse{Containers: []*runtimeapi.Container{{Id: req.Filter.Id, PodSandboxId: "sandbox"}}}, nil
}
func (*recoveryRuntime) ListPodSandbox(context.Context, *runtimeapi.ListPodSandboxRequest) (*runtimeapi.ListPodSandboxResponse, error) {
	return &runtimeapi.ListPodSandboxResponse{Items: []*runtimeapi.PodSandbox{{Id: "sandbox"}}}, nil
}

func TestContainerRecoveryMissedHookAndNoReplay(t *testing.T) {
	dir, err := os.MkdirTemp("", "na-recovery-")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "cri.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	server := grpc.NewServer()
	service := &recoveryRuntime{}
	runtimeapi.RegisterRuntimeServiceServer(server, service)
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	status := func(id string) corev1.ContainerStatus {
		return corev1.ContainerStatus{Name: id, ContainerID: "containerd://" + id, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}
	}
	pod := &corev1.Pod{Name: "pod", Namespace: "default", Spec: corev1.PodSpec{NodeName: "node-one"}, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{status("missed"), status("existing"), status("completed")}}}
	excluded := pod.DeepCopy()
	excluded.Name = "excluded"
	excluded.Labels = map[string]string{"skip": "true"}
	excluded.Status.ContainerStatuses = []corev1.ContainerStatus{status("excluded")}
	cc := &containercollection.ContainerCollection{}
	cw := &ContainerWatcher{cfg: config.Config{NodeName: "node-one", ExcludeLabels: map[string][]string{"skip": {"true"}}}, containerCollection: cc, k8sClient: &k8sinterface.KubernetesApi{KubernetesClient: fake.NewClientset(pod, excluded)}, runtime: &runtimeconfig.RuntimeConfig{Name: igtypes.RuntimeNameContainerd, SocketPath: socket, RuntimeProtocol: runtimeconfig.RuntimeProtocolCRI}}
	cc.AddContainer(makeTestContainer("existing", "default", "pod", "existing", 1))
	cw.observedContainers.Store("completed", struct{}{})
	require.NoError(t, cw.reconcileNamespaceFilter(t.Context(), nil, cw.runningContainersForNamespace))
	recovered := cc.GetContainer("missed")
	require.NotNil(t, recovered)
	require.Equal(t, uint32(os.Getpid()), recovered.Runtime.ContainerPID)
	_, late := cw.lateAdmissions.Load(recovered)
	require.True(t, late, "recovered containers must not claim complete capture from startup")
	require.Nil(t, cc.GetContainer("excluded"))
	require.Nil(t, cc.GetContainer("completed"))
	require.Equal(t, int32(1), service.calls.Load(), "known and excluded containers must be filtered before CRI")
	require.NoError(t, cw.reconcileNamespaceFilter(t.Context(), nil, cw.runningContainersForNamespace))
	require.Same(t, recovered, cc.GetContainer("missed"))
	require.Equal(t, int32(1), service.calls.Load())
	_, retained := cw.observedContainers.Load("completed")
	require.True(t, retained, "completed sessions remain remembered while the pod references them")

	// An explicit namespace re-inclusion must still replay an observed session.
	filterPath := filepath.Join(dir, "previous.json")
	require.NoError(t, os.WriteFile(filterPath, []byte(`{"includeNamespaces":[],"excludeNamespaces":["default"]}`), 0600))
	previous, err := config.ReadNamespaceFilter(filterPath)
	require.NoError(t, err)
	require.NoError(t, cw.reconcileNamespaceFilter(t.Context(), previous, cw.runningContainersForNamespace))
	require.NotNil(t, cc.GetContainer("completed"))
	require.Equal(t, int32(2), service.calls.Load())

	// Forget a retired runtime ID after it disappears from pod status and collection.
	cc.RemoveContainer("completed")
	pod.Status.ContainerStatuses = pod.Status.ContainerStatuses[:2]
	_, err = cw.k8sClient.KubernetesClient.CoreV1().Pods("default").UpdateStatus(t.Context(), pod, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.NoError(t, cw.reconcileNamespaceFilter(t.Context(), nil, cw.runningContainersForNamespace))
	_, retained = cw.observedContainers.Load("completed")
	require.False(t, retained)
	require.Equal(t, int32(2), service.calls.Load())
}

func TestContainerRecoveryBlockedRuntimeShutdown(t *testing.T) {
	cw, runtime, write := namespaceBlockedRuntimeWatcher(t)
	write(`{"includeNamespaces":[],"excludeNamespaces":[]}`)
	_, err := cw.cfg.ReloadNamespaceFilter()
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ticks := make(chan time.Time, 1)
	ticks <- time.Now()
	done := make(chan struct{})
	go func() { defer close(done); cw.watchContainerRecovery(ctx, ticks) }()
	select {
	case <-runtime.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("recovery did not reach CRI")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("recovery did not join after cancellation")
	}
	require.Eventually(t, func() bool { return runtime.active.Load() == 0 }, time.Second, time.Millisecond)
	require.Nil(t, cw.containerCollection.GetContainer("late"))
}
