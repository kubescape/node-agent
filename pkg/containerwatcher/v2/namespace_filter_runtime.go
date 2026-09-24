package containerwatcher

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/cri"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"github.com/kubescape/node-agent/pkg/config"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
)

const namespaceFilterDiscoveryTimeout = 30 * time.Second

// runningContainersForNamespace uses a private CRI connection. The pinned IG
// client issues RPCs with context.Background, so canceling our context must
// close that connection to interrupt the actual I/O, including sandbox calls.
// It never closes the shared client used by the rest of node-agent.
func (cw *ContainerWatcher) runningContainersForNamespace(ctx context.Context, previous *config.NamespaceFilter) ([]containercollection.Container, error) {
	ctx, cancel := context.WithTimeout(ctx, namespaceFilterDiscoveryTimeout)
	defer cancel()
	pods, err := cw.k8sClient.GetKubernetesClient().CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", cw.cfg.NodeName).String(),
	})
	if err != nil {
		return nil, err
	}
	var client runtimeclient.ContainerRuntimeClient
	var containers []containercollection.Container
	var discoveryErrors []error
	for i := range pods.Items {
		if ctx.Err() != nil {
			return containers, ctx.Err()
		}
		pod := &pods.Items[i]
		if !previous.SkipNamespace(pod.Namespace) || cw.cfg.IgnoreContainer(pod.Namespace, pod.Name, pod.Labels) {
			continue
		}
		if client == nil {
			if cw.runtime == nil {
				return nil, fmt.Errorf("namespace discovery requires a container runtime")
			}
			client, err = containerutils.NewContainerRuntimeClient(cw.runtime)
			if err != nil {
				return nil, err
			}
			// Kubernetes uses CRI. Do not claim cancellation for an alternative
			// implementation whose Close does not interrupt pending requests.
			if _, ok := client.(*cri.CRIClient); !ok {
				client.Close()
				return nil, fmt.Errorf("namespace discovery requires a CRI runtime client")
			}
			var closeOnce sync.Once
			closeClient := func() { closeOnce.Do(func() { _ = client.Close() }) }
			stop := context.AfterFunc(ctx, closeClient)
			defer func() { stop(); closeClient() }()
		}
		discovered, err := runningNamespacePodContainers(ctx, client, pod)
		containers = append(containers, discovered...)
		if ctx.Err() != nil {
			return containers, ctx.Err()
		}
		if err != nil {
			discoveryErrors = append(discoveryErrors, err)
		}
	}
	return containers, errors.Join(discoveryErrors...)
}

// Build the same runtime/Kubernetes metadata as IG's GetRunningContainers,
// using the private, cancellable runtime session rather than its shared client.
func runningNamespacePodContainers(ctx context.Context, client runtimeclient.ContainerRuntimeClient, pod *corev1.Pod) ([]containercollection.Container, error) {
	var containers []containercollection.Container
	var failures []error
	for _, statuses := range [][]corev1.ContainerStatus{pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses, pod.Status.EphemeralContainerStatuses} {
		for _, status := range statuses {
			if ctx.Err() != nil {
				return containers, ctx.Err()
			}
			if status.State.Running == nil || status.ContainerID == "" {
				continue
			}
			details, err := client.GetContainerDetails(status.ContainerID)
			if err != nil {
				failures = append(failures, fmt.Errorf("container %s: %w", status.ContainerID, err))
				continue
			}
			if details.Pid <= 0 || uint64(details.Pid) > math.MaxUint32 {
				failures = append(failures, fmt.Errorf("invalid PID for container %s", status.ContainerID))
				continue
			}
			if _, err := os.Stat(filepath.Join(host.HostProcFs, fmt.Sprint(details.Pid))); err != nil {
				failures = append(failures, err)
				continue
			}
			container := containercollection.Container{
				Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					RuntimeName: details.Runtime.RuntimeName, ContainerID: details.Runtime.ContainerID,
					ContainerName: details.Runtime.ContainerName, ContainerPID: uint32(details.Pid),
					ContainerImageName: details.Runtime.ContainerImageName, ContainerImageDigest: details.Runtime.ContainerImageDigest,
					ContainerStartedAt: details.Runtime.ContainerStartedAt,
				}},
				K8s: containercollection.K8sMetadata{BasicK8sMetadata: types.BasicK8sMetadata{Namespace: pod.Namespace, PodName: pod.Name, ContainerName: status.Name}},
			}
			container.SetPodLabels(pod.Labels)
			if container.K8s.PodLabels == nil {
				container.K8s.PodLabels = map[string]string{}
			}
			// Fully enrich before AddContainer so its runtime enricher cannot issue
			// an uncancellable fallback request using the collection's shared client.
			if !runtimeclient.IsEnrichedWithK8sMetadata(container.K8s.BasicK8sMetadata) || !runtimeclient.IsEnrichedWithRuntimeMetadata(container.Runtime.BasicRuntimeMetadata) {
				failures = append(failures, fmt.Errorf("incomplete metadata for container %s", status.ContainerID))
				continue
			}
			containers = append(containers, container)
		}
	}
	return containers, errors.Join(failures...)
}
