package containerwatcher

import (
	"context"
	"fmt"
	"strings"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
)

const namespaceFilterPollInterval = 5 * time.Second

// watchNamespaceFilter has a single writer. Failed discovery is retried while
// later valid edits remain effective, including exclusions during an API outage.
func (cw *ContainerWatcher) watchNamespaceFilter(ctx context.Context, ticks <-chan time.Time) {
	var pending *config.NamespaceFilter
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			if ctx.Err() != nil {
				return
			}
			previous := cw.cfg.NamespaceFilterSnapshot()
			changed, err := cw.cfg.ReloadNamespaceFilter()
			if err != nil {
				logger.L().Warning("Namespace filter reload failed; keeping last valid settings", helpers.Error(err))
			}
			if changed {
				if pending == nil {
					pending = previous
				} else {
					pending = pending.UnionExclusions(previous)
				}
				logger.L().Info("Namespace filter updated")
			}
			if pending == nil {
				continue
			}
			if err := cw.reconcileNamespaceFilter(ctx, pending, cw.runningContainersForNamespace); err != nil {
				logger.L().Warning("Namespace filter reconciliation failed; will retry", helpers.Error(err))
				continue
			}
			pending = nil
		}
	}
}

// reconcileNamespaceFilter removes excluded containers even if rediscovery
// fails. Only namespaces that changed from excluded to included are replayed:
// otherwise an unrelated update would restart completed profiling sessions.
func (cw *ContainerWatcher) reconcileNamespaceFilter(ctx context.Context, previous *config.NamespaceFilter, running func(context.Context, *config.NamespaceFilter) ([]containercollection.Container, error)) error {
	for _, container := range cw.containerCollection.GetContainersBySelector(&containercollection.ContainerSelector{}) {
		if !utils.IsHostContainer(container) && cw.cfg.IgnoreContainer(container.K8s.Namespace, container.K8s.PodName, container.K8s.PodLabels) {
			cw.removeContainer(container)
		}
	}
	containers, err := running(ctx, previous)
	// Partial results are useful: retry will skip containers already present.
	for i := range containers {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		container := &containers[i]
		if utils.IsHostContainer(container) || !previous.SkipNamespace(container.K8s.Namespace) || cw.cfg.IgnoreContainer(container.K8s.Namespace, container.K8s.PodName, container.K8s.PodLabels) {
			continue
		}
		if cw.containerCollection.GetContainer(container.Runtime.ContainerID) != nil {
			continue
		}
		cw.containerCollection.AddContainer(container)
		if cw.containerCollection.GetContainer(container.Runtime.ContainerID) == nil {
			err = fmt.Errorf("container %s could not be admitted; retrying discovery", container.Runtime.ContainerID)
		}
	}
	return err
}

// runningContainersForNamespace re-queries the node's pods and runtime, rather
// than retaining container pointers/PIDs removed by an earlier exclusion.
func (cw *ContainerWatcher) runningContainersForNamespace(ctx context.Context, previous *config.NamespaceFilter) ([]containercollection.Container, error) {
	pods, err := cw.k8sClient.GetKubernetesClient().CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", cw.cfg.NodeName).String(),
	})
	if err != nil {
		return nil, err
	}
	var containers []containercollection.Container
	var incomplete bool
	for i := range pods.Items {
		if ctx.Err() != nil {
			return containers, ctx.Err()
		}
		pod := &pods.Items[i]
		if !previous.SkipNamespace(pod.Namespace) || cw.cfg.IgnoreContainer(pod.Namespace, pod.Name, pod.Labels) {
			continue
		}
		discovered := cw.igK8sClient.GetRunningContainers(pod)
		containers = append(containers, discovered...)
		// GetRunningContainers logs individual runtime failures and skips them.
		// Surface these as retryable instead of losing running containers forever.
		ids := make(map[string]bool, len(discovered))
		for _, container := range discovered {
			ids[container.Runtime.ContainerID] = true
		}
		for _, statuses := range [][]corev1.ContainerStatus{pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses, pod.Status.EphemeralContainerStatuses} {
			for _, status := range statuses {
				if status.State.Running == nil || status.ContainerID == "" {
					continue
				}
				_, id, ok := strings.Cut(status.ContainerID, "://")
				if !ok {
					id = status.ContainerID
				}
				if !ids[id] {
					incomplete = true
				}
			}
		}
	}
	if incomplete {
		return containers, fmt.Errorf("runtime metadata unavailable for one or more running containers")
	}
	return containers, nil
}
