package containerwatcher

import (
	"context"
	"errors"
	"fmt"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/utils"
)

const namespaceFilterPollInterval = 5 * time.Second

// watchNamespaceFilter publishes changes and removes exclusions independently
// of the single admission worker. Each discovery owns a cancellable connection;
// a new generation cancels the old request without delaying publication.
func (cw *ContainerWatcher) watchNamespaceFilter(ctx context.Context, ticks <-chan time.Time) {
	type result struct {
		generation uint64
		err        error
	}
	var pending *config.NamespaceFilter
	var generation uint64
	var done <-chan result
	var cancel context.CancelFunc
	retryRequested := false
	startAdmission := func() {
		if pending == nil || done != nil || ctx.Err() != nil {
			return
		}
		jobCtx, jobCancel := context.WithTimeout(ctx, namespaceFilterDiscoveryTimeout)
		cancel = jobCancel
		results := make(chan result, 1)
		done = results
		previous, revision := pending, generation
		go func() {
			err := cw.reconcileNamespaceFilter(jobCtx, previous, cw.runningContainersForNamespace)
			jobCancel()
			results <- result{revision, err}
		}()
	}
	defer func() {
		if cancel != nil {
			cancel()
			<-done // No orphaned discovery or mutations after collection shutdown.
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case outcome := <-done:
			done, cancel = nil, nil
			if outcome.err == nil && outcome.generation == generation {
				pending = nil
			}
			if outcome.err != nil && !errors.Is(outcome.err, context.Canceled) {
				logger.L().Warning("Namespace filter admission failed; will retry", helpers.Error(outcome.err))
			}
			if retryRequested {
				retryRequested = false
				startAdmission()
			}
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
				generation++
				if cancel != nil {
					cancel()
				}
				logger.L().Info("Namespace filter updated")
			}
			if pending == nil {
				continue
			}
			cw.removeExcludedNamespaceContainers()
			if done != nil {
				retryRequested = true
			} else {
				startAdmission()
			}
		}
	}
}

func (cw *ContainerWatcher) removeExcludedNamespaceContainers() {
	for _, container := range cw.containerCollection.GetContainersBySelector(&containercollection.ContainerSelector{}) {
		if !utils.IsHostContainer(container) && cw.cfg.IgnoreContainer(container.K8s.Namespace, container.K8s.PodName, container.K8s.PodLabels) {
			cw.removeContainer(container)
		}
	}
}

// reconcileNamespaceFilter admits containers independently of filter polling.
// Only namespaces that changed from excluded to included are replayed, so an
// unrelated update does not restart completed profiling sessions.
func (cw *ContainerWatcher) reconcileNamespaceFilter(ctx context.Context, previous *config.NamespaceFilter, running func(context.Context, *config.NamespaceFilter) ([]containercollection.Container, error)) error {
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
		cw.lateAdmissions.Store(container, struct{}{})
		cw.containerCollection.AddContainer(container)
		if cw.containerCollection.GetContainer(container.Runtime.ContainerID) != container {
			cw.lateAdmissions.Delete(container)
		}
		if cw.containerCollection.GetContainer(container.Runtime.ContainerID) == nil {
			err = fmt.Errorf("container %s could not be admitted; retrying discovery", container.Runtime.ContainerID)
		}
	}
	return err
}
