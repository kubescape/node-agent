package seccompprofilewatcher

import (
	"context"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	v1beta1api "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

// SeccompProfileWatcher watches SeccompProfile resources and applies them using SeccompManager
type SeccompProfileWatcher interface {
	Start(ctx context.Context)
	Stop()
}

// SeccompProfileWatcherImpl implements SeccompProfileWatcher using a SeccompProfileClient
type SeccompProfileWatcherImpl struct {
	client         storage.SeccompProfileClient
	seccompManager seccompmanager.SeccompManagerClient
	stopCh         chan struct{}
}

// NewSeccompProfileWatcher creates a new SeccompProfileWatcher
func NewSeccompProfileWatcher(client storage.SeccompProfileClient, seccompManager seccompmanager.SeccompManagerClient) *SeccompProfileWatcherImpl {
	return &SeccompProfileWatcherImpl{
		client:         client,
		seccompManager: seccompManager,
		stopCh:         make(chan struct{}),
	}
}

// Start begins watching SeccompProfile resources
func (w *SeccompProfileWatcherImpl) Start(ctx context.Context) {
	go w.watchLoop(ctx)
}

// Stop stops the watcher
func (w *SeccompProfileWatcherImpl) Stop() {
	close(w.stopCh)
}

func (w *SeccompProfileWatcherImpl) watchLoop(ctx context.Context) {
	// First, list existing SeccompProfiles
	if err := w.listExisting(ctx); err != nil {
		logger.L().Ctx(ctx).Warning("SeccompProfileWatcher - failed to list existing profiles", helpers.Error(err))
	}

	// Then start watching for changes
	w.watchWithRetry(ctx)
}

func (w *SeccompProfileWatcherImpl) listExisting(ctx context.Context) error {
	var resourceVersion string
	opts := metav1.ListOptions{}

	for {
		list, err := w.client.ListSeccompProfiles("", opts)
		if err != nil {
			return err
		}

		for i := range list.Items {
			profile := &list.Items[i]
			w.handleAdd(ctx, profile)
		}

		resourceVersion = list.ResourceVersion
		if list.Continue == "" {
			break
		}
		opts.Continue = list.Continue
	}

	logger.L().Ctx(ctx).Debug("SeccompProfileWatcher - listed existing profiles",
		helpers.String("resourceVersion", resourceVersion))
	return nil
}

// watchExit explains why processEvents returned, so watchWithRetry can react.
type watchExit int

const (
	exitStopped       watchExit = iota // stopCh/ctx cancelled — caller should return
	exitErrorEvent                     // watch.Error / expired RV — poison RV, re-List, back off
	exitChannelClosed                  // clean channel close — re-watch from same RV
)

func (w *SeccompProfileWatcherImpl) watchWithRetry(ctx context.Context) {
	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 0 // Never stop retrying

	opts := metav1.ListOptions{}

	for {
		select {
		case <-w.stopCh:
			return
		case <-ctx.Done():
			return
		default:
		}

		watcher, err := w.client.WatchSeccompProfiles("", opts)
		if err != nil {
			delay := b.NextBackOff()
			logger.L().Ctx(ctx).Debug("SeccompProfileWatcher - watch error, retrying",
				helpers.Error(err),
				helpers.String("retryIn", delay.String()))
			select {
			case <-time.After(delay):
			case <-w.stopCh:
				return
			case <-ctx.Done():
				return
			}
			continue
		}

		resourceVersion, exit := w.processEvents(ctx, watcher)

		switch exit {
		case exitStopped:
			return
		case exitChannelClosed:
			if resourceVersion != "" {
				// Made progress before the close (e.g. server rotated the watch after
				// delivering events). Resume from the last good RV and reset backoff.
				opts.ResourceVersion = resourceVersion
				b.Reset()
				continue
			}
			// Clean close before any event: the CRD watch path can close without a
			// watch.Error on disconnects/timeouts. Resetting backoff here would let
			// repeated instant closes hot-spin, so back off before retrying instead.
			delay := b.NextBackOff()
			logger.L().Ctx(ctx).Debug("SeccompProfileWatcher - watch closed before any event, backing off",
				helpers.String("retryIn", delay.String()))
			select {
			case <-time.After(delay):
			case <-w.stopCh:
				return
			case <-ctx.Done():
				return
			}
		case exitErrorEvent:
			// The RV is poisoned (e.g. 410 Expired after etcd compaction). Drop it
			// and re-List to recover a fresh RV, then back off before re-watching so
			// a persistent error can never drive a zero-delay hot loop.
			opts.ResourceVersion = ""
			if err := w.listExisting(ctx); err != nil {
				logger.L().Ctx(ctx).Warning("SeccompProfileWatcher - re-list after watch error failed", helpers.Error(err))
			}
			delay := b.NextBackOff()
			logger.L().Ctx(ctx).Debug("SeccompProfileWatcher - watch error event, re-listing and backing off",
				helpers.String("retryIn", delay.String()))
			select {
			case <-time.After(delay):
			case <-w.stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}
}

func (w *SeccompProfileWatcherImpl) processEvents(ctx context.Context, watcher watch.Interface) (string, watchExit) {
	defer watcher.Stop()

	var lastResourceVersion string

	for {
		select {
		case <-w.stopCh:
			return lastResourceVersion, exitStopped
		case <-ctx.Done():
			return lastResourceVersion, exitStopped
		case event, ok := <-watcher.ResultChan():
			if !ok {
				// Channel closed, need to restart watch
				return lastResourceVersion, exitChannelClosed
			}

			if event.Type == watch.Error {
				logger.L().Ctx(ctx).Debug("SeccompProfileWatcher - watch error event")
				return lastResourceVersion, exitErrorEvent
			}

			profile, ok := event.Object.(*v1beta1api.SeccompProfile)
			if !ok {
				logger.L().Ctx(ctx).Warning("SeccompProfileWatcher - unexpected object type")
				continue
			}

			lastResourceVersion = profile.ResourceVersion

			switch event.Type {
			case watch.Added:
				w.handleAdd(ctx, profile)
			case watch.Modified:
				w.handleModify(ctx, profile)
			case watch.Deleted:
				w.handleDelete(ctx, profile)
			}
		}
	}
}

func (w *SeccompProfileWatcherImpl) handleAdd(ctx context.Context, profile *v1beta1api.SeccompProfile) {
	if err := w.seccompManager.AddSeccompProfile(profile); err != nil {
		logger.L().Ctx(ctx).Warning("SeccompProfileWatcher - failed to add seccomp profile",
			helpers.Error(err),
			helpers.String("name", profile.GetName()),
			helpers.String("namespace", profile.GetNamespace()))
	}
}

func (w *SeccompProfileWatcherImpl) handleModify(ctx context.Context, profile *v1beta1api.SeccompProfile) {
	if err := w.seccompManager.AddSeccompProfile(profile); err != nil {
		logger.L().Ctx(ctx).Warning("SeccompProfileWatcher - failed to modify seccomp profile",
			helpers.Error(err),
			helpers.String("name", profile.GetName()),
			helpers.String("namespace", profile.GetNamespace()))
	}
}

func (w *SeccompProfileWatcherImpl) handleDelete(ctx context.Context, profile *v1beta1api.SeccompProfile) {
	if err := w.seccompManager.DeleteSeccompProfile(profile); err != nil {
		logger.L().Ctx(ctx).Warning("SeccompProfileWatcher - failed to delete seccomp profile",
			helpers.Error(err),
			helpers.String("name", profile.GetName()),
			helpers.String("namespace", profile.GetNamespace()))
	}
}
