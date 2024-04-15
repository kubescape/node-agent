package dynamicwatcher

import (
	"context"
	"errors"
	"fmt"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/watcher"
	"node-agent/pkg/watcher/cooldownqueue"
	"os"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
)

const (
	kubescapeCustomResourceGroup = "spdx.softwarecomposition.kubescape.io"
)

// resourceVersionGetter is an interface used to get resource version from events.
type resourceVersionGetter interface {
	GetResourceVersion() string
}

type WatchHandler struct {
	k8sClient   k8sclient.K8sClientInterface
	resources   map[string]watcher.WatchResource
	eventQueues map[string]*cooldownqueue.CooldownQueue
	handlers    []watcher.Watcher
}

var errWatchClosed = errors.New("watch channel closed")

func NewWatchHandler(k8sClient k8sclient.K8sClientInterface) *WatchHandler {
	return &WatchHandler{
		k8sClient:   k8sClient,
		resources:   make(map[string]watcher.WatchResource),
		eventQueues: make(map[string]*cooldownqueue.CooldownQueue),
	}
}

func (wh *WatchHandler) AddAdaptor(adaptor watcher.Adaptor) {

	// add handler
	wh.handlers = append(wh.handlers, adaptor)

	// add resources to watch
	for _, r := range adaptor.WatchResources() {
		if _, ok := wh.resources[r.GroupVersionResource().String()]; !ok {
			wh.resources[r.GroupVersionResource().String()] = r
			wh.eventQueues[r.GroupVersionResource().String()] = cooldownqueue.NewCooldownQueue()
		}
	}
}

func (wh *WatchHandler) Start(ctx context.Context) {

	for k, v := range wh.resources {
		go func(r string, w watcher.WatchResource) {
			if err := wh.watch(ctx, w, wh.eventQueues[r]); err != nil {
				logger.L().Fatal("watch resource", helpers.Error(err))
			}
		}(k, v)
	}
}

func (wh *WatchHandler) watch(ctx context.Context, resource watcher.WatchResource, eventQueue *cooldownqueue.CooldownQueue) error {
	// for our storage, we need to list all resources and get them one by one
	// as list returns objects with empty spec
	// and watch does not return existing objects
	res := resource.GroupVersionResource()
	opt := resource.ListOptions()

	if res.Group == kubescapeCustomResourceGroup {
		if err := backoff.RetryNotify(func() error {
			var err error
			opt.ResourceVersion, err = wh.getExistingStorageObjects(ctx, res, opt)
			return err
		}, newBackOff(), func(err error, d time.Duration) {
			// filed to list resources, will retry
		}); err != nil {
			return fmt.Errorf("giving up get existing storage objects: %w", err)
		}
	}

	go wh.watchRetry(ctx, res, opt, eventQueue)

	// process events
	for event := range eventQueue.ResultChan {
		// skip non-objects
		obj, ok := event.Object.(*unstructured.Unstructured)
		if !ok || obj == nil {
			continue
		}
		for _, handler := range wh.handlers {
			switch event.Type {
			case watch.Added:
				handler.AddHandler(ctx, obj)
			case watch.Modified:
				handler.ModifyHandler(ctx, obj)
			case watch.Deleted:
				handler.DeleteHandler(ctx, obj)
			}
		}
	}
	return nil
}

func (wh *WatchHandler) Stop(_ context.Context) {
	for _, q := range wh.eventQueues {
		q.Stop()
	}
}

func (wh *WatchHandler) watchRetry(ctx context.Context, res schema.GroupVersionResource, watchOpts metav1.ListOptions, eventQueue *cooldownqueue.CooldownQueue) {
	exitFatal := true
	if err := backoff.RetryNotify(func() error {
		watcher, err := wh.k8sClient.GetDynamicClient().Resource(res).Namespace("").Watch(context.Background(), watchOpts)
		if err != nil {
			if k8sErrors.ReasonForError(err) == metav1.StatusReasonNotFound {
				exitFatal = false
				return backoff.Permanent(err)
			}
			return fmt.Errorf("client resource: %w", err)
		}
		logger.L().Debug("starting watch", helpers.String("resource", res.Resource))
		for {
			event, chanActive := <-watcher.ResultChan()
			// set resource version to resume watch from
			// inspired by https://github.com/kubernetes/client-go/blob/5a0a4247921dd9e72d158aaa6c1ee124aba1da80/tools/watch/retrywatcher.go#L157
			if metaObject, ok := event.Object.(resourceVersionGetter); ok {
				watchOpts.ResourceVersion = metaObject.GetResourceVersion()
			}
			if eventQueue.Closed() {
				watcher.Stop()
				return backoff.Permanent(errors.New("event queue closed"))
			}
			if !chanActive {
				// channel closed, retry
				return errWatchClosed
			}
			if event.Type == watch.Error {
				return fmt.Errorf("watch error: %s", event.Object)
			}

			eventQueue.Enqueue(event)
		}
	}, newBackOff(), func(err error, d time.Duration) {
		if !errors.Is(err, errWatchClosed) {
			logger.L().Ctx(ctx).Debug("watch", helpers.Error(err),
				helpers.String("resource", res.Resource),
				helpers.String("retry in", d.String()))
		}
	}); err != nil {
		logger.L().Ctx(ctx).Error("giving up watch", helpers.Error(err),
			helpers.String("resource", res.String()))
		if exitFatal {
			os.Exit(1)
		}
	}
}

func (wh *WatchHandler) getExistingStorageObjects(ctx context.Context, res schema.GroupVersionResource, watchOpts metav1.ListOptions) (string, error) {
	logger.L().Debug("getting existing objects from storage", helpers.String("resource", res.Resource))
	list, err := wh.k8sClient.GetDynamicClient().Resource(res).Namespace("").List(context.Background(), watchOpts)
	if err != nil {
		return "", fmt.Errorf("list resources: %w", err)
	}
	logger.L().Info("got existing objects from storage", helpers.String("resource", res.Resource), helpers.Int("count", len(list.Items)))
	for i := range list.Items {
		for _, handler := range wh.handlers {
			var l unstructured.Unstructured
			l = list.Items[i]
			handler.AddHandler(ctx, &l)
		}
	}
	// set resource version to watch from
	return list.GetResourceVersion(), nil
}

func newBackOff() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	// never stop retrying (unless PermanentError is returned)
	b.MaxElapsedTime = 0
	return b
}
