package dynamicwatcher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/watcher"
	"github.com/kubescape/node-agent/pkg/watcher/cooldownqueue"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/pager"

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

type SkipNamespaceFunc func(string) bool

type WatchHandler struct {
	k8sClient         k8sclient.K8sClientInterface
	resources         map[string]watcher.WatchResource
	eventQueues       map[string]*cooldownqueue.CooldownQueue
	handlers          []watcher.Watcher
	skipNamespaceFunc SkipNamespaceFunc
}

var errWatchClosed = errors.New("watch channel closed")

func NewWatchHandler(k8sClient k8sclient.K8sClientInterface, skipNamespaceFunc SkipNamespaceFunc) *WatchHandler {
	return &WatchHandler{
		k8sClient:         k8sClient,
		resources:         make(map[string]watcher.WatchResource),
		eventQueues:       make(map[string]*cooldownqueue.CooldownQueue),
		skipNamespaceFunc: skipNamespaceFunc,
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
				logger.L().Fatal("WatchHandler - watch resource", helpers.Error(err))
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
			logger.L().Ctx(ctx).Warning("WatchHandler - get existing storage objects", helpers.Error(err),
				helpers.String("retry in", d.String()))
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
		w, err := wh.k8sClient.GetDynamicClient().Resource(res).Namespace("").Watch(context.Background(), watchOpts)
		if err != nil {
			if k8sErrors.ReasonForError(err) == metav1.StatusReasonNotFound {
				exitFatal = false
				return backoff.Permanent(err)
			}
			return fmt.Errorf("client resource: %w", err)
		}
		logger.L().Debug("WatchHandler - starting watch", helpers.String("resource", res.Resource))
		for {
			event, chanActive := <-w.ResultChan()
			// set resource version to resume watch from
			// inspired by https://github.com/kubernetes/client-go/blob/5a0a4247921dd9e72d158aaa6c1ee124aba1da80/tools/watch/retrywatcher.go#L157
			if metaObject, ok := event.Object.(resourceVersionGetter); ok {
				watchOpts.ResourceVersion = metaObject.GetResourceVersion()
			}
			if eventQueue.Closed() {
				w.Stop()
				return backoff.Permanent(errors.New("event queue closed"))
			}
			if !chanActive {
				// channel closed, retry
				return errWatchClosed
			}
			if event.Type == watch.Error {
				return fmt.Errorf("watch error: %s", event.Object)
			}
			pod := event.Object.(*unstructured.Unstructured)
			if wh.skipNamespaceFunc(pod.GetNamespace()) {
				continue
			}
			eventQueue.Enqueue(event)
		}
	}, newBackOff(), func(err error, d time.Duration) {
		if !errors.Is(err, errWatchClosed) {
			logger.L().Debug("WatchHandler - watch", helpers.Error(err),
				helpers.String("resource", res.Resource),
				helpers.String("retry in", d.String()))
		}
	}); err != nil {
		logger.L().Ctx(ctx).Error("WatchHandler - giving up watch", helpers.Error(err),
			helpers.String("resource", res.String()))
		if exitFatal {
			os.Exit(1)
		}
	}
}

func (wh *WatchHandler) getExistingStorageObjects(ctx context.Context, res schema.GroupVersionResource, watchOpts metav1.ListOptions) (string, error) {
	logger.L().Debug("WatchHandler - getting existing objects from storage", helpers.String("resource", res.Resource))
	list := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return wh.k8sClient.GetDynamicClient().Resource(res).Namespace("").List(ctx, opts)
	})
	var resourceVersion string
	if err := list.EachListItem(context.Background(), watchOpts, func(obj runtime.Object) error {
		pod := obj.(*unstructured.Unstructured)
		resourceVersion = pod.GetResourceVersion()
		if wh.skipNamespaceFunc(pod.GetNamespace()) {
			return nil
		}
		for _, handler := range wh.handlers {
			handler.AddHandler(ctx, pod)
		}
		return nil
	}); err != nil {
		return "", fmt.Errorf("list resources: %w", err)
	}
	// set resource version to watch from
	return resourceVersion, nil
}

func newBackOff() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	// never stop retrying (unless PermanentError is returned)
	b.MaxElapsedTime = 0
	return b
}
