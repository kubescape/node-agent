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
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/pager"

	"github.com/cenkalti/backoff/v4"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	errors2 "k8s.io/apimachinery/pkg/api/errors"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	storageClient     spdxv1beta1.SpdxV1beta1Interface
	resources         map[string]watcher.WatchResource
	eventQueues       map[string]*cooldownqueue.CooldownQueue
	handlers          []watcher.Watcher
	skipNamespaceFunc SkipNamespaceFunc
}

var errWatchClosed = errors.New("watch channel closed")
var errNotImplemented = errors.New("not implemented")

func NewWatchHandler(k8sClient k8sclient.K8sClientInterface, storageClient spdxv1beta1.SpdxV1beta1Interface, skipNamespaceFunc SkipNamespaceFunc) *WatchHandler {
	return &WatchHandler{
		k8sClient:         k8sClient,
		storageClient:     storageClient,
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
		obj, ok := event.Object.(runtime.Object)
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

func (wh *WatchHandler) chooseWatcher(res schema.GroupVersionResource, opts metav1.ListOptions) (watch.Interface, error) {
	switch res.Resource {
	case "applicationprofiles":
		return wh.storageClient.ApplicationProfiles("").Watch(context.Background(), opts)
	case "networkneighborhoods":
		return wh.storageClient.NetworkNeighborhoods("").Watch(context.Background(), opts)
	case "pods":
		return wh.k8sClient.GetKubernetesClient().CoreV1().Pods("").Watch(context.Background(), opts)
	case "runtimerulealertbindings":
		return wh.k8sClient.GetDynamicClient().Resource(res).Namespace("").Watch(context.Background(), opts)
	case "seccompprofiles":
		return wh.storageClient.SeccompProfiles("").Watch(context.Background(), opts)
	default:
		return wh.k8sClient.GetDynamicClient().Resource(res).Watch(context.Background(), opts)
	}
	return nil, fmt.Errorf("cannot watch for resource %s: %w", res.Resource, errNotImplemented)
}

func (wh *WatchHandler) watchRetry(ctx context.Context, res schema.GroupVersionResource, watchOpts metav1.ListOptions, eventQueue *cooldownqueue.CooldownQueue) {
	exitFatal := true
	if err := backoff.RetryNotify(func() error {
		w, err := wh.chooseWatcher(res, watchOpts)
		if err != nil {
			if k8sErrors.ReasonForError(err) == metav1.StatusReasonNotFound {
				exitFatal = false
				return backoff.Permanent(err)
			} else if errors.Is(err, errNotImplemented) {
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
			obj := event.Object.(metav1.Object)
			if wh.skipNamespaceFunc(obj.GetNamespace()) {
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

func (wh *WatchHandler) chooseLister(res schema.GroupVersionResource, opts metav1.ListOptions) (runtime.Object, error) {
	switch res.Resource {
	case "applicationprofiles":
		return wh.storageClient.ApplicationProfiles("").List(context.Background(), opts)
	case "networkneighborhoods":
		return wh.storageClient.NetworkNeighborhoods("").List(context.Background(), opts)
	case "pods":
		return wh.k8sClient.GetKubernetesClient().CoreV1().Pods("").List(context.Background(), opts)
	case "runtimerulealertbindings":
		return wh.k8sClient.GetDynamicClient().Resource(res).Namespace("").List(context.Background(), opts)
	case "seccompprofiles":
		return wh.storageClient.SeccompProfiles("").List(context.Background(), opts)
	}
	return nil, errors2.NewNotFound(res.GroupResource(), "not implemented")
}

func (wh *WatchHandler) getExistingStorageObjects(ctx context.Context, res schema.GroupVersionResource, watchOpts metav1.ListOptions) (string, error) {
	logger.L().Debug("WatchHandler - getting existing objects from storage", helpers.String("resource", res.Resource))
	list := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return wh.chooseLister(res, opts)
	})
	var resourceVersion string
	if err := list.EachListItem(context.Background(), watchOpts, func(obj runtime.Object) error {
		meta := obj.(metav1.Object)
		resourceVersion = meta.GetResourceVersion()
		if wh.skipNamespaceFunc(meta.GetNamespace()) {
			return nil
		}
		for _, handler := range wh.handlers {
			handler.AddHandler(ctx, obj)
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
