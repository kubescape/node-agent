package podwatcher

import (
	"context"
	"errors"
	"fmt"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/watcher"
	"node-agent/pkg/watcher/cooldownqueue"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/cenkalti/backoff/v4"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

type resourceVersionGetter interface {
	GetResourceVersion() string
}

var errWatchClosed = errors.New("watch channel closed")

type WatchHandler struct {
	nodeName   string
	k8sClient  k8sclient.K8sClientInterface
	eventQueue *cooldownqueue.CooldownQueue
	handlers   []watcher.Watcher
}

// NewWatchHandler creates a new WatchHandler, initializes the maps and returns it
func NewWatchHandler(nodeName string, k8sClient k8sclient.K8sClientInterface, handlers []watcher.Watcher) *WatchHandler {
	return &WatchHandler{
		k8sClient:  k8sClient,
		nodeName:   nodeName,
		eventQueue: cooldownqueue.NewCooldownQueue(cooldownqueue.DefaultQueueSize, cooldownqueue.DefaultTTL),
		handlers:   handlers,
	}
}

func (wh *WatchHandler) AddHandler(handlers watcher.Watcher) {
	wh.handlers = append(wh.handlers, handlers)
}

func (wh *WatchHandler) Watch(ctx context.Context) {
	watchOpts := v1.ListOptions{
		Watch:         true,
		FieldSelector: "spec.nodeName=" + wh.nodeName, // only when the pod is running
	}

	// list pods and add them to the queue, this is for the pods that were created before the watch started
	wh.listPods(ctx)

	// start watching
	go wh.watchRetry(ctx, watchOpts)

	// process events
	go func() {
		for event := range wh.eventQueue.ResultChan {
			// skip non-pod objects
			pod, ok := event.Object.(*corev1.Pod)
			if !ok {
				continue
			}
			for i := range wh.handlers {
				switch event.Type {
				case watch.Added:
					wh.handlers[i].RuntimeObjAddHandler(pod)
				case watch.Modified:
					wh.handlers[i].RuntimeObjUpdateHandler(pod)
				case watch.Deleted:
					wh.handlers[i].RuntimeObjDeleteHandler(pod)
				}
			}
		}
		logger.L().Ctx(ctx).Fatal("pod watcher event queue closed")
	}()
}
func (wh *WatchHandler) listPods(ctx context.Context) error {
	pods, err := wh.k8sClient.GetKubernetesClient().CoreV1().Pods("").List(ctx, v1.ListOptions{
		FieldSelector: "spec.nodeName=" + wh.nodeName, // only when the pod is running
	})
	if err != nil {
		return err
	}
	for i := range pods.Items {
		pods.Items[i].APIVersion = "v1"
		pods.Items[i].Kind = "Pod"
		wh.eventQueue.Enqueue(watch.Event{
			Type:   watch.Added,
			Object: &pods.Items[i],
		})
	}
	return nil

}

func (wh *WatchHandler) watchRetry(ctx context.Context, watchOpts v1.ListOptions) {
	if err := backoff.RetryNotify(func() error {
		watcher, err := wh.k8sClient.GetKubernetesClient().CoreV1().Pods("").Watch(context.Background(), watchOpts)
		if err != nil {
			return fmt.Errorf("client resource: %w", err)
		}
		for {
			event, chanActive := <-watcher.ResultChan()
			// set resource version to resume watch from
			// inspired by https://github.com/kubernetes/client-go/blob/5a0a4247921dd9e72d158aaa6c1ee124aba1da80/tools/watch/retrywatcher.go#L157
			if metaObject, ok := event.Object.(resourceVersionGetter); ok {
				watchOpts.ResourceVersion = metaObject.GetResourceVersion()
			}
			if wh.eventQueue.Closed() {
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
			wh.eventQueue.Enqueue(event)
		}
	}, newBackOff(), func(err error, d time.Duration) {
		if !errors.Is(err, errWatchClosed) {
			logger.L().Ctx(ctx).Warning("watch", helpers.Error(err),
				helpers.String("resource", "pods"),
				helpers.String("retry in", d.String()))
		}
	}); err != nil {
		logger.L().Ctx(ctx).Fatal("giving up watch", helpers.Error(err),
			helpers.String("resource", "pods"))
	}
}

func newBackOff() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	// never stop retrying (unless PermanentError is returned)
	b.MaxElapsedTime = 0
	return b
}
