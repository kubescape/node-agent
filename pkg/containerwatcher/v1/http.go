package containerwatcher

import (
	"fmt"

	tracerhttp "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/tracer"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGContainerWatcher) httpEventCallback(event *tracerhttptype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		logger.L().Ctx(ch.ctx).Warning("http tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	if event.Response == nil || event.Response.StatusCode == 404 {
		return
	}

	ch.httpWorkerChan <- event
}

func (ch *IGContainerWatcher) startHttpTracing() error {
	if err := ch.tracerCollection.AddTracer(httpTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	httpMountnsmap, err := ch.tracerCollection.TracerMountNsMap(httpTraceName)
	if err != nil {
		return fmt.Errorf("getting httpMountnsmap: %w", err)
	}

	tracerHttp, err := tracerhttp.NewTracer(&tracerhttp.Config{MountnsMap: httpMountnsmap}, ch.containerCollection, ch.httpEventCallback)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}

	go func() {
		for event := range ch.httpWorkerChan {
			_ = ch.httpWorkerPool.Invoke(*event)
		}
	}()

	ch.httpTracer = tracerHttp
	return nil
}

func (ch *IGContainerWatcher) stopHttpTracing() error {
	if err := ch.tracerCollection.RemoveTracer(httpTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}
	ch.httpTracer.Close()
	return nil
}
