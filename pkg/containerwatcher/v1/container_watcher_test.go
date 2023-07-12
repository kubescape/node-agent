package containerwatcher

import (
	"context"
	"node-agent/pkg/relevancymanager"
	relevancymanagerV1 "node-agent/pkg/relevancymanager/v1"
	"testing"

	"github.com/gammazero/workerpool"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerexec "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	traceropen "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/tracer"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/kubescape/k8s-interface/k8sinterface"
)

type fakeTracerMapsUpdater struct {
	containers map[string]*containercollection.Container
}

func (f *fakeTracerMapsUpdater) TracerMapsUpdater() containercollection.FuncNotify {
	return func(event containercollection.PubSubEvent) {
		switch event.Type {
		case containercollection.EventTypeAddContainer:
			f.containers[event.Container.ID] = event.Container
		case containercollection.EventTypeRemoveContainer:
			delete(f.containers, event.Container.ID)
		}
	}
}

func TestCreateIGContainerWatcher(t *testing.T) {
	type args struct {
		k8sClient        *k8sinterface.KubernetesApi
		relevancyManager relevancymanager.RelevancyManagerClient
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "TestCreateIGContainerWatcher",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CreateIGContainerWatcher(tt.args.k8sClient, tt.args.relevancyManager)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateIGContainerWatcher() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestIGContainerWatcher_Start(t *testing.T) {
	cc := containercollection.ContainerCollection{}
	f := &fakeTracerMapsUpdater{containers: make(map[string]*containercollection.Container)}

	if err := cc.Initialize(containercollection.WithTracerCollection(f)); err != nil {
		t.Fatalf("Failed to initialize container collection: %s", err)
	}
	type fields struct {
		containerCollection *containercollection.ContainerCollection
		k8sClient           *k8sinterface.KubernetesApi
		relevancyManager    relevancymanager.RelevancyManagerClient
		tracerCollection    *tracercollection.TracerCollection
		tracerExec          *tracerexec.Tracer
		tracerOpen          *traceropen.Tracer
		workerPool          *workerpool.WorkerPool
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "TestIGContainerWatcher_Start",
			fields: fields{
				containerCollection: &cc,
				relevancyManager:    &relevancymanagerV1.RelevancyManager{},
			},
			args: args{ctx: context.TODO()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := &IGContainerWatcher{
				containerCollection: tt.fields.containerCollection,
				k8sClient:           tt.fields.k8sClient,
				relevancyManager:    tt.fields.relevancyManager,
				tracerCollection:    tt.fields.tracerCollection,
				tracerExec:          tt.fields.tracerExec,
				tracerOpen:          tt.fields.tracerOpen,
				workerPool:          tt.fields.workerPool,
			}
			if err := ch.Start(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("Start() error = %v, wantErr %v", err, tt.wantErr)
			}
			ch.Stop()
		})
	}
}

func TestIGContainerWatcher_UnregisterContainer(t *testing.T) {
	type fields struct {
		containerCollection *containercollection.ContainerCollection
		k8sClient           *k8sinterface.KubernetesApi
		relevancyManager    relevancymanager.RelevancyManagerClient
		tracerCollection    *tracercollection.TracerCollection
		tracerExec          *tracerexec.Tracer
		tracerOpen          *traceropen.Tracer
		workerPool          *workerpool.WorkerPool
	}
	type args struct {
		ctx       context.Context
		container *containercollection.Container
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := &IGContainerWatcher{
				containerCollection: tt.fields.containerCollection,
				k8sClient:           tt.fields.k8sClient,
				relevancyManager:    tt.fields.relevancyManager,
				tracerCollection:    tt.fields.tracerCollection,
				tracerExec:          tt.fields.tracerExec,
				tracerOpen:          tt.fields.tracerOpen,
				workerPool:          tt.fields.workerPool,
			}
			ch.UnregisterContainer(tt.args.ctx, tt.args.container)
		})
	}
}

func TestIGContainerWatcher_printNsMap(t *testing.T) {
	type fields struct {
		containerCollection *containercollection.ContainerCollection
		k8sClient           *k8sinterface.KubernetesApi
		relevancyManager    relevancymanager.RelevancyManagerClient
		tracerCollection    *tracercollection.TracerCollection
		tracerExec          *tracerexec.Tracer
		tracerOpen          *traceropen.Tracer
		workerPool          *workerpool.WorkerPool
	}
	type args struct {
		id string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := &IGContainerWatcher{
				containerCollection: tt.fields.containerCollection,
				k8sClient:           tt.fields.k8sClient,
				relevancyManager:    tt.fields.relevancyManager,
				tracerCollection:    tt.fields.tracerCollection,
				tracerExec:          tt.fields.tracerExec,
				tracerOpen:          tt.fields.tracerOpen,
				workerPool:          tt.fields.workerPool,
			}
			ch.printNsMap(tt.args.id)
		})
	}
}
