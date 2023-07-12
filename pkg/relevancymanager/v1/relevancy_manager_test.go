package relevancymanager

import (
	"context"
	"node-agent/pkg/config"
	"node-agent/pkg/containerwatcher"
	"node-agent/pkg/filehandler"
	"node-agent/pkg/storageclient"
	"reflect"
	"sync"
	"testing"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/k8s-interface/instanceidhandler"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/spf13/afero"
)

func TestRelevancyManager_ReportContainerStarted(t *testing.T) {
	type fields struct {
		afterTimerActionsChannel chan afterTimerActionsData
		cfg                      config.Config
		clusterName              string
		containerHandler         containerwatcher.ContainerWatcher
		fileHandler              filehandler.FileHandler
		k8sClient                *k8sinterface.KubernetesApi
		sbomFs                   afero.Fs
		storageClient            storageclient.StorageClient
		watchedContainers        sync.Map
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
		{
			name: "TestRelevancyManager_ReportContainerStarted",
			args: args{
				container: &containercollection.Container{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := &RelevancyManager{
				afterTimerActionsChannel: tt.fields.afterTimerActionsChannel,
				cfg:                      tt.fields.cfg,
				clusterName:              tt.fields.clusterName,
				containerHandler:         tt.fields.containerHandler,
				fileHandler:              tt.fields.fileHandler,
				k8sClient:                tt.fields.k8sClient,
				sbomFs:                   tt.fields.sbomFs,
				storageClient:            tt.fields.storageClient,
				watchedContainers:        tt.fields.watchedContainers,
			}
			rm.ReportContainerStarted(tt.args.ctx, tt.args.container)
		})
	}
}

func TestRelevancyManager_ReportContainerTerminated(t *testing.T) {
	type fields struct {
		afterTimerActionsChannel chan afterTimerActionsData
		cfg                      config.Config
		clusterName              string
		containerHandler         containerwatcher.ContainerWatcher
		fileHandler              filehandler.FileHandler
		k8sClient                *k8sinterface.KubernetesApi
		sbomFs                   afero.Fs
		storageClient            storageclient.StorageClient
		watchedContainers        sync.Map
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
			rm := &RelevancyManager{
				afterTimerActionsChannel: tt.fields.afterTimerActionsChannel,
				cfg:                      tt.fields.cfg,
				clusterName:              tt.fields.clusterName,
				containerHandler:         tt.fields.containerHandler,
				fileHandler:              tt.fields.fileHandler,
				k8sClient:                tt.fields.k8sClient,
				sbomFs:                   tt.fields.sbomFs,
				storageClient:            tt.fields.storageClient,
				watchedContainers:        tt.fields.watchedContainers,
			}
			rm.ReportContainerTerminated(tt.args.ctx, tt.args.container)
		})
	}
}

func TestRelevancyManager_ReportFileAccess(t *testing.T) {
	type fields struct {
		afterTimerActionsChannel chan afterTimerActionsData
		cfg                      config.Config
		clusterName              string
		containerHandler         containerwatcher.ContainerWatcher
		fileHandler              filehandler.FileHandler
		k8sClient                *k8sinterface.KubernetesApi
		sbomFs                   afero.Fs
		storageClient            storageclient.StorageClient
		watchedContainers        sync.Map
	}
	type args struct {
		ctx       context.Context
		namespace string
		pod       string
		container string
		file      string
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
			rm := &RelevancyManager{
				afterTimerActionsChannel: tt.fields.afterTimerActionsChannel,
				cfg:                      tt.fields.cfg,
				clusterName:              tt.fields.clusterName,
				containerHandler:         tt.fields.containerHandler,
				fileHandler:              tt.fields.fileHandler,
				k8sClient:                tt.fields.k8sClient,
				sbomFs:                   tt.fields.sbomFs,
				storageClient:            tt.fields.storageClient,
				watchedContainers:        tt.fields.watchedContainers,
			}
			rm.ReportFileAccess(tt.args.ctx, tt.args.namespace, tt.args.pod, tt.args.container, tt.args.file)
		})
	}
}

func TestRelevancyManager_SetContainerHandler(t *testing.T) {
	type fields struct {
		afterTimerActionsChannel chan afterTimerActionsData
		cfg                      config.Config
		clusterName              string
		containerHandler         containerwatcher.ContainerWatcher
		fileHandler              filehandler.FileHandler
		k8sClient                *k8sinterface.KubernetesApi
		sbomFs                   afero.Fs
		storageClient            storageclient.StorageClient
		watchedContainers        sync.Map
	}
	type args struct {
		containerHandler containerwatcher.ContainerWatcher
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
			rm := &RelevancyManager{
				afterTimerActionsChannel: tt.fields.afterTimerActionsChannel,
				cfg:                      tt.fields.cfg,
				clusterName:              tt.fields.clusterName,
				containerHandler:         tt.fields.containerHandler,
				fileHandler:              tt.fields.fileHandler,
				k8sClient:                tt.fields.k8sClient,
				sbomFs:                   tt.fields.sbomFs,
				storageClient:            tt.fields.storageClient,
				watchedContainers:        tt.fields.watchedContainers,
			}
			rm.SetContainerHandler(tt.args.containerHandler)
		})
	}
}

func TestRelevancyManager_StartRelevancyManager(t *testing.T) {
	type fields struct {
		afterTimerActionsChannel chan afterTimerActionsData
		cfg                      config.Config
		clusterName              string
		containerHandler         containerwatcher.ContainerWatcher
		fileHandler              filehandler.FileHandler
		k8sClient                *k8sinterface.KubernetesApi
		sbomFs                   afero.Fs
		storageClient            storageclient.StorageClient
		watchedContainers        sync.Map
	}
	type args struct {
		ctx context.Context
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
			rm := &RelevancyManager{
				afterTimerActionsChannel: tt.fields.afterTimerActionsChannel,
				cfg:                      tt.fields.cfg,
				clusterName:              tt.fields.clusterName,
				containerHandler:         tt.fields.containerHandler,
				fileHandler:              tt.fields.fileHandler,
				k8sClient:                tt.fields.k8sClient,
				sbomFs:                   tt.fields.sbomFs,
				storageClient:            tt.fields.storageClient,
				watchedContainers:        tt.fields.watchedContainers,
			}
			rm.StartRelevancyManager(tt.args.ctx)
		})
	}
}

func TestRelevancyManager_afterTimerActions(t *testing.T) {
	type fields struct {
		afterTimerActionsChannel chan afterTimerActionsData
		cfg                      config.Config
		clusterName              string
		containerHandler         containerwatcher.ContainerWatcher
		fileHandler              filehandler.FileHandler
		k8sClient                *k8sinterface.KubernetesApi
		sbomFs                   afero.Fs
		storageClient            storageclient.StorageClient
		watchedContainers        sync.Map
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
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := &RelevancyManager{
				afterTimerActionsChannel: tt.fields.afterTimerActionsChannel,
				cfg:                      tt.fields.cfg,
				clusterName:              tt.fields.clusterName,
				containerHandler:         tt.fields.containerHandler,
				fileHandler:              tt.fields.fileHandler,
				k8sClient:                tt.fields.k8sClient,
				sbomFs:                   tt.fields.sbomFs,
				storageClient:            tt.fields.storageClient,
				watchedContainers:        tt.fields.watchedContainers,
			}
			if err := rm.afterTimerActions(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("afterTimerActions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRelevancyManager_deleteResources(t *testing.T) {
	type fields struct {
		afterTimerActionsChannel chan afterTimerActionsData
		cfg                      config.Config
		clusterName              string
		containerHandler         containerwatcher.ContainerWatcher
		fileHandler              filehandler.FileHandler
		k8sClient                *k8sinterface.KubernetesApi
		sbomFs                   afero.Fs
		storageClient            storageclient.StorageClient
		watchedContainers        sync.Map
	}
	type args struct {
		watchedContainer watchedContainerData
		containerID      string
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
			rm := &RelevancyManager{
				afterTimerActionsChannel: tt.fields.afterTimerActionsChannel,
				cfg:                      tt.fields.cfg,
				clusterName:              tt.fields.clusterName,
				containerHandler:         tt.fields.containerHandler,
				fileHandler:              tt.fields.fileHandler,
				k8sClient:                tt.fields.k8sClient,
				sbomFs:                   tt.fields.sbomFs,
				storageClient:            tt.fields.storageClient,
				watchedContainers:        tt.fields.watchedContainers,
			}
			rm.deleteResources(tt.args.watchedContainer, tt.args.containerID)
		})
	}
}

func TestRelevancyManager_getSBOM(t *testing.T) {
	type fields struct {
		afterTimerActionsChannel chan afterTimerActionsData
		cfg                      config.Config
		clusterName              string
		containerHandler         containerwatcher.ContainerWatcher
		fileHandler              filehandler.FileHandler
		k8sClient                *k8sinterface.KubernetesApi
		sbomFs                   afero.Fs
		storageClient            storageclient.StorageClient
		watchedContainers        sync.Map
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
			rm := &RelevancyManager{
				afterTimerActionsChannel: tt.fields.afterTimerActionsChannel,
				cfg:                      tt.fields.cfg,
				clusterName:              tt.fields.clusterName,
				containerHandler:         tt.fields.containerHandler,
				fileHandler:              tt.fields.fileHandler,
				k8sClient:                tt.fields.k8sClient,
				sbomFs:                   tt.fields.sbomFs,
				storageClient:            tt.fields.storageClient,
				watchedContainers:        tt.fields.watchedContainers,
			}
			rm.getSBOM(tt.args.ctx, tt.args.container)
		})
	}
}

func TestRelevancyManager_parsePodData(t *testing.T) {
	type fields struct {
		afterTimerActionsChannel chan afterTimerActionsData
		cfg                      config.Config
		clusterName              string
		containerHandler         containerwatcher.ContainerWatcher
		fileHandler              filehandler.FileHandler
		k8sClient                *k8sinterface.KubernetesApi
		sbomFs                   afero.Fs
		storageClient            storageclient.StorageClient
		watchedContainers        sync.Map
	}
	type args struct {
		ctx       context.Context
		pod       *workloadinterface.Workload
		container *containercollection.Container
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		want1   string
		want2   string
		want3   instanceidhandler.IInstanceID
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := &RelevancyManager{
				afterTimerActionsChannel: tt.fields.afterTimerActionsChannel,
				cfg:                      tt.fields.cfg,
				clusterName:              tt.fields.clusterName,
				containerHandler:         tt.fields.containerHandler,
				fileHandler:              tt.fields.fileHandler,
				k8sClient:                tt.fields.k8sClient,
				sbomFs:                   tt.fields.sbomFs,
				storageClient:            tt.fields.storageClient,
				watchedContainers:        tt.fields.watchedContainers,
			}
			got, got1, got2, got3, err := rm.parsePodData(tt.args.ctx, tt.args.pod, tt.args.container)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePodData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parsePodData() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("parsePodData() got1 = %v, want %v", got1, tt.want1)
			}
			if got2 != tt.want2 {
				t.Errorf("parsePodData() got2 = %v, want %v", got2, tt.want2)
			}
			if !reflect.DeepEqual(got3, tt.want3) {
				t.Errorf("parsePodData() got3 = %v, want %v", got3, tt.want3)
			}
		})
	}
}

func TestRelevancyManager_startRelevancyProcess(t *testing.T) {
	type fields struct {
		afterTimerActionsChannel chan afterTimerActionsData
		cfg                      config.Config
		clusterName              string
		containerHandler         containerwatcher.ContainerWatcher
		fileHandler              filehandler.FileHandler
		k8sClient                *k8sinterface.KubernetesApi
		sbomFs                   afero.Fs
		storageClient            storageclient.StorageClient
		watchedContainers        sync.Map
	}
	type args struct {
		ctx            context.Context
		container      *containercollection.Container
		k8sContainerID string
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
			rm := &RelevancyManager{
				afterTimerActionsChannel: tt.fields.afterTimerActionsChannel,
				cfg:                      tt.fields.cfg,
				clusterName:              tt.fields.clusterName,
				containerHandler:         tt.fields.containerHandler,
				fileHandler:              tt.fields.fileHandler,
				k8sClient:                tt.fields.k8sClient,
				sbomFs:                   tt.fields.sbomFs,
				storageClient:            tt.fields.storageClient,
				watchedContainers:        tt.fields.watchedContainers,
			}
			rm.startRelevancyProcess(tt.args.ctx, tt.args.container, tt.args.k8sContainerID)
		})
	}
}

func TestRelevancyManager_startTimer(t *testing.T) {
	type fields struct {
		afterTimerActionsChannel chan afterTimerActionsData
		cfg                      config.Config
		clusterName              string
		containerHandler         containerwatcher.ContainerWatcher
		fileHandler              filehandler.FileHandler
		k8sClient                *k8sinterface.KubernetesApi
		sbomFs                   afero.Fs
		storageClient            storageclient.StorageClient
		watchedContainers        sync.Map
	}
	type args struct {
		watchedContainer watchedContainerData
		containerID      string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := &RelevancyManager{
				afterTimerActionsChannel: tt.fields.afterTimerActionsChannel,
				cfg:                      tt.fields.cfg,
				clusterName:              tt.fields.clusterName,
				containerHandler:         tt.fields.containerHandler,
				fileHandler:              tt.fields.fileHandler,
				k8sClient:                tt.fields.k8sClient,
				sbomFs:                   tt.fields.sbomFs,
				storageClient:            tt.fields.storageClient,
				watchedContainers:        tt.fields.watchedContainers,
			}
			if err := rm.startTimer(tt.args.watchedContainer, tt.args.containerID); (err != nil) != tt.wantErr {
				t.Errorf("startTimer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
