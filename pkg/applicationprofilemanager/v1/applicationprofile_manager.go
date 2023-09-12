package applicationprofilemanager

import (
	"context"
	"errors"
	"node-agent/pkg/applicationprofilemanager"
	"node-agent/pkg/config"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/storage"
	"node-agent/pkg/utils"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	instanceidhandlerV1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ApplicationProfileManager struct {
	cfg                      config.Config
	ctx                      context.Context
	capabilitiesSets         sync.Map // key is k8sContainerID
	execSets                 sync.Map // key is k8sContainerID
	openSets                 sync.Map // key is k8sContainerID
	watchedContainerChannels sync.Map // key is ContainerID
	k8sClient                k8sclient.K8sClientInterface
	storageClient            storage.StorageClient
	syscallPeekFunc          func(nsMountId uint64) ([]string, error)
}

type execStruct struct {
	path string
	args mapset.Set[string]
}

type openStruct struct {
	path  string
	flags mapset.Set[string]
}

var _ applicationprofilemanager.ApplicationProfileManagerClient = (*ApplicationProfileManager)(nil)

func CreateApplicationProfileManager(ctx context.Context, cfg config.Config, k8sClient k8sclient.K8sClientInterface, storageClient storage.StorageClient) (*ApplicationProfileManager, error) {
	return &ApplicationProfileManager{
		cfg:           cfg,
		ctx:           ctx,
		k8sClient:     k8sClient,
		storageClient: storageClient,
	}, nil
}

func (am *ApplicationProfileManager) ensureInstanceID(ctx context.Context, container *containercollection.Container, watchedContainer *utils.WatchedContainerData) {
	if watchedContainer.InstanceID != nil {
		return
	}
	wl, err := am.k8sClient.GetWorkload(container.K8s.Namespace, "Pod", container.K8s.PodName)
	if err != nil {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to get workload", helpers.Error(err))
		return
	}
	pod := wl.(*workloadinterface.Workload)
	// find instanceID
	instanceIDs, err := instanceidhandlerV1.GenerateInstanceID(pod)
	if err != nil {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to generate instanceID", helpers.Error(err))
		return
	}
	watchedContainer.InstanceID = instanceIDs[0]
	for i := range instanceIDs {
		if instanceIDs[i].GetContainerName() == container.K8s.ContainerName {
			watchedContainer.InstanceID = instanceIDs[i]
		}
	}
}

func (am *ApplicationProfileManager) deleteResources(watchedContainer *utils.WatchedContainerData) {
	watchedContainer.UpdateDataTicker.Stop()
	am.capabilitiesSets.Delete(watchedContainer.K8sContainerID)
	am.execSets.Delete(watchedContainer.K8sContainerID)
	am.openSets.Delete(watchedContainer.K8sContainerID)
	am.watchedContainerChannels.Delete(watchedContainer.ContainerID)
}

func (am *ApplicationProfileManager) monitorContainer(ctx context.Context, container *containercollection.Container, watchedContainer *utils.WatchedContainerData) error {
	for {
		select {
		case <-watchedContainer.UpdateDataTicker.C:
			// adjust ticker after first tick
			if !watchedContainer.InitialDelayExpired {
				watchedContainer.InitialDelayExpired = true
				watchedContainer.UpdateDataTicker.Reset(am.cfg.UpdateDataPeriod)
			}
			am.ensureInstanceID(ctx, container, watchedContainer)
			am.saveProfile(ctx, watchedContainer, container.K8s.Namespace)
		case err := <-watchedContainer.SyncChannel:
			switch {
			case errors.Is(err, utils.ContainerHasTerminatedError):
				am.ensureInstanceID(ctx, container, watchedContainer)
				am.saveProfile(ctx, watchedContainer, container.K8s.Namespace)
				return nil
			}
		}
	}
}

func (am *ApplicationProfileManager) saveProfile(ctx context.Context, watchedContainer *utils.WatchedContainerData, namespace string) {
	ctx, span := otel.Tracer("").Start(ctx, "ApplicationProfileManager.saveProfile")
	defer span.End()

	if watchedContainer.InstanceID == nil {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - instanceID is nil")
		return
	}
	slug, err := watchedContainer.InstanceID.GetSlug()
	if err != nil {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to get slug", helpers.Error(err))
		return
	}

	// activity
	activity := &v1beta1.ApplicationActivity{
		ObjectMeta: metav1.ObjectMeta{
			Name: slug,
		},
	}
	syscalls, err := am.syscallPeekFunc(watchedContainer.NsMntId)
	if err == nil {
		activity.Spec.Syscalls = syscalls
	} else {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to get syscalls", helpers.Error(err))
	}
	if err := am.storageClient.CreateApplicationActivity(activity, namespace); err != nil {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to save application activity", helpers.Error(err))
	}

	// profile
	profile := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: slug,
		},
	}
	// add capabilities
	if value, ok := am.capabilitiesSets.Load(watchedContainer.K8sContainerID); ok {
		set := value.(*mapset.Set[string])
		profile.Spec.Capabilities = (*set).ToSlice()
	}
	// add execs
	if value, ok := am.execSets.Load(watchedContainer.K8sContainerID); ok {
		set := value.(*mapset.Set[execStruct])
		profile.Spec.Execs = make([]v1beta1.ExecCalls, 0)
		for _, exec := range (*set).ToSlice() {
			profile.Spec.Execs = append(profile.Spec.Execs, v1beta1.ExecCalls{
				Path: exec.path,
				Args: exec.args.ToSlice(),
			})
		}
	}
	// add opens
	if value, ok := am.openSets.Load(watchedContainer.K8sContainerID); ok {
		set := value.(*mapset.Set[openStruct])
		profile.Spec.Opens = make([]v1beta1.OpenCalls, 0)
		for _, open := range (*set).ToSlice() {
			profile.Spec.Opens = append(profile.Spec.Opens, v1beta1.OpenCalls{
				Path:  open.path,
				Flags: open.flags.ToSlice(),
			})
		}
	}
	if err := am.storageClient.CreateApplicationProfile(profile, namespace); err != nil {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to save application profile", helpers.Error(err))
	}
	// profile summary
	summary := &v1beta1.ApplicationProfileSummary{
		ObjectMeta: profile.ObjectMeta,
	}
	if err := am.storageClient.CreateApplicationProfileSummary(summary, namespace); err != nil {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to save application profile summary", helpers.Error(err))
	}
}

func (am *ApplicationProfileManager) startApplicationProfiling(ctx context.Context, container *containercollection.Container, k8sContainerID string) {
	ctx, span := otel.Tracer("").Start(ctx, "ApplicationProfileManager.startApplicationProfiling")
	defer span.End()

	syncChannel := make(chan error, 10)
	am.watchedContainerChannels.Store(container.Runtime.ContainerID, syncChannel)

	watchedContainer := &utils.WatchedContainerData{
		ContainerID:      container.Runtime.ContainerID,
		UpdateDataTicker: time.NewTicker(utils.AddRandomDuration(5, 10, am.cfg.InitialDelay)), // get out of sync with the relevancy manager
		SyncChannel:      syncChannel,
		K8sContainerID:   k8sContainerID,
		NsMntId:          container.Mntns,
	}

	if err := am.monitorContainer(ctx, container, watchedContainer); err != nil {
		logger.L().Info("ApplicationProfileManager - stop monitor on container", helpers.String("reason", err.Error()), helpers.String("container ID", container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
	}

	am.deleteResources(watchedContainer)
}

func (am *ApplicationProfileManager) ContainerCallback(notif containercollection.PubSubEvent) {
	k8sContainerID := utils.CreateK8sContainerID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.ContainerName)
	ctx, span := otel.Tracer("").Start(am.ctx, "ApplicationProfileManager.ContainerCallback", trace.WithAttributes(attribute.String("containerID", notif.Container.Runtime.ContainerID), attribute.String("k8s workload", k8sContainerID)))
	defer span.End()

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		_, exist := am.watchedContainerChannels.Load(notif.Container.Runtime.ContainerID)
		if exist {
			logger.L().Debug("container already exist in memory", helpers.String("container ID", notif.Container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
			return
		}
		capabilitiesSet := mapset.NewSet[string]()
		am.capabilitiesSets.Store(k8sContainerID, &capabilitiesSet)
		execSet := mapset.NewSet[execStruct]()
		am.execSets.Store(k8sContainerID, &execSet)
		openSet := mapset.NewSet[openStruct]()
		am.openSets.Store(k8sContainerID, &openSet)
		go am.startApplicationProfiling(ctx, notif.Container, k8sContainerID)
	case containercollection.EventTypeRemoveContainer:
		if channel, ok := am.watchedContainerChannels.LoadAndDelete(notif.Container.Runtime.ContainerID); ok {
			if !ok {
				logger.L().Debug("container not found in memory", helpers.String("container ID", notif.Container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
				return
			}
			channel.(chan error) <- utils.ContainerHasTerminatedError
		}
	}
}

func (am *ApplicationProfileManager) RegisterPeekFunc(peek func(mntns uint64) ([]string, error)) {
	am.syscallPeekFunc = peek
}

func (am *ApplicationProfileManager) ReportCapability(k8sContainerID, capability string) {
	if value, ok := am.capabilitiesSets.Load(k8sContainerID); ok {
		set := value.(*mapset.Set[string])
		(*set).Add(capability)
	}
}

func (am *ApplicationProfileManager) ReportFileExec(k8sContainerID, path string, args []string) {
	if value, ok := am.execSets.Load(k8sContainerID); ok {
		set := value.(*mapset.Set[execStruct])
		(*set).Add(execStruct{
			path: path,
			args: mapset.NewSet[string](args...),
		})
	}
}

func (am *ApplicationProfileManager) ReportFileOpen(k8sContainerID, path string, flags []string) {
	if value, ok := am.openSets.Load(k8sContainerID); ok {
		set := value.(*mapset.Set[openStruct])
		(*set).Add(openStruct{
			path:  path,
			flags: mapset.NewSet[string](flags...),
		})
	}
}
