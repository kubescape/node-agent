package applicationprofilemanager

import (
	"context"
	"errors"
	"node-agent/pkg/applicationprofilemanager"
	"node-agent/pkg/config"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/storage"
	"node-agent/pkg/utils"
	"sort"
	"time"

	"github.com/armosec/utils-k8s-go/wlid"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ApplicationProfileManager struct {
	cfg                      config.Config
	clusterName              string
	ctx                      context.Context
	capabilitiesSets         maps.SafeMap[string, mapset.Set[string]]            // key is k8sContainerID
	execSets                 maps.SafeMap[string, map[string]mapset.Set[string]] // key is k8sContainerID
	openSets                 maps.SafeMap[string, map[string]mapset.Set[string]] // key is k8sContainerID
	watchedContainerChannels maps.SafeMap[string, chan error]                    // key is ContainerID
	k8sClient                k8sclient.K8sClientInterface
	storageClient            storage.StorageClient
	syscallPeekFunc          func(nsMountId uint64) ([]string, error)
}

var _ applicationprofilemanager.ApplicationProfileManagerClient = (*ApplicationProfileManager)(nil)

func CreateApplicationProfileManager(ctx context.Context, cfg config.Config, clusterName string, k8sClient k8sclient.K8sClientInterface, storageClient storage.StorageClient) (*ApplicationProfileManager, error) {
	return &ApplicationProfileManager{
		cfg:           cfg,
		clusterName:   clusterName,
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
	// find parentWlid
	kind, name, err := am.k8sClient.CalculateWorkloadParentRecursive(pod)
	if err != nil {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to calculate workload parent", helpers.Error(err))
		return
	}
	parentWorkload, err := am.k8sClient.GetWorkload(pod.GetNamespace(), kind, name)
	if err != nil {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to get parent workload", helpers.Error(err))
		return
	}
	w := parentWorkload.(*workloadinterface.Workload)
	watchedContainer.Wlid = w.GenerateWlid(am.clusterName)
	err = wlid.IsWlidValid(watchedContainer.Wlid)
	if err != nil {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to validate WLID", helpers.Error(err))
		return
	}
	// find instanceID
	instanceIDs, err := instanceidhandler.GenerateInstanceID(pod)
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
	// find container type and index
	// containers
	if watchedContainer.ContainerType == utils.Unknown {
		containers, err := pod.GetContainers()
		if err != nil {
			logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to get containers", helpers.Error(err))
			return
		}
		for i, c := range containers {
			if c.Name == container.K8s.ContainerName {
				watchedContainer.ContainerIndex = i
				watchedContainer.ContainerType = utils.Container
				break
			}
		}
	}
	// initContainers
	if watchedContainer.ContainerType == utils.Unknown {
		initContainers, err := pod.GetInitContainers()
		if err != nil {
			logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to get init containers", helpers.Error(err))
			return
		}
		for i, c := range initContainers {
			if c.Name == container.K8s.ContainerName {
				watchedContainer.ContainerIndex = i
				watchedContainer.ContainerType = utils.InitContainer
				break
			}
		}
	}
	// FIXME ephemeralContainers are not supported yet
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

	// activity sets
	syscalls := mapset.NewSet[string]()
	// existing activity
	existingActivity, _ := am.storageClient.GetApplicationActivity(slug, namespace)
	if existingActivity != nil {
		syscalls.Append(existingActivity.Spec.Syscalls...)
	}
	// new activity
	newActivity := &v1beta1.ApplicationActivity{
		ObjectMeta: metav1.ObjectMeta{
			Name: slug,
			Annotations: map[string]string{
				instanceidhandler.WlidMetadataKey:   watchedContainer.Wlid,
				instanceidhandler.StatusMetadataKey: "",
			},
			Labels: utils.GetLabels(watchedContainer, true),
		},
	}
	// add syscalls
	newSyscalls, err := am.syscallPeekFunc(watchedContainer.NsMntId)
	if err == nil {
		syscalls.Append(newSyscalls...)
	} else {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to get syscalls", helpers.Error(err))
	}
	newActivity.Spec.Syscalls = syscalls.ToSlice()
	if err := am.storageClient.CreateApplicationActivity(newActivity, namespace); err != nil {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to save application activity", helpers.Error(err))
	}

	// profile sets
	capabilities := am.capabilitiesSets.Get(watchedContainer.K8sContainerID)
	execs := am.execSets.Get(watchedContainer.K8sContainerID)
	opens := am.openSets.Get(watchedContainer.K8sContainerID)
	// existing profile
	existingProfile, _ := am.storageClient.GetApplicationProfile(slug, namespace)
	existingProfileContainer := utils.GetApplicationProfileContainer(existingProfile, watchedContainer.ContainerType, watchedContainer.ContainerIndex)
	if existingProfile != nil {
		capabilities.Append(existingProfileContainer.Capabilities...)
		for _, exec := range existingProfileContainer.Execs {
			if _, exist := execs[exec.Path]; !exist {
				execs[exec.Path] = mapset.NewSet[string]()
			}
			execs[exec.Path].Append(exec.Args...)
		}
		for _, open := range existingProfileContainer.Opens {
			if _, exist := opens[open.Path]; !exist {
				opens[open.Path] = mapset.NewSet[string]()
			}
			opens[open.Path].Append(open.Flags...)
		}
	}
	// new profile
	newProfile := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: slug,
			Annotations: map[string]string{
				instanceidhandler.WlidMetadataKey:   watchedContainer.Wlid,
				instanceidhandler.StatusMetadataKey: "",
			},
			Labels: utils.GetLabels(watchedContainer, true),
		},
	}
	newProfileContainer := v1beta1.ApplicationProfileContainer{
		Name: watchedContainer.InstanceID.GetContainerName(),
	}
	// add capabilities
	newProfileContainer.Capabilities = capabilities.ToSlice()
	sort.Strings(newProfileContainer.Capabilities)
	// add execs
	newProfileContainer.Execs = make([]v1beta1.ExecCalls, 0)
	for path, exec := range execs {
		args := exec.ToSlice()
		sort.Strings(args)
		newProfileContainer.Execs = append(newProfileContainer.Execs, v1beta1.ExecCalls{
			Path: path,
			Args: args,
		})
	}
	// add opens
	newProfileContainer.Opens = make([]v1beta1.OpenCalls, 0)
	for path, open := range opens {
		flags := open.ToSlice()
		sort.Strings(flags)
		newProfileContainer.Opens = append(newProfileContainer.Opens, v1beta1.OpenCalls{
			Path:  path,
			Flags: flags,
		})
	}
	// insert application profile container
	utils.InsertApplicationProfileContainer(newProfile, watchedContainer.ContainerType, watchedContainer.ContainerIndex, newProfileContainer)
	// save application profile
	if err := am.storageClient.CreateApplicationProfile(newProfile, namespace); err != nil {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to save application profile", helpers.Error(err))
	}
	logger.L().Debug("ApplicationProfileManager - saved application profile", helpers.String("slug", slug), helpers.String("container ID", watchedContainer.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID), helpers.Interface("profile", newProfile))
	// profile summary
	summary := &v1beta1.ApplicationProfileSummary{
		ObjectMeta: newProfile.ObjectMeta,
	}
	if err := am.storageClient.CreateApplicationProfileSummary(summary, namespace); err != nil {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to save application profile summary", helpers.Error(err))
	}
}

func (am *ApplicationProfileManager) startApplicationProfiling(ctx context.Context, container *containercollection.Container, k8sContainerID string) {
	ctx, span := otel.Tracer("").Start(ctx, "ApplicationProfileManager.startApplicationProfiling")
	defer span.End()

	syncChannel := make(chan error, 10)
	am.watchedContainerChannels.Set(container.Runtime.ContainerID, syncChannel)

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
		if am.watchedContainerChannels.Has(notif.Container.Runtime.ContainerID) {
			logger.L().Debug("container already exist in memory", helpers.String("container ID", notif.Container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
			return
		}
		am.capabilitiesSets.Set(k8sContainerID, mapset.NewSet[string]())
		am.execSets.Set(k8sContainerID, make(map[string]mapset.Set[string]))
		am.openSets.Set(k8sContainerID, make(map[string]mapset.Set[string]))
		go am.startApplicationProfiling(ctx, notif.Container, k8sContainerID)
	case containercollection.EventTypeRemoveContainer:
		channel := am.watchedContainerChannels.Get(notif.Container.Runtime.ContainerID)
		if channel != nil {
			channel <- utils.ContainerHasTerminatedError
		}
		am.watchedContainerChannels.Delete(notif.Container.Runtime.ContainerID)
	}
}

func (am *ApplicationProfileManager) RegisterPeekFunc(peek func(mntns uint64) ([]string, error)) {
	am.syscallPeekFunc = peek
}

func (am *ApplicationProfileManager) ReportCapability(k8sContainerID, capability string) {
	am.capabilitiesSets.Get(k8sContainerID).Add(capability)
}

func (am *ApplicationProfileManager) ReportFileExec(k8sContainerID, path string, args []string) {
	execs := am.execSets.Get(k8sContainerID)
	if _, exist := execs[path]; !exist {
		execs[path] = mapset.NewSet[string]()
	}
	execs[path].Append(args...)
}

func (am *ApplicationProfileManager) ReportFileOpen(k8sContainerID, path string, flags []string) {
	opens := am.openSets.Get(k8sContainerID)
	if _, exist := opens[path]; !exist {
		opens[path] = mapset.NewSet[string]()
	}
	opens[path].Append(flags...)
}
