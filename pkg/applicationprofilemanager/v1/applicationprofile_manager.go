package applicationprofilemanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"node-agent/pkg/applicationprofilemanager"
	"node-agent/pkg/config"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/storage"
	"node-agent/pkg/utils"
	"sort"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"

	"github.com/armosec/utils-k8s-go/wlid"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/names"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ApplicationProfileManager struct {
	cfg                      config.Config
	clusterName              string
	ctx                      context.Context
	capabilitiesSets         maps.SafeMap[string, mapset.Set[string]]                        // key is k8sContainerID
	execMaps                 maps.SafeMap[string, *maps.SafeMap[string, mapset.Set[string]]] // key is k8sContainerID
	openMaps                 maps.SafeMap[string, *maps.SafeMap[string, mapset.Set[string]]] // key is k8sContainerID
	watchedContainerChannels maps.SafeMap[string, chan error]                                // key is ContainerID
	savedCapabilities        maps.SafeMap[string, int]
	savedSyscalls            maps.SafeMap[string, int]
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

	// get pod template hash
	watchedContainer.TemplateHash, _ = pod.GetLabel("pod-template-hash")

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
	watchedContainer.ParentResourceVersion = w.GetResourceVersion()
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
	if watchedContainer.ContainerType == utils.Unknown {
		watchedContainer.SetContainerType(pod, container.K8s.ContainerName)
	}

	// FIXME ephemeralContainers are not supported yet
}

func (am *ApplicationProfileManager) deleteResources(watchedContainer *utils.WatchedContainerData) {
	watchedContainer.UpdateDataTicker.Stop()
	am.capabilitiesSets.Delete(watchedContainer.K8sContainerID)
	am.execMaps.Delete(watchedContainer.K8sContainerID)
	am.openMaps.Delete(watchedContainer.K8sContainerID)
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

type PatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

func (am *ApplicationProfileManager) saveProfile(ctx context.Context, watchedContainer *utils.WatchedContainerData, namespace string) {
	ctx, span := otel.Tracer("").Start(ctx, "ApplicationProfileManager.saveProfile")
	defer span.End()

	if watchedContainer.InstanceID == nil {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - instanceID is nil")
		return
	}

	// leave container name empty this way the "slug" will represent a workload
	slug, err := names.InstanceIDToSlug(watchedContainer.InstanceID.GetName(), watchedContainer.InstanceID.GetKind(), "", watchedContainer.InstanceID.GetHashed())
	if err != nil {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to get slug", helpers.Error(err))
		return
	}

	// get syscalls from IG
	observedSyscalls, err := am.syscallPeekFunc(watchedContainer.NsMntId)
	if err != nil {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to get syscalls", helpers.Error(err))
	}
	// check if we have new activities to save
	if len(observedSyscalls) > am.savedSyscalls.Get(watchedContainer.K8sContainerID) {
		newActivity := &v1beta1.ApplicationActivity{
			ObjectMeta: metav1.ObjectMeta{
				Name: slug,
				Annotations: map[string]string{
					helpersv1.WlidMetadataKey:   watchedContainer.Wlid,
					helpersv1.StatusMetadataKey: helpersv1.Ready,
				},
				Labels: utils.GetLabels(watchedContainer, true),
			},
		}
		// add syscalls
		newActivity.Spec.Syscalls = observedSyscalls
		// save application activity
		if err := am.storageClient.CreateApplicationActivity(newActivity, namespace); err != nil {
			logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to save application activity", helpers.Error(err))
		} else {
			am.savedSyscalls.Set(watchedContainer.K8sContainerID, len(observedSyscalls))
			logger.L().Debug("ApplicationProfileManager - saved application activity", helpers.String("slug", slug), helpers.String("container ID", watchedContainer.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID))
		}
	}

	// profile sets
	var addedProfiles int
	execs := make(map[string]mapset.Set[string])
	opens := make(map[string]mapset.Set[string])
	// get capabilities, execs and opens from IG
	var observedCapabilities []string
	newCapabilitiesSet := mapset.NewSet[string]()
	capabilitiesSet, ok := am.capabilitiesSets.Load(watchedContainer.K8sContainerID)
	if ok {
		// replace the capabilities set with a new one
		am.capabilitiesSets.Set(watchedContainer.K8sContainerID, newCapabilitiesSet)
		observedCapabilities = capabilitiesSet.ToSlice()
	}
	newExecMap := new(maps.SafeMap[string, mapset.Set[string]])
	execMap, ok := am.execMaps.Load(watchedContainer.K8sContainerID)
	if ok {
		// replace the exec map with a new one
		am.execMaps.Set(watchedContainer.K8sContainerID, newExecMap)
		// if we fail to save the profile we will restore execMap entries
		execMap.Range(func(path string, exec mapset.Set[string]) bool {
			if _, exist := execs[path]; !exist {
				execs[path] = mapset.NewSet[string]()
			}
			addedProfiles += execs[path].Append(exec.ToSlice()...)
			return true
		})
	}
	newOpenMap := new(maps.SafeMap[string, mapset.Set[string]])
	openMap, ok := am.openMaps.Load(watchedContainer.K8sContainerID)
	if ok {
		// replace the open map with a new one
		am.openMaps.Set(watchedContainer.K8sContainerID, newOpenMap)
		// if we fail to save the profile we will restore openMap entries
		openMap.Range(func(path string, open mapset.Set[string]) bool {
			if _, exist := opens[path]; !exist {
				opens[path] = mapset.NewSet[string]()
			}
			addedProfiles += opens[path].Append(open.ToSlice()...)
			return true
		})
	}
	// new profile
	if addedProfiles > 0 || len(observedCapabilities) > am.savedCapabilities.Get(watchedContainer.K8sContainerID) {
		var profileOperations []PatchOperation
		newProfile := &v1beta1.ApplicationProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name: slug,
				Annotations: map[string]string{
					helpersv1.WlidMetadataKey:   watchedContainer.Wlid,
					helpersv1.StatusMetadataKey: helpersv1.Ready,
				},
				Labels: utils.GetLabels(watchedContainer, true),
			},
		}
		newProfileContainer := &v1beta1.ApplicationProfileContainer{
			Name: watchedContainer.InstanceID.GetContainerName(),
		}
		// add capabilities
		sort.Strings(observedCapabilities)
		newProfileContainer.Capabilities = observedCapabilities
		capabilitiesPath := fmt.Sprintf("/spec/containers/%d/capabilities/-", watchedContainer.ContainerIndex)
		for _, capability := range observedCapabilities {
			profileOperations = append(profileOperations, PatchOperation{
				Op:    "add",
				Path:  capabilitiesPath,
				Value: capability,
			})
		}
		// add execs
		newProfileContainer.Execs = make([]v1beta1.ExecCalls, 0)
		execsPath := fmt.Sprintf("/spec/containers/%d/execs/-", watchedContainer.ContainerIndex)
		for path, exec := range execs {
			args := exec.ToSlice()
			sort.Strings(args)
			newExec := v1beta1.ExecCalls{
				Path: path,
				Args: args,
			}
			newProfileContainer.Execs = append(newProfileContainer.Execs, newExec)
			profileOperations = append(profileOperations, PatchOperation{
				Op:    "add",
				Path:  execsPath,
				Value: newExec,
			})
		}
		// add opens
		newProfileContainer.Opens = make([]v1beta1.OpenCalls, 0)
		opensPath := fmt.Sprintf("/spec/containers/%d/opens/-", watchedContainer.ContainerIndex)
		for path, open := range opens {
			flags := open.ToSlice()
			sort.Strings(flags)
			newOpen := v1beta1.OpenCalls{
				Path:  path,
				Flags: flags,
			}
			newProfileContainer.Opens = append(newProfileContainer.Opens, newOpen)
			profileOperations = append(profileOperations, PatchOperation{
				Op:    "add",
				Path:  opensPath,
				Value: newOpen,
			})
		}
		// insert application profile container
		utils.InsertApplicationProfileContainer(newProfile, watchedContainer.ContainerType, watchedContainer.ContainerIndex, newProfileContainer)
		// calculate patch
		patch, err := json.Marshal(profileOperations)
		if err != nil {
			logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to marshal patch", helpers.Error(err))
			return
		}
		// save application profile
		var gotErr error
		if err := am.storageClient.PatchApplicationProfile(slug, namespace, patch); err != nil {
			if apierrors.IsNotFound(err) {
				if err := am.storageClient.CreateApplicationProfile(newProfile, namespace); err != nil {
					gotErr = err
					logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to create application profile", helpers.Error(err))
				}
			} else {
				gotErr = err
				logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to patch application profile", helpers.Error(err))
			}
		}
		if gotErr != nil {
			// restore capabilities set
			newCapabilitiesSet.Append(capabilitiesSet.ToSlice()...)
			// restore execMap entries
			execMap.Range(func(k string, v mapset.Set[string]) bool {
				if newExecMap.Has(k) {
					newExecMap.Get(k).Append(v.ToSlice()...)
				} else {
					newExecMap.Set(k, v)
				}
				return true
			})
			// restore openMap entries
			openMap.Range(func(k string, v mapset.Set[string]) bool {
				if newOpenMap.Has(k) {
					newOpenMap.Get(k).Append(v.ToSlice()...)
				} else {
					newOpenMap.Set(k, v)
				}
				return true
			})
		} else {
			am.savedCapabilities.Set(watchedContainer.K8sContainerID, len(observedCapabilities))
			logger.L().Debug("ApplicationProfileManager - saved application profile", helpers.String("slug", slug), helpers.String("container ID", watchedContainer.ContainerID), helpers.String("k8s workload", watchedContainer.K8sContainerID))
			// profile summary
			summary := &v1beta1.ApplicationProfileSummary{
				ObjectMeta: newProfile.ObjectMeta,
			}
			if err := am.storageClient.CreateApplicationProfileSummary(summary, namespace); err != nil {
				logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to save application profile summary", helpers.Error(err))
			}
		}
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
		am.execMaps.Set(k8sContainerID, new(maps.SafeMap[string, mapset.Set[string]]))
		am.openMaps.Set(k8sContainerID, new(maps.SafeMap[string, mapset.Set[string]]))
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
	capabilitiesSet, err := utils.WaitGetSafeMap(&am.capabilitiesSets, k8sContainerID)
	if err != nil {
		return
	}
	capabilitiesSet.Add(capability)
}

func (am *ApplicationProfileManager) ReportFileExec(k8sContainerID, path string, args []string) {
	// skip empty path
	if path == "" {
		return
	}
	execMap, err := utils.WaitGetSafeMap(&am.execMaps, k8sContainerID)
	if err != nil {
		return
	}
	if execMap.Has(path) {
		execMap.Get(path).Append(args...)
	} else {
		execMap.Set(path, mapset.NewSet[string](args...))
	}
}

func (am *ApplicationProfileManager) ReportFileOpen(k8sContainerID, path string, flags []string) {
	openMap, err := utils.WaitGetSafeMap(&am.openMaps, k8sContainerID)
	if err != nil {
		return
	}
	if openMap.Has(path) {
		openMap.Get(path).Append(flags...)
	} else {
		openMap.Set(path, mapset.NewSet[string](flags...))
	}
}
