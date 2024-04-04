package applicationprofilemanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"node-agent/pkg/applicationprofilemanager"
	"node-agent/pkg/config"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/storage"
	"node-agent/pkg/utils"
	"time"

	"github.com/cenkalti/backoff/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

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
	storageUtils "github.com/kubescape/storage/pkg/utils"
	"go.opentelemetry.io/otel"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ApplicationProfileManager struct {
	cfg                      config.Config
	clusterName              string
	ctx                      context.Context
	containerMutexes         storageUtils.MapMutex[string]                                   // key is k8sContainerID
	trackedContainers        mapset.Set[string]                                              // key is k8sContainerID
	savedCapabilities        maps.SafeMap[string, mapset.Set[string]]                        // key is k8sContainerID
	savedExecs               maps.SafeMap[string, *maps.SafeMap[string, mapset.Set[string]]] // key is k8sContainerID
	droppedEvents            maps.SafeMap[string, bool]                                      // key is k8sContainerID
	savedOpens               maps.SafeMap[string, *maps.SafeMap[string, mapset.Set[string]]] // key is k8sContainerID
	savedSyscalls            maps.SafeMap[string, mapset.Set[string]]                        // key is k8sContainerID
	toSaveCapabilities       maps.SafeMap[string, mapset.Set[string]]                        // key is k8sContainerID
	toSaveExecs              maps.SafeMap[string, *maps.SafeMap[string, mapset.Set[string]]] // key is k8sContainerID
	toSaveOpens              maps.SafeMap[string, *maps.SafeMap[string, mapset.Set[string]]] // key is k8sContainerID
	watchedContainerChannels maps.SafeMap[string, chan error]                                // key is ContainerID
	k8sClient                k8sclient.K8sClientInterface
	k8sObjectCache           objectcache.K8sObjectCache
	storageClient            storage.StorageClient
	syscallPeekFunc          func(nsMountId uint64) ([]string, error)
	preRunningContainerIDs   mapset.Set[string]
}

var _ applicationprofilemanager.ApplicationProfileManagerClient = (*ApplicationProfileManager)(nil)

func CreateApplicationProfileManager(ctx context.Context, cfg config.Config, clusterName string, k8sClient k8sclient.K8sClientInterface, storageClient storage.StorageClient, preRunningContainerIDs mapset.Set[string], k8sObjectCache objectcache.K8sObjectCache) (*ApplicationProfileManager, error) {
	return &ApplicationProfileManager{
		cfg:                    cfg,
		clusterName:            clusterName,
		ctx:                    ctx,
		k8sClient:              k8sClient,
		k8sObjectCache:         k8sObjectCache,
		storageClient:          storageClient,
		containerMutexes:       storageUtils.NewMapMutex[string](),
		trackedContainers:      mapset.NewSet[string](),
		preRunningContainerIDs: preRunningContainerIDs,
	}, nil
}

func (am *ApplicationProfileManager) ensureInstanceID(container *containercollection.Container, watchedContainer *utils.WatchedContainerData) error {
	if watchedContainer.InstanceID != nil {
		return nil
	}
	wl, err := am.k8sClient.GetWorkload(container.K8s.Namespace, "Pod", container.K8s.PodName)
	if err != nil {
		return fmt.Errorf("failed to get workload: %w", err)
	}
	pod := wl.(*workloadinterface.Workload)

	// get pod template hash
	watchedContainer.TemplateHash, _ = pod.GetLabel("pod-template-hash")

	// find parentWlid
	kind, name, err := am.k8sClient.CalculateWorkloadParentRecursive(pod)
	if err != nil {
		return fmt.Errorf("failed to calculate workload parent: %w", err)
	}
	parentWorkload, err := am.k8sClient.GetWorkload(pod.GetNamespace(), kind, name)
	if err != nil {
		return fmt.Errorf("failed to get parent workload: %w", err)
	}
	w := parentWorkload.(*workloadinterface.Workload)
	watchedContainer.Wlid = w.GenerateWlid(am.clusterName)
	err = wlid.IsWlidValid(watchedContainer.Wlid)
	if err != nil {
		return fmt.Errorf("failed to validate WLID: %w", err)
	}
	watchedContainer.ParentResourceVersion = w.GetResourceVersion()
	// find instanceID
	instanceIDs, err := instanceidhandler.GenerateInstanceID(pod)
	if err != nil {
		return fmt.Errorf("failed to generate instanceID: %w", err)
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
	return nil
}

func (am *ApplicationProfileManager) deleteResources(watchedContainer *utils.WatchedContainerData) {
	// make sure we don't run deleteResources and saveProfile at the same time
	am.containerMutexes.Lock(watchedContainer.K8sContainerID)
	defer am.containerMutexes.Unlock(watchedContainer.K8sContainerID)
	// delete resources
	watchedContainer.UpdateDataTicker.Stop()
	am.trackedContainers.Remove(watchedContainer.K8sContainerID)
	am.savedCapabilities.Delete(watchedContainer.K8sContainerID)
	am.savedExecs.Delete(watchedContainer.K8sContainerID)
	am.droppedEvents.Delete(watchedContainer.K8sContainerID)
	am.savedOpens.Delete(watchedContainer.K8sContainerID)
	am.savedSyscalls.Delete(watchedContainer.K8sContainerID)
	am.toSaveCapabilities.Delete(watchedContainer.K8sContainerID)
	am.toSaveExecs.Delete(watchedContainer.K8sContainerID)
	am.toSaveOpens.Delete(watchedContainer.K8sContainerID)
	am.watchedContainerChannels.Delete(watchedContainer.ContainerID)
}

func (am *ApplicationProfileManager) monitorContainer(ctx context.Context, container *containercollection.Container, watchedContainer *utils.WatchedContainerData) error {
	// set completion status & status as soon as we start monitoring the container
	if am.preRunningContainerIDs.Contains(container.Runtime.ContainerID) {
		watchedContainer.SetCompletionStatus(utils.WatchedContainerCompletionStatusPartial)
	} else {
		watchedContainer.SetCompletionStatus(utils.WatchedContainerCompletionStatusFull)
	}
	watchedContainer.SetStatus(utils.WatchedContainerStatusInitializing)
	am.saveProfile(ctx, watchedContainer, container.K8s.Namespace)

	for {
		select {
		case <-watchedContainer.UpdateDataTicker.C:
			// adjust ticker after first tick
			if !watchedContainer.InitialDelayExpired {
				watchedContainer.InitialDelayExpired = true
				watchedContainer.UpdateDataTicker.Reset(am.cfg.UpdateDataPeriod)
			}
			watchedContainer.SetStatus(utils.WatchedContainerStatusReady)
			am.saveProfile(ctx, watchedContainer, container.K8s.Namespace)
		case err := <-watchedContainer.SyncChannel:
			switch {
			case errors.Is(err, utils.ContainerHasTerminatedError):
				// if exit code is 0 we set the status to completed
				// TODO: Should we split ContainerHasTerminatedError to indicate if we reached the maxSniffingTime?
				if watchedContainer.GetTerminationExitCode(am.k8sObjectCache, container.K8s.Namespace, container.K8s.PodName, container.K8s.ContainerName) == 0 {
					watchedContainer.SetStatus(utils.WatchedContainerStatusCompleted)
				}

				am.saveProfile(ctx, watchedContainer, container.K8s.Namespace)
				return nil
			case errors.Is(err, utils.TooLargeApplicationProfileError):
				watchedContainer.SetStatus(utils.WatchedContainerStatusTooLarge)
				return nil
			}
		}
	}
}

func (am *ApplicationProfileManager) saveProfile(ctx context.Context, watchedContainer *utils.WatchedContainerData, namespace string) {
	ctx, span := otel.Tracer("").Start(ctx, "ApplicationProfileManager.saveProfile")
	defer span.End()

	// make sure we don't run deleteResources and saveProfile at the same time
	am.containerMutexes.Lock(watchedContainer.K8sContainerID)
	defer am.containerMutexes.Unlock(watchedContainer.K8sContainerID)

	// verify the container hasn't already been deleted
	if !am.trackedContainers.Contains(watchedContainer.K8sContainerID) {
		logger.L().Ctx(ctx).Debug("ApplicationProfileManager - container isn't tracked, not saving profile",
			helpers.Int("container index", watchedContainer.ContainerIndex),
			helpers.String("container ID", watchedContainer.ContainerID),
			helpers.String("k8s workload", watchedContainer.K8sContainerID))
		return
	}

	if watchedContainer.InstanceID == nil {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - instanceID is nil",
			helpers.Int("container index", watchedContainer.ContainerIndex),
			helpers.String("container ID", watchedContainer.ContainerID),
			helpers.String("k8s workload", watchedContainer.K8sContainerID))
		return
	}

	// leave container name empty this way the "slug" will represent a workload
	slug, err := names.InstanceIDToSlug(watchedContainer.InstanceID.GetName(), watchedContainer.InstanceID.GetKind(), "", watchedContainer.InstanceID.GetHashed())
	if err != nil {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to get slug", helpers.Error(err),
			helpers.String("slug", slug),
			helpers.Int("container index", watchedContainer.ContainerIndex),
			helpers.String("container ID", watchedContainer.ContainerID),
			helpers.String("k8s workload", watchedContainer.K8sContainerID))
		return
	}

	// sleep for container index second to desynchronize the profiles saving
	time.Sleep(time.Duration(watchedContainer.ContainerIndex) * time.Second)

	if droppedEvents := am.droppedEvents.Get(watchedContainer.K8sContainerID); droppedEvents {
		watchedContainer.SetStatus(utils.WatchedContainerStatusMissingRuntime)
	}

	// application activity
	// get syscalls from IG

	var observedSyscalls []string
	var toSaveSyscalls []string

	if am.syscallPeekFunc != nil {
		observedSyscalls, err = am.syscallPeekFunc(watchedContainer.NsMntId)
		if err != nil {
			logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to get syscalls", helpers.Error(err),
				helpers.String("slug", slug),
				helpers.Int("container index", watchedContainer.ContainerIndex),
				helpers.String("container ID", watchedContainer.ContainerID),
				helpers.String("k8s workload", watchedContainer.K8sContainerID))
		}
		// check if we have new activities to save
		savedSyscalls := am.savedSyscalls.Get(watchedContainer.K8sContainerID)
		toSaveSyscallsSet := mapset.NewSet[string](observedSyscalls...).Difference(savedSyscalls)
		if !toSaveSyscallsSet.IsEmpty() {
			toSaveSyscalls = toSaveSyscallsSet.ToSlice()
		}
	} else {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - syscall peek function is nil", helpers.String("slug", slug))
	}

	// application profile
	var capabilities []string
	execs := make(map[string]mapset.Set[string])
	opens := make(map[string]mapset.Set[string])
	// get capabilities from IG
	if toSaveCapabilities := am.toSaveCapabilities.Get(watchedContainer.K8sContainerID); toSaveCapabilities.Cardinality() > 0 {
		// remove capabilities to save in a thread safe way using Pop
		for {
			capability, continuePop := toSaveCapabilities.Pop()
			if continuePop {
				capabilities = append(capabilities, capability)
			} else {
				break
			}
		}
	}

	// get pointer to execs map from IG
	toSaveExecs := am.toSaveExecs.Get(watchedContainer.K8sContainerID)
	// point IG to a new exec map
	am.toSaveExecs.Set(watchedContainer.K8sContainerID, new(maps.SafeMap[string, mapset.Set[string]]))
	// prepare execs map
	toSaveExecs.Range(func(path string, exec mapset.Set[string]) bool {
		if _, exist := execs[path]; !exist {
			execs[path] = mapset.NewSet[string]()
		}
		execs[path].Append(exec.ToSlice()...)
		return true
	})
	// get pointer to opens map from IG
	toSaveOpens := am.toSaveOpens.Get(watchedContainer.K8sContainerID)
	// point IG to a new opens map
	am.toSaveOpens.Set(watchedContainer.K8sContainerID, new(maps.SafeMap[string, mapset.Set[string]]))
	// prepare opens map
	toSaveOpens.Range(func(path string, open mapset.Set[string]) bool {
		if _, exist := opens[path]; !exist {
			opens[path] = mapset.NewSet[string]()
		}
		opens[path].Append(open.ToSlice()...)
		return true
	})
	// new profile activity
	// the process tries to use JSON patching to avoid conflicts between updates on the same profile from different containers
	// 0. create both a patch and a new profile
	// 1. try to apply the patch
	// 2a. the profile doesn't exist - create the new profile
	// 2b. the patch was invalid - get existing object to fix the patch
	// 3a. the profile is missing Containers or InitContainers - ADD one with the container profile at the right index
	// 3b. the profile is missing the container profile - ADD the container profile at the right index
	// 3c. default - patch the container ourselves and REPLACE it at the right index
	if len(capabilities) > 0 || len(execs) > 0 || len(opens) > 0 || len(toSaveSyscalls) > 0 || watchedContainer.StatusUpdated() {
		// calculate patch
		profileOperations := utils.CreateCapabilitiesPatchOperations(capabilities, observedSyscalls, execs, opens, watchedContainer.ContainerType.String(), watchedContainer.ContainerIndex)
		profileOperations = utils.AppendStatusAnnotationPatchOperations(profileOperations, watchedContainer)

		patch, err := json.Marshal(profileOperations)
		if err != nil {
			logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to marshal patch", helpers.Error(err),
				helpers.String("slug", slug),
				helpers.Int("container index", watchedContainer.ContainerIndex),
				helpers.String("container ID", watchedContainer.ContainerID),
				helpers.String("k8s workload", watchedContainer.K8sContainerID))
			return
		}
		// try to patch application profile
		var gotErr error
		if err := am.storageClient.PatchApplicationProfile(slug, namespace, patch, watchedContainer.SyncChannel); err != nil {
			if apierrors.IsNotFound(err) {
				// new application profile
				newProfile := &v1beta1.ApplicationProfile{
					ObjectMeta: metav1.ObjectMeta{
						Name: slug,
						Annotations: map[string]string{
							helpersv1.WlidMetadataKey:       watchedContainer.Wlid,
							helpersv1.CompletionMetadataKey: string(watchedContainer.GetCompletionStatus()),
							helpersv1.StatusMetadataKey:     string(watchedContainer.GetStatus()),
						},
						Labels: utils.GetLabels(watchedContainer, true),
					},
				}
				// new profile container
				newProfileContainer := &v1beta1.ApplicationProfileContainer{
					Name: watchedContainer.InstanceID.GetContainerName(),
				}
				utils.EnrichProfileContainer(newProfileContainer, capabilities, observedSyscalls, execs, opens)
				// insert application profile container
				utils.InsertApplicationProfileContainer(newProfile, watchedContainer.ContainerType, watchedContainer.ContainerIndex, newProfileContainer)
				// try to create application profile
				if err := am.storageClient.CreateApplicationProfile(newProfile, namespace); err != nil {
					gotErr = err
					logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to create application profile", helpers.Error(err),
						helpers.String("slug", slug),
						helpers.Int("container index", watchedContainer.ContainerIndex),
						helpers.String("container ID", watchedContainer.ContainerID),
						helpers.String("k8s workload", watchedContainer.K8sContainerID))
				}
			} else {
				logger.L().Ctx(ctx).Debug("ApplicationProfileManager - failed to patch application profile, will get existing one and adjust patch", helpers.Error(err),
					helpers.String("slug", slug),
					helpers.Int("container index", watchedContainer.ContainerIndex),
					helpers.String("container ID", watchedContainer.ContainerID),
					helpers.String("k8s workload", watchedContainer.K8sContainerID))
				// get existing profile
				existingProfile, err := am.storageClient.GetApplicationProfile(namespace, slug)
				if err != nil {
					gotErr = err
					logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to get existing application profile", helpers.Error(err),
						helpers.String("slug", slug),
						helpers.Int("container index", watchedContainer.ContainerIndex),
						helpers.String("container ID", watchedContainer.ContainerID),
						helpers.String("k8s workload", watchedContainer.K8sContainerID))
				} else {
					var replaceOperations []utils.PatchOperation
					// check existing profile container
					existingProfileContainer := utils.GetApplicationProfileContainer(existingProfile, watchedContainer.ContainerType, watchedContainer.ContainerIndex)
					var addProfileContainer bool
					if existingProfileContainer == nil {
						existingProfileContainer = &v1beta1.ApplicationProfileContainer{
							Name: watchedContainer.InstanceID.GetContainerName(),
						}
						addProfileContainer = true
					}
					// update it
					utils.EnrichProfileContainer(existingProfileContainer, capabilities, observedSyscalls, execs, opens)
					// get existing containers
					var existingContainers []v1beta1.ApplicationProfileContainer
					if watchedContainer.ContainerType == utils.Container {
						existingContainers = existingProfile.Spec.Containers
					} else {
						existingContainers = existingProfile.Spec.InitContainers
					}
					// replace or add application profile container using patch
					switch {
					case existingContainers == nil:
						// insert a new container slice, with the new container at the right index
						containers := make([]v1beta1.ApplicationProfileContainer, watchedContainer.ContainerIndex+1)
						containers[watchedContainer.ContainerIndex] = *existingProfileContainer
						replaceOperations = append(replaceOperations, utils.PatchOperation{
							Op:    "add",
							Path:  fmt.Sprintf("/spec/%s", watchedContainer.ContainerType),
							Value: containers,
						})
					case addProfileContainer:
						for i := len(existingContainers); i < watchedContainer.ContainerIndex; i++ {
							replaceOperations = append(replaceOperations, utils.PatchOperation{
								Op:    "add",
								Path:  fmt.Sprintf("/spec/%s/%d", watchedContainer.ContainerType, i),
								Value: v1beta1.ApplicationProfileContainer{},
							})
						}
						replaceOperations = append(replaceOperations, utils.PatchOperation{
							Op:    "add",
							Path:  fmt.Sprintf("/spec/%s/%d", watchedContainer.ContainerType, watchedContainer.ContainerIndex),
							Value: existingProfileContainer,
						})
					default:
						replaceOperations = append(replaceOperations, utils.PatchOperation{
							Op:    "replace",
							Path:  fmt.Sprintf("/spec/%s/%d", watchedContainer.ContainerType, watchedContainer.ContainerIndex),
							Value: existingProfileContainer,
						})
					}

					replaceOperations = utils.AppendStatusAnnotationPatchOperations(replaceOperations, watchedContainer)

					patch, err := json.Marshal(replaceOperations)
					if err != nil {
						logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to marshal patch", helpers.Error(err),
							helpers.String("slug", slug),
							helpers.Int("container index", watchedContainer.ContainerIndex),
							helpers.String("container ID", watchedContainer.ContainerID),
							helpers.String("k8s workload", watchedContainer.K8sContainerID))
						return
					}
					if err := am.storageClient.PatchApplicationProfile(slug, namespace, patch, watchedContainer.SyncChannel); err != nil {
						gotErr = err
						logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to patch application profile", helpers.Error(err),
							helpers.String("slug", slug),
							helpers.Int("container index", watchedContainer.ContainerIndex),
							helpers.String("container ID", watchedContainer.ContainerID),
							helpers.String("k8s workload", watchedContainer.K8sContainerID))
					}
				}
			}
		}
		if gotErr != nil {
			// restore capabilities set
			am.toSaveCapabilities.Get(watchedContainer.K8sContainerID).Append(capabilities...)
			// restore execs map entries
			toSaveExecs.Range(utils.SetInMap(am.toSaveExecs.Get(watchedContainer.K8sContainerID)))
			// restore opens map entries
			toSaveOpens.Range(utils.SetInMap(am.toSaveOpens.Get(watchedContainer.K8sContainerID)))
		} else {
			// for status updates to be tracked, we reset the update flag
			watchedContainer.ResetStatusUpdatedFlag()

			// record saved syscalls
			am.savedSyscalls.Get(watchedContainer.K8sContainerID).Append(toSaveSyscalls...)
			// record saved capabilities
			am.savedCapabilities.Get(watchedContainer.K8sContainerID).Append(capabilities...)
			// record saved execs
			toSaveExecs.Range(utils.SetInMap(am.savedExecs.Get(watchedContainer.K8sContainerID)))
			// record saved opens
			toSaveOpens.Range(utils.SetInMap(am.savedOpens.Get(watchedContainer.K8sContainerID)))
			logger.L().Debug("ApplicationProfileManager - saved application profile",
				helpers.Int("capabilities", len(capabilities)),
				helpers.Int("execs", toSaveExecs.Len()),
				helpers.Int("opens", toSaveOpens.Len()),
				helpers.String("slug", slug),
				helpers.Int("container index", watchedContainer.ContainerIndex),
				helpers.String("container ID", watchedContainer.ContainerID),
				helpers.String("k8s workload", watchedContainer.K8sContainerID))
			// profile summary
			// summary := &v1beta1.ApplicationProfileSummary{
			// 	ObjectMeta: metav1.ObjectMeta{
			// 		Name: slug,
			// 		Annotations: map[string]string{
			// 			helpersv1.WlidMetadataKey:   watchedContainer.Wlid,
			// 			helpersv1.StatusMetadataKey: helpersv1.Ready,
			// 		},
			// 		Labels: utils.GetLabels(watchedContainer, true),
			// 	},
			// }
			// if err := am.storageClient.CreateApplicationProfileSummary(summary, namespace); err != nil {
			// 	logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to save application profile summary", helpers.Error(err),
			// 		helpers.String("slug", slug),
			// 		helpers.Int("container index", watchedContainer.ContainerIndex),
			// 		helpers.String("container ID", watchedContainer.ContainerID),
			// 		helpers.String("k8s workload", watchedContainer.K8sContainerID))
			// }
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

	// don't start monitoring until we have the instanceID - need to retry until the Pod is updated
	if err := backoff.Retry(func() error {
		return am.ensureInstanceID(container, watchedContainer)
	}, backoff.NewExponentialBackOff()); err != nil {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to ensure instanceID", helpers.Error(err),
			helpers.Int("container index", watchedContainer.ContainerIndex),
			helpers.String("container ID", watchedContainer.ContainerID),
			helpers.String("k8s workload", watchedContainer.K8sContainerID))
	}

	if err := am.monitorContainer(ctx, container, watchedContainer); err != nil {
		logger.L().Info("ApplicationProfileManager - stop monitor on container", helpers.String("reason", err.Error()),
			helpers.Int("container index", watchedContainer.ContainerIndex),
			helpers.String("container ID", watchedContainer.ContainerID),
			helpers.String("k8s workload", watchedContainer.K8sContainerID))
	}

	am.deleteResources(watchedContainer)
}

func (am *ApplicationProfileManager) waitForContainer(k8sContainerID string) error {
	return backoff.Retry(func() error {
		if am.trackedContainers.Contains(k8sContainerID) {
			return nil
		}
		return fmt.Errorf("container %s not found", k8sContainerID)
	}, backoff.NewExponentialBackOff())
}

func (am *ApplicationProfileManager) ContainerCallback(notif containercollection.PubSubEvent) {
	k8sContainerID := utils.CreateK8sContainerID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.ContainerName)
	ctx, span := otel.Tracer("").Start(am.ctx, "ApplicationProfileManager.ContainerCallback", trace.WithAttributes(attribute.String("containerID", notif.Container.Runtime.ContainerID), attribute.String("k8s workload", k8sContainerID)))
	defer span.End()

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		if am.watchedContainerChannels.Has(notif.Container.Runtime.ContainerID) {
			logger.L().Debug("container already exist in memory",
				helpers.String("container ID", notif.Container.Runtime.ContainerID),
				helpers.String("k8s workload", k8sContainerID))
			return
		}
		am.savedCapabilities.Set(k8sContainerID, mapset.NewSet[string]())
		am.droppedEvents.Set(k8sContainerID, false)
		am.savedExecs.Set(k8sContainerID, new(maps.SafeMap[string, mapset.Set[string]]))
		am.savedOpens.Set(k8sContainerID, new(maps.SafeMap[string, mapset.Set[string]]))
		am.savedSyscalls.Set(k8sContainerID, mapset.NewSet[string]())
		am.toSaveCapabilities.Set(k8sContainerID, mapset.NewSet[string]())
		am.toSaveExecs.Set(k8sContainerID, new(maps.SafeMap[string, mapset.Set[string]]))
		am.toSaveOpens.Set(k8sContainerID, new(maps.SafeMap[string, mapset.Set[string]]))
		am.trackedContainers.Add(k8sContainerID)
		go am.startApplicationProfiling(ctx, notif.Container, k8sContainerID)

		// stop monitoring after MaxSniffingTime
		time.AfterFunc(am.cfg.MaxSniffingTime, func() {
			logger.L().Info("stop monitor on container - after monitoring time", helpers.String("container ID", notif.Container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
			event := containercollection.PubSubEvent{
				Timestamp: time.Now().Format(time.RFC3339),
				Type:      containercollection.EventTypeRemoveContainer,
				Container: notif.Container,
			}
			am.ContainerCallback(event)
		})
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
	if err := am.waitForContainer(k8sContainerID); err != nil {
		return
	}
	if am.savedCapabilities.Has(capability) {
		return
	}
	am.toSaveCapabilities.Get(k8sContainerID).Add(capability)
}

func (am *ApplicationProfileManager) ReportFileExec(k8sContainerID, path string, args []string) {
	// skip empty path
	if path == "" {
		return
	}
	if err := am.waitForContainer(k8sContainerID); err != nil {
		return
	}
	// check if we already have this exec
	savedExecs := am.savedExecs.Get(k8sContainerID)
	if savedExecs.Has(path) && savedExecs.Get(path).Contains(args...) {
		return
	}
	// add to exec map
	execMap := am.toSaveExecs.Get(k8sContainerID)
	if execMap.Has(path) {
		execMap.Get(path).Append(args...)
	} else {
		execMap.Set(path, mapset.NewSet[string](args...))
	}
}

func (am *ApplicationProfileManager) ReportFileOpen(k8sContainerID, path string, flags []string) {
	if err := am.waitForContainer(k8sContainerID); err != nil {
		return
	}
	// check if we already have this open
	savedOpens := am.savedOpens.Get(k8sContainerID)
	if savedOpens.Has(path) && savedOpens.Get(path).Contains(flags...) {
		return
	}
	// add to open map
	openMap := am.toSaveOpens.Get(k8sContainerID)
	if openMap.Has(path) {
		openMap.Get(path).Append(flags...)
	} else {
		openMap.Set(path, mapset.NewSet[string](flags...))
	}
}

func (am *ApplicationProfileManager) ReportDroppedEvent(k8sContainerID string) {
	if err := am.waitForContainer(k8sContainerID); err != nil {
		return
	}
	am.droppedEvents.Set(k8sContainerID, true)
}
