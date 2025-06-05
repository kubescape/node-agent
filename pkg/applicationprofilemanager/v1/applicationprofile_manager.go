package applicationprofilemanager

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v5"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/applicationprofilemanager"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerhardlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/types"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	tracersymlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/types"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulebindingmanager"
	"github.com/kubescape/node-agent/pkg/ruleengine/v1"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
	storageUtils "github.com/kubescape/storage/pkg/utils"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var procRegex = regexp.MustCompile(`^/proc/\d+`)

type ApplicationProfileManager struct {
	cfg                      config.Config
	clusterName              string
	ctx                      context.Context
	containerMutexes         storageUtils.MapMutex[string]                                             // key is k8sContainerID
	trackedContainers        mapset.Set[string]                                                        // key is k8sContainerID
	removedContainers        mapset.Set[string]                                                        // key is k8sContainerID
	droppedEventsContainers  mapset.Set[string]                                                        // key is k8sContainerID
	toSaveCapabilities       maps.SafeMap[string, mapset.Set[string]]                                  // key is k8sContainerID
	toSaveEndpoints          maps.SafeMap[string, *maps.SafeMap[string, *v1beta1.HTTPEndpoint]]        // key is k8sContainerID
	toSaveExecs              maps.SafeMap[string, *maps.SafeMap[string, []string]]                     // key is k8sContainerID
	toSaveOpens              maps.SafeMap[string, *maps.SafeMap[string, mapset.Set[string]]]           // key is k8sContainerID
	toSaveRulePolicies       maps.SafeMap[string, *maps.SafeMap[string, *v1beta1.RulePolicy]]          // key is k8sContainerID
	toSaveCallStacks         maps.SafeMap[string, *maps.SafeMap[string, *v1beta1.IdentifiedCallStack]] // key is k8sContainerID
	watchedContainerChannels maps.SafeMap[string, chan error]                                          // key is ContainerID
	k8sClient                k8sclient.K8sClientInterface
	k8sObjectCache           objectcache.K8sObjectCache
	storageClient            storage.StorageClient
	syscallPeekFunc          func(nsMountId uint64) ([]string, error)
	seccompManager           seccompmanager.SeccompManagerClient
	enricher                 applicationprofilemanager.Enricher
	ruleCache                rulebindingmanager.RuleBindingCache
}

var _ applicationprofilemanager.ApplicationProfileManagerClient = (*ApplicationProfileManager)(nil)

func CreateApplicationProfileManager(ctx context.Context, cfg config.Config, clusterName string, k8sClient k8sclient.K8sClientInterface, storageClient storage.StorageClient, k8sObjectCache objectcache.K8sObjectCache, seccompManager seccompmanager.SeccompManagerClient, enricher applicationprofilemanager.Enricher, ruleCache rulebindingmanager.RuleBindingCache) (*ApplicationProfileManager, error) {
	return &ApplicationProfileManager{
		cfg:                     cfg,
		clusterName:             clusterName,
		ctx:                     ctx,
		k8sClient:               k8sClient,
		k8sObjectCache:          k8sObjectCache,
		storageClient:           storageClient,
		containerMutexes:        storageUtils.NewMapMutex[string](),
		trackedContainers:       mapset.NewSet[string](),
		removedContainers:       mapset.NewSet[string](),
		droppedEventsContainers: mapset.NewSet[string](),
		seccompManager:          seccompManager,
		enricher:                enricher,
		ruleCache:               ruleCache,
	}, nil
}

func (am *ApplicationProfileManager) deleteResources(watchedContainer *utils.WatchedContainerData) {
	// make sure we don't run deleteResources and saveProfile at the same time
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := am.containerMutexes.Lock(ctx, watchedContainer.K8sContainerID)
	if err != nil {
		logger.L().Debug("ApplicationProfileManager - failed to lock container mutex", helpers.Error(err),
			helpers.String("container ID", watchedContainer.ContainerID),
			helpers.String("k8s workload", watchedContainer.K8sContainerID))
		return
	}
	defer am.containerMutexes.Unlock(watchedContainer.K8sContainerID)
	am.removedContainers.Add(watchedContainer.K8sContainerID)
	// delete resources
	watchedContainer.UpdateDataTicker.Stop()
	am.trackedContainers.Remove(watchedContainer.K8sContainerID)
	am.droppedEventsContainers.Remove(watchedContainer.K8sContainerID)
	am.toSaveCapabilities.Delete(watchedContainer.K8sContainerID)
	am.toSaveEndpoints.Delete(watchedContainer.K8sContainerID)
	am.toSaveExecs.Delete(watchedContainer.K8sContainerID)
	am.toSaveOpens.Delete(watchedContainer.K8sContainerID)
	am.toSaveRulePolicies.Delete(watchedContainer.K8sContainerID)
	am.toSaveCallStacks.Delete(watchedContainer.K8sContainerID)
	am.watchedContainerChannels.Delete(watchedContainer.ContainerID)
}

func (am *ApplicationProfileManager) ContainerReachedMaxTime(containerID string) {
	if channel := am.watchedContainerChannels.Get(containerID); channel != nil {
		channel <- utils.ContainerReachedMaxTime
	}
}

func (am *ApplicationProfileManager) monitorContainer(ctx context.Context, container *containercollection.Container, watchedContainer *utils.WatchedContainerData) error {
	logger.L().Info("ApplicationProfileManager - start monitor on container",
		helpers.Interface("preRunning", watchedContainer.PreRunningContainer),
		helpers.Int("container index", watchedContainer.ContainerIndex),
		helpers.String("container ID", watchedContainer.ContainerID),
		helpers.String("k8s workload", watchedContainer.K8sContainerID))

	// set completion status & status as soon as we start monitoring the container
	if watchedContainer.PreRunningContainer {
		watchedContainer.SetCompletionStatus(utils.WatchedContainerCompletionStatusPartial)
	} else {
		watchedContainer.SetCompletionStatus(utils.WatchedContainerCompletionStatusFull)
	}
	watchedContainer.SetStatus(utils.WatchedContainerStatusInitializing)

	initOps := GetInitOperations(am.ruleCache, watchedContainer.ContainerType.String(), watchedContainer.ContainerIndex)

	for {
		select {
		case <-watchedContainer.UpdateDataTicker.C:
			// adjust ticker after first tick
			if !watchedContainer.InitialDelayExpired {
				watchedContainer.InitialDelayExpired = true
				watchedContainer.UpdateDataTicker.Reset(utils.AddJitter(am.cfg.UpdateDataPeriod, am.cfg.MaxJitterPercentage))
			}
			watchedContainer.SetStatus(utils.WatchedContainerStatusReady)
			am.saveProfile(ctx, watchedContainer, container.K8s.Namespace, nil)

			// save profile after initialaztion
			if initOps != nil {
				am.saveProfile(ctx, watchedContainer, container.K8s.Namespace, initOps)
				initOps = nil
			}

		case err := <-watchedContainer.SyncChannel:
			switch {
			case errors.Is(err, utils.ContainerHasTerminatedError):
				// if exit code is 0 we set the status to completed
				if objectcache.GetTerminationExitCode(am.k8sObjectCache, container.K8s.Namespace, container.K8s.PodName, container.K8s.ContainerName, container.Runtime.ContainerID) == 0 {
					watchedContainer.SetStatus(utils.WatchedContainerStatusCompleted)
				}
				am.saveProfile(ctx, watchedContainer, container.K8s.Namespace, nil)
				return err
			case errors.Is(err, utils.ContainerReachedMaxTime):
				watchedContainer.SetStatus(utils.WatchedContainerStatusCompleted)
				am.saveProfile(ctx, watchedContainer, container.K8s.Namespace, nil)
				return err
			case errors.Is(err, utils.ObjectCompleted):
				watchedContainer.SetStatus(utils.WatchedContainerStatusCompleted)
				return err
			case errors.Is(err, utils.TooLargeObjectError):
				logger.L().Debug("ApplicationProfileManager - object is too large")
				watchedContainer.SetStatus(utils.WatchedContainerStatusTooLarge)
				return err
			}
		}
	}
}

func (am *ApplicationProfileManager) saveProfile(ctx context.Context, watchedContainer *utils.WatchedContainerData, namespace string, initalizeOperations []utils.PatchOperation) {
	ctx, span := otel.Tracer("").Start(ctx, "ApplicationProfileManager.saveProfile")
	defer span.End()

	// make sure we don't run deleteResources and saveProfile at the same time
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := am.containerMutexes.Lock(ctx, watchedContainer.K8sContainerID)
	if err != nil {
		logger.L().Debug("ApplicationProfileManager - failed to lock container mutex", helpers.Error(err),
			helpers.String("container ID", watchedContainer.ContainerID),
			helpers.String("k8s workload", watchedContainer.K8sContainerID))
		return
	}
	defer am.containerMutexes.Unlock(watchedContainer.K8sContainerID)

	// verify the container hasn't already been deleted
	if !am.trackedContainers.Contains(watchedContainer.K8sContainerID) {
		return
	}

	if watchedContainer.InstanceID == nil {
		logger.L().Debug("ApplicationProfileManager - instanceID is nil",
			helpers.Int("container index", watchedContainer.ContainerIndex),
			helpers.String("container ID", watchedContainer.ContainerID),
			helpers.String("k8s workload", watchedContainer.K8sContainerID))
		return
	}

	// sleep for container index second to desynchronize the profiles saving
	time.Sleep(time.Duration(watchedContainer.ContainerIndex) * time.Second)

	if am.droppedEventsContainers.ContainsOne(watchedContainer.K8sContainerID) {
		watchedContainer.SetStatus(utils.WatchedContainerStatusMissingRuntime)
	}

	// get syscalls from IG
	var observedSyscalls []string
	var toSaveSyscalls []string
	if am.syscallPeekFunc != nil {
		if observedSyscalls, err = am.syscallPeekFunc(watchedContainer.NsMntId); err == nil {
			// check if we have new activities to save
			toSaveSyscallsSet := mapset.NewSet[string](observedSyscalls...)
			if !toSaveSyscallsSet.IsEmpty() {
				toSaveSyscalls = toSaveSyscallsSet.ToSlice()
			}
		}
	}

	// get capabilities from IG
	var capabilities []string
	endpoints := make(map[string]*v1beta1.HTTPEndpoint)
	execs := make(map[string][]string)
	opens := make(map[string]mapset.Set[string])
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

	// get pointer to endpoints map from IG
	toSaveEndpoints := am.toSaveEndpoints.Get(watchedContainer.K8sContainerID)
	// point IG to a new endpoints map
	am.toSaveEndpoints.Set(watchedContainer.K8sContainerID, new(maps.SafeMap[string, *v1beta1.HTTPEndpoint]))
	// prepare endpoints map
	toSaveEndpoints.Range(func(path string, endpoint *v1beta1.HTTPEndpoint) bool {
		endpoints[path] = endpoint
		return true
	})
	// get pointer to execs map from IG
	toSaveExecs := am.toSaveExecs.Get(watchedContainer.K8sContainerID)
	// point IG to a new exec map
	am.toSaveExecs.Set(watchedContainer.K8sContainerID, new(maps.SafeMap[string, []string]))
	// prepare execs map
	toSaveExecs.Range(func(execIdentifier string, pathAndArgs []string) bool {
		execs[execIdentifier] = pathAndArgs
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

	// get rule policies
	rulePolicies := make(map[string]v1beta1.RulePolicy)
	toSaveRulePolicies := am.toSaveRulePolicies.Get(watchedContainer.K8sContainerID)
	// point IG to a new rule policies map
	am.toSaveRulePolicies.Set(watchedContainer.K8sContainerID, new(maps.SafeMap[string, *v1beta1.RulePolicy]))
	// prepare rule policies map
	toSaveRulePolicies.Range(func(ruleIdentifier string, rulePolicy *v1beta1.RulePolicy) bool {
		rulePolicies[ruleIdentifier] = *rulePolicy
		return true
	})

	// Get call stacks
	callStacks := make([]v1beta1.IdentifiedCallStack, 0)
	toSaveCallStacks := am.toSaveCallStacks.Get(watchedContainer.K8sContainerID)
	// Point IG to a new call stacks map
	am.toSaveCallStacks.Set(watchedContainer.K8sContainerID, new(maps.SafeMap[string, *v1beta1.IdentifiedCallStack]))
	// Prepare call stacks slice
	toSaveCallStacks.Range(func(identifier string, callStack *v1beta1.IdentifiedCallStack) bool {
		callStacks = append(callStacks, *callStack)
		return true
	})

	// new activity
	// we send a new profile for the container containing the new capabilities, endpoints, execs, opens, rule policies and call stacks
	if len(capabilities) > 0 || len(endpoints) > 0 || len(execs) > 0 || len(opens) > 0 || len(toSaveSyscalls) > 0 || len(initalizeOperations) > 0 || len(callStacks) > 0 || watchedContainer.StatusUpdated() {
		now := time.Now()
		// keep the container name in the slug as we're sending per-container profiles
		slug, err := watchedContainer.InstanceID.GetOneTimeSlug(false)
		if err != nil {
			logger.L().Ctx(ctx).Warning("ApplicationProfileManager - failed to get slug", helpers.Error(err),
				helpers.Int("container index", watchedContainer.ContainerIndex),
				helpers.String("container ID", watchedContainer.ContainerID),
				helpers.String("k8s workload", watchedContainer.K8sContainerID))
			return
		}
		// create a new ApplicationProfile object
		newObject := &v1beta1.ContainerProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name: slug,
				Annotations: map[string]string{
					helpersv1.CompletionMetadataKey:      string(watchedContainer.GetCompletionStatus()),
					helpersv1.InstanceIDMetadataKey:      watchedContainer.InstanceID.GetStringFormatted(),
					helpersv1.ReportSeriesIdMetadataKey:  watchedContainer.Uuid,
					helpersv1.ReportTimestampMetadataKey: now.Format(time.RFC3339),
					helpersv1.StatusMetadataKey:          string(watchedContainer.GetStatus()),
					helpersv1.WlidMetadataKey:            watchedContainer.Wlid,
				},
				Labels: utils.GetLabels(watchedContainer, false),
			},
			Spec: v1beta1.ContainerProfileSpec{
				Architectures: []string{runtime.GOARCH},
			},
		}
		if watchedContainer.PreviousProfileTS != nil {
			newObject.ObjectMeta.Annotations[helpersv1.PreviousReportTimestampMetadataKey] = watchedContainer.PreviousProfileTS.Format(time.RFC3339)
		}
		utils.EnrichContainerProfileSpec(&newObject.Spec, capabilities, observedSyscalls, execs, opens, endpoints, rulePolicies, callStacks, watchedContainer.ImageID, watchedContainer.ImageTag)
		// try to create object
		if err := am.storageClient.CreateContainerProfile(newObject, namespace); err != nil {
			logger.L().Ctx(ctx).Warning("ApplicationProfileManager - failed to create application profile", helpers.Error(err),
				helpers.Int("container index", watchedContainer.ContainerIndex),
				helpers.String("container ID", watchedContainer.ContainerID),
				helpers.String("k8s workload", watchedContainer.K8sContainerID))
			// restore capabilities set
			am.toSaveCapabilities.Get(watchedContainer.K8sContainerID).Append(capabilities...)
			// restore endpoints map entries
			toSaveEndpoints.Range(func(path string, endpoint *v1beta1.HTTPEndpoint) bool {
				if !am.toSaveEndpoints.Get(watchedContainer.K8sContainerID).Has(path) {
					am.toSaveEndpoints.Get(watchedContainer.K8sContainerID).Set(path, endpoint)
				}
				return true
			})
			// restore execs map entries
			toSaveExecs.Range(func(uniqueExecIdentifier string, v []string) bool {
				if !am.toSaveExecs.Get(watchedContainer.K8sContainerID).Has(uniqueExecIdentifier) {
					am.toSaveExecs.Get(watchedContainer.K8sContainerID).Set(uniqueExecIdentifier, v)
				}
				return true
			})
			// restore opens map entries
			toSaveOpens.Range(utils.SetInMap(am.toSaveOpens.Get(watchedContainer.K8sContainerID)))
			// restore call stacks
			toSaveCallStacks.Range(func(identifier string, callStack *v1beta1.IdentifiedCallStack) bool {
				if !am.toSaveCallStacks.Get(watchedContainer.K8sContainerID).Has(identifier) {
					am.toSaveCallStacks.Get(watchedContainer.K8sContainerID).Set(identifier, callStack)
				}
				return true
			})
		} else {
			// for status updates to be tracked, we reset the update flag
			watchedContainer.ResetStatusUpdatedFlag()
			watchedContainer.PreviousProfileTS = &now

			logger.L().Debug("ApplicationProfileManager - saved application profile",
				helpers.Int("capabilities", len(capabilities)),
				helpers.Int("endpoints", toSaveEndpoints.Len()),
				helpers.Int("execs", toSaveExecs.Len()),
				helpers.Int("opens", toSaveOpens.Len()),
				helpers.Int("rule policies", toSaveRulePolicies.Len()),
				helpers.Int("call stacks", toSaveCallStacks.Len()),
				helpers.Int("init operations", len(initalizeOperations)),
				helpers.Int("container index", watchedContainer.ContainerIndex),
				helpers.String("container ID", watchedContainer.ContainerID),
				helpers.String("k8s workload", watchedContainer.K8sContainerID))
		}
	}
}

func (am *ApplicationProfileManager) startApplicationProfiling(ctx context.Context, container *containercollection.Container, k8sContainerID string) {
	ctx, span := otel.Tracer("").Start(ctx, "ApplicationProfileManager.startApplicationProfiling")
	defer span.End()

	sharedData, err := am.waitForSharedContainerData(container.Runtime.ContainerID)
	if err != nil {
		logger.L().Error("ApplicationProfileManager - container not found in shared data",
			helpers.String("container ID", container.Runtime.ContainerID),
			helpers.String("k8s workload", k8sContainerID))
		return
	}

	if !am.cfg.EnableRuntimeDetection && sharedData.PreRunningContainer {
		logger.L().Debug("ApplicationProfileManager - skip container", helpers.String("reason", "preRunning container"),
			helpers.String("container ID", container.Runtime.ContainerID),
			helpers.String("k8s workload", k8sContainerID))
		return
	}

	syncChannel := make(chan error, 10)
	am.watchedContainerChannels.Set(container.Runtime.ContainerID, syncChannel)

	watchedContainer := &utils.WatchedContainerData{
		ContainerID:            container.Runtime.ContainerID,
		ImageID:                sharedData.ImageID,
		ImageTag:               sharedData.ImageTag,
		UpdateDataTicker:       time.NewTicker(utils.AddJitter(am.cfg.InitialDelay, am.cfg.MaxJitterPercentage)),
		SyncChannel:            syncChannel,
		K8sContainerID:         k8sContainerID,
		NsMntId:                container.Mntns,
		InstanceID:             sharedData.InstanceID,
		Wlid:                   sharedData.Wlid,
		ParentResourceVersion:  sharedData.ParentResourceVersion,
		ContainerInfos:         sharedData.ContainerInfos,
		ParentWorkloadSelector: sharedData.ParentWorkloadSelector,
		SeccompProfilePath:     sharedData.SeccompProfilePath,
		ContainerType:          sharedData.ContainerType,
		ContainerIndex:         sharedData.ContainerIndex,
		PreRunningContainer:    sharedData.PreRunningContainer,
		Uuid:                   sharedData.Uuid,
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
	if am.removedContainers.Contains(k8sContainerID) {
		return fmt.Errorf("container %s has been removed", k8sContainerID)
	}
	_, err := backoff.Retry(context.Background(), func() (any, error) {
		if am.trackedContainers.Contains(k8sContainerID) {
			return nil, nil
		}
		return nil, fmt.Errorf("container %s not found", k8sContainerID)
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()))
	return err
}

func (am *ApplicationProfileManager) waitForSharedContainerData(containerID string) (*utils.WatchedContainerData, error) {
	return backoff.Retry(context.Background(), func() (*utils.WatchedContainerData, error) {
		if sharedData := am.k8sObjectCache.GetSharedContainerData(containerID); sharedData != nil {
			return sharedData, nil
		}
		return nil, fmt.Errorf("container %s not found in shared data", containerID)
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()))
}

func (am *ApplicationProfileManager) ContainerCallback(notif containercollection.PubSubEvent) {
	// check if the container should be ignored
	if am.cfg.IgnoreContainer(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.PodLabels) {
		return
	}

	k8sContainerID := utils.CreateK8sContainerID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.Runtime.ContainerID)
	ctx, span := otel.Tracer("").Start(am.ctx, "ApplicationProfileManager.ContainerCallback", trace.WithAttributes(attribute.String("containerID", notif.Container.Runtime.ContainerID), attribute.String("k8s workload", k8sContainerID)))
	defer span.End()

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		if am.watchedContainerChannels.Has(notif.Container.Runtime.ContainerID) {
			return
		}
		am.toSaveCapabilities.Set(k8sContainerID, mapset.NewSet[string]())
		am.toSaveEndpoints.Set(k8sContainerID, new(maps.SafeMap[string, *v1beta1.HTTPEndpoint]))
		am.toSaveExecs.Set(k8sContainerID, new(maps.SafeMap[string, []string]))
		am.toSaveOpens.Set(k8sContainerID, new(maps.SafeMap[string, mapset.Set[string]]))
		am.toSaveRulePolicies.Set(k8sContainerID, new(maps.SafeMap[string, *v1beta1.RulePolicy]))
		am.toSaveCallStacks.Set(k8sContainerID, new(maps.SafeMap[string, *v1beta1.IdentifiedCallStack]))
		am.removedContainers.Remove(k8sContainerID) // make sure container is not in the removed list
		am.trackedContainers.Add(k8sContainerID)

		go am.startApplicationProfiling(ctx, notif.Container, k8sContainerID)

	case containercollection.EventTypeRemoveContainer:
		channel := am.watchedContainerChannels.Get(notif.Container.Runtime.ContainerID)
		if channel != nil {
			channel <- utils.ContainerHasTerminatedError
		}
	}
}

func (am *ApplicationProfileManager) RegisterPeekFunc(peek func(mntns uint64) ([]string, error)) {
	am.syscallPeekFunc = peek
}

func (am *ApplicationProfileManager) ReportCapability(k8sContainerID, capability string) {
	if err := am.waitForContainer(k8sContainerID); err != nil {
		return
	}
	// add to capability map
	am.toSaveCapabilities.Get(k8sContainerID).Add(capability)
}

func (am *ApplicationProfileManager) ReportFileExec(k8sContainerID string, event events.ExecEvent) {
	if err := am.waitForContainer(k8sContainerID); err != nil {
		return
	}

	path := event.Comm
	if len(event.Args) > 0 {
		path = event.Args[0]
	}

	// check if we already have this exec
	// we use a SHA256 hash of the exec to identify it uniquely (path + args, in the order they were provided)
	execIdentifier := utils.CalculateSHA256FileExecHash(path, event.Args)
	if am.enricher != nil {
		go am.enricher.EnrichEvent(k8sContainerID, &event, execIdentifier)
	}

	// add to exec map, first element is the path, the rest are the args
	am.toSaveExecs.Get(k8sContainerID).Set(execIdentifier, append([]string{path}, event.Args...))
}

func (am *ApplicationProfileManager) ReportFileOpen(k8sContainerID string, event events.OpenEvent) {
	if err := am.waitForContainer(k8sContainerID); err != nil {
		return
	}
	// deduplicate /proc/1234/* into /proc/.../* (quite a common case)
	// we perform it here instead of waiting for compression
	path := event.Path
	if strings.HasPrefix(path, "/proc/") {
		path = procRegex.ReplaceAllString(path, "/proc/"+dynamicpathdetector.DynamicIdentifier)
	}

	isSensitive := utils.IsSensitivePath(path, ruleengine.SensitiveFiles)

	if am.enricher != nil && isSensitive {
		openIdentifier := utils.CalculateSHA256FileOpenHash(path)
		go am.enricher.EnrichEvent(k8sContainerID, &event, openIdentifier)
	}

	// add to open map
	openMap := am.toSaveOpens.Get(k8sContainerID)
	if openMap.Has(path) {
		openMap.Get(path).Append(event.Flags...)
	} else {
		openMap.Set(path, mapset.NewSet[string](event.Flags...))
	}
}

func (am *ApplicationProfileManager) ReportSymlinkEvent(k8sContainerID string, event *tracersymlinktype.Event) {
	if err := am.waitForContainer(k8sContainerID); err != nil {
		return
	}

	if am.enricher != nil {
		symlinkIdentifier := utils.CalculateSHA256FileOpenHash(event.OldPath + event.NewPath)
		go am.enricher.EnrichEvent(k8sContainerID, event, symlinkIdentifier)
	}
}

func (am *ApplicationProfileManager) ReportHardlinkEvent(k8sContainerID string, event *tracerhardlinktype.Event) {
	if err := am.waitForContainer(k8sContainerID); err != nil {
		return
	}

	if am.enricher != nil {
		hardlinkIdentifier := utils.CalculateSHA256FileOpenHash(event.OldPath + event.NewPath)
		go am.enricher.EnrichEvent(k8sContainerID, event, hardlinkIdentifier)
	}
}

func (am *ApplicationProfileManager) ReportDroppedEvent(k8sContainerID string) {
	am.droppedEventsContainers.Add(k8sContainerID)
}

func (am *ApplicationProfileManager) ReportHTTPEvent(k8sContainerID string, event *tracerhttptype.Event) {
	if err := am.waitForContainer(k8sContainerID); err != nil {
		return
	}

	if event.Response == nil {
		logger.L().Debug("ApplicationProfileManager - HTTP event without response", helpers.String("container ID", k8sContainerID))
		return
	}

	endpointIdentifier, err := GetEndpointIdentifier(event)
	if err != nil {
		logger.L().Ctx(am.ctx).Warning("ApplicationProfileManager - failed to get endpoint identifier", helpers.Error(err))
		return
	}
	endpoint, err := GetNewEndpoint(event, endpointIdentifier)
	if err != nil {
		logger.L().Ctx(am.ctx).Warning("ApplicationProfileManager - failed to get new endpoint", helpers.Error(err))
		return
	}
	// check if we already have this endpoint
	endpointHash := CalculateHTTPEndpointHash(endpoint)
	// add to endpoint map
	am.toSaveEndpoints.Get(k8sContainerID).Set(endpointHash, endpoint)
}

func (am *ApplicationProfileManager) ReportRulePolicy(k8sContainerID, ruleId, allowedProcess string, allowedContainer bool) {
	if err := am.waitForContainer(k8sContainerID); err != nil {
		return
	}

	newPolicy := &v1beta1.RulePolicy{
		AllowedContainer: allowedContainer,
		AllowedProcesses: []string{allowedProcess},
	}

	toBeSavedPolicies := am.toSaveRulePolicies.Get(k8sContainerID)
	toBeSavedPolicy := toBeSavedPolicies.Get(ruleId)

	if IsPolicyIncluded(toBeSavedPolicy, newPolicy) {
		return
	}

	var finalPolicy *v1beta1.RulePolicy
	if toBeSavedPolicy != nil {
		finalPolicy = toBeSavedPolicy
		if allowedContainer {
			finalPolicy.AllowedContainer = true
		}
		if allowedProcess != "" && !slices.Contains(finalPolicy.AllowedProcesses, allowedProcess) {
			finalPolicy.AllowedProcesses = append(finalPolicy.AllowedProcesses, allowedProcess)
		}
	} else {
		finalPolicy = newPolicy
	}

	toBeSavedPolicies.Set(ruleId, finalPolicy)
}

func (am *ApplicationProfileManager) ReportIdentifiedCallStack(k8sContainerID string, callStack *v1beta1.IdentifiedCallStack) {
	if err := am.waitForContainer(k8sContainerID); err != nil {
		return
	}

	// Generate unique identifier for the call stack
	callStackIdentifier := CalculateSHA256CallStackHash(*callStack)

	// Add to call stacks map
	am.toSaveCallStacks.Get(k8sContainerID).Set(callStackIdentifier, callStack)
}
