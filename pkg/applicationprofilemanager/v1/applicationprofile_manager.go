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
	"istio.io/pkg/cache"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var procRegex = regexp.MustCompile(`^/proc/\d+`)

type APMetadata struct {
	Status           string
	CompletionStatus string
	Wlid             string
}

type ApplicationProfileManager struct {
	cfg                      config.Config
	clusterName              string
	ctx                      context.Context
	containerMutexes         storageUtils.MapMutex[string]                                             // key is k8sContainerID
	trackedContainers        mapset.Set[string]                                                        // key is k8sContainerID
	removedContainers        mapset.Set[string]                                                        // key is k8sContainerID
	droppedEventsContainers  mapset.Set[string]                                                        // key is k8sContainerID
	savedCapabilities        maps.SafeMap[string, cache.ExpiringCache]                                 // key is k8sContainerID
	savedEndpoints           maps.SafeMap[string, cache.ExpiringCache]                                 // key is k8sContainerID
	savedExecs               maps.SafeMap[string, cache.ExpiringCache]                                 // key is k8sContainerID
	savedOpens               maps.SafeMap[string, cache.ExpiringCache]                                 // key is k8sContainerID
	savedSyscalls            maps.SafeMap[string, mapset.Set[string]]                                  // key is k8sContainerID
	savedRulePolicies        maps.SafeMap[string, cache.ExpiringCache]                                 // key is k8sContainerID
	savedCallStacks          maps.SafeMap[string, cache.ExpiringCache]                                 // key is k8sContainerID
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
	apMetadataCache          *objectcache.CRDMetadataCache[APMetadata]
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
		apMetadataCache:         objectcache.NewCRDMetadataCache[APMetadata](),
	}, nil
}

func (am *ApplicationProfileManager) deleteResources(watchedContainer *utils.WatchedContainerData) {
	// make sure we don't run deleteResources and saveProfile at the same time
	am.containerMutexes.Lock(watchedContainer.K8sContainerID)
	defer am.containerMutexes.Unlock(watchedContainer.K8sContainerID)
	am.removedContainers.Add(watchedContainer.K8sContainerID)
	// delete resources
	watchedContainer.UpdateDataTicker.Stop()
	am.trackedContainers.Remove(watchedContainer.K8sContainerID)
	am.droppedEventsContainers.Remove(watchedContainer.K8sContainerID)
	am.savedCapabilities.Delete(watchedContainer.K8sContainerID)
	am.savedEndpoints.Delete(watchedContainer.K8sContainerID)
	am.savedExecs.Delete(watchedContainer.K8sContainerID)
	am.savedOpens.Delete(watchedContainer.K8sContainerID)
	am.savedSyscalls.Delete(watchedContainer.K8sContainerID)
	am.savedRulePolicies.Delete(watchedContainer.K8sContainerID)
	am.toSaveCapabilities.Delete(watchedContainer.K8sContainerID)
	am.toSaveEndpoints.Delete(watchedContainer.K8sContainerID)
	am.toSaveExecs.Delete(watchedContainer.K8sContainerID)
	am.toSaveOpens.Delete(watchedContainer.K8sContainerID)
	am.toSaveRulePolicies.Delete(watchedContainer.K8sContainerID)
	am.savedCallStacks.Delete(watchedContainer.K8sContainerID)
	am.toSaveCallStacks.Delete(watchedContainer.K8sContainerID)
	am.watchedContainerChannels.Delete(watchedContainer.ContainerID)
}

func (am *ApplicationProfileManager) ContainerReachedMaxTime(containerID string) {
	if channel := am.watchedContainerChannels.Get(containerID); channel != nil {
		channel <- utils.ContainerReachedMaxTime
	}
}

func (am *ApplicationProfileManager) monitorContainer(ctx context.Context, container *containercollection.Container, watchedContainer *utils.WatchedContainerData) error {
	var initOps []utils.PatchOperation
	if metadata, ok := am.apMetadataCache.Get(watchedContainer.Wlid); ok {
		if metadata.Status == string(utils.WatchedContainerStatusCompleted) {
			logger.L().Debug("ApplicationProfileManager - found completed cached application profile", helpers.String("wlid", watchedContainer.Wlid))
			return utils.ObjectCompleted
		} else if metadata.CompletionStatus == string(utils.WatchedContainerCompletionStatusFull) {
			logger.L().Debug("ApplicationProfileManager - found full cached application profile", helpers.String("wlid", watchedContainer.Wlid))
			watchedContainer.SetCompletionStatus(utils.WatchedContainerCompletionStatusFull)
			watchedContainer.SetStatus(utils.WatchedContainerStatusReady)
		} else {
			logger.L().Debug("ApplicationProfileManager - found partial cached application profile", helpers.String("wlid", watchedContainer.Wlid))
			watchedContainer.SetStatus(utils.WatchedContainerStatusReady)
			watchedContainer.SetCompletionStatus(utils.WatchedContainerCompletionStatusPartial)
		}
	} else {
		logger.L().Debug("ApplicationProfileManager - cached application profile not found for wlid", helpers.String("wlid", watchedContainer.Wlid))
		initOps = GetInitOperations(am.ruleCache, watchedContainer.ContainerType.String(), watchedContainer.ContainerIndex)
		if watchedContainer.PreRunningContainer {
			watchedContainer.SetCompletionStatus(utils.WatchedContainerCompletionStatusPartial)
		} else {
			watchedContainer.SetCompletionStatus(utils.WatchedContainerCompletionStatusFull)
		}
		watchedContainer.SetStatus(utils.WatchedContainerStatusInitializing)
	}

	logger.L().Debug("ApplicationProfileManager - start monitor on container",
		helpers.Interface("preRunning", watchedContainer.PreRunningContainer),
		helpers.Int("container index", watchedContainer.ContainerIndex),
		helpers.String("container ID", watchedContainer.ContainerID),
		helpers.String("k8s workload", watchedContainer.K8sContainerID))

	// set completion status & status as soon as we start monitoring the container

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
				am.apMetadataCache.Set(watchedContainer.Wlid, APMetadata{
					Status:           string(watchedContainer.GetStatus()),
					CompletionStatus: string(watchedContainer.GetCompletionStatus()),
					Wlid:             watchedContainer.Wlid,
				})
				return err
			case errors.Is(err, utils.ContainerReachedMaxTime):
				watchedContainer.SetStatus(utils.WatchedContainerStatusCompleted)
				am.saveProfile(ctx, watchedContainer, container.K8s.Namespace, nil)
				am.apMetadataCache.Set(watchedContainer.Wlid, APMetadata{
					Status:           string(watchedContainer.GetStatus()),
					CompletionStatus: string(watchedContainer.GetCompletionStatus()),
					Wlid:             watchedContainer.Wlid,
				})
				return err
			case errors.Is(err, utils.ObjectCompleted):
				watchedContainer.SetStatus(utils.WatchedContainerStatusCompleted)
				am.apMetadataCache.Set(watchedContainer.Wlid, APMetadata{
					Status:           string(watchedContainer.GetStatus()),
					CompletionStatus: string(watchedContainer.GetCompletionStatus()),
					Wlid:             watchedContainer.Wlid,
				})
				return err
			case errors.Is(err, utils.TooLargeObjectError):
				logger.L().Debug("ApplicationProfileManager - object is too large")
				watchedContainer.SetStatus(utils.WatchedContainerStatusTooLarge)
				am.apMetadataCache.Set(watchedContainer.Wlid, APMetadata{
					Status:           string(watchedContainer.GetStatus()),
					CompletionStatus: string(watchedContainer.GetCompletionStatus()),
					Wlid:             watchedContainer.Wlid,
				})
				return err
			}
		}
	}
}

func (am *ApplicationProfileManager) saveProfile(ctx context.Context, watchedContainer *utils.WatchedContainerData, namespace string, initalizeOperations []utils.PatchOperation) {
	ctx, span := otel.Tracer("").Start(ctx, "ApplicationProfileManager.saveProfile")
	defer span.End()

	// make sure we don't run deleteResources and saveProfile at the same time
	am.containerMutexes.Lock(watchedContainer.K8sContainerID)
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

	// leave container name empty this way the "slug" will represent a workload
	slug, err := watchedContainer.InstanceID.GetSlug(true)
	if err != nil {
		logger.L().Ctx(ctx).Warning("ApplicationProfileManager - failed to get slug", helpers.Error(err),
			helpers.String("slug", slug),
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

	// application activity is deprecated
	// syscalls now reside in the application profile

	// get syscalls from IG
	var observedSyscalls []string
	var toSaveSyscalls []string
	if am.syscallPeekFunc != nil {
		if observedSyscalls, err = am.syscallPeekFunc(watchedContainer.NsMntId); err == nil {
			// check if we have new activities to save
			savedSyscalls := am.savedSyscalls.Get(watchedContainer.K8sContainerID)
			toSaveSyscallsSet := mapset.NewSet[string](observedSyscalls...).Difference(savedSyscalls)
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
	// the process tries to use JSON patching to avoid conflicts between updates on the same object from different containers
	// 0. create both a patch and a new object
	// 1. try to apply the patch
	// 2a. the object doesn't exist - create the new object
	// 2b. the patch was invalid - get existing object to fix the patch
	// 3a. the object is missing its container slice - ADD one with the container profile at the right index
	// 3b. the object is missing the container profile - ADD the container profile at the right index
	// 3c. default - patch the container ourselves and REPLACE it at the right index
	if len(capabilities) > 0 || len(endpoints) > 0 || len(execs) > 0 || len(opens) > 0 || len(toSaveSyscalls) > 0 || len(initalizeOperations) > 0 || len(callStacks) > 0 || watchedContainer.StatusUpdated() {
		// 0. calculate patch
		operations := utils.CreateCapabilitiesPatchOperations(capabilities, observedSyscalls, execs, opens, endpoints, rulePolicies, callStacks, watchedContainer.ContainerType.String(), watchedContainer.ContainerIndex)
		if len(initalizeOperations) > 0 {
			operations = append(operations, initalizeOperations...)
		}

		operations = utils.AppendStatusAnnotationPatchOperations(operations, watchedContainer)
		operations = append(operations, utils.PatchOperation{
			Op:    "add",
			Path:  "/spec/architectures/-",
			Value: runtime.GOARCH,
		})

		// 1. try to patch object
		var gotErr error
		if err := am.storageClient.PatchApplicationProfile(slug, namespace, operations, watchedContainer.SyncChannel); err != nil {
			switch {
			case apierrors.IsTimeout(err):
				// backoff timeout, we have already retried for maxElapsedTime
				gotErr = err
				logger.L().Ctx(ctx).Debug("ApplicationProfileManager - failed to patch application profile", helpers.Error(err),
					helpers.String("slug", slug),
					helpers.Int("container index", watchedContainer.ContainerIndex),
					helpers.String("container ID", watchedContainer.ContainerID),
					helpers.String("k8s workload", watchedContainer.K8sContainerID))
			case apierrors.IsNotFound(err):
				// 2a. new object
				newObject := &v1beta1.ApplicationProfile{
					ObjectMeta: metav1.ObjectMeta{
						Name: slug,
						Annotations: map[string]string{
							helpersv1.InstanceIDMetadataKey: watchedContainer.InstanceID.GetStringNoContainer(),
							helpersv1.WlidMetadataKey:       watchedContainer.Wlid,
							helpersv1.CompletionMetadataKey: string(watchedContainer.GetCompletionStatus()),
							helpersv1.StatusMetadataKey:     string(watchedContainer.GetStatus()),
						},
						Labels: utils.GetLabels(watchedContainer, true),
					},
				}
				addContainers := func(containers []v1beta1.ApplicationProfileContainer, containerInfos []utils.ContainerInfo) []v1beta1.ApplicationProfileContainer {
					for _, info := range containerInfos {
						seccompProfile, err := am.seccompManager.GetSeccompProfile(info.Name, watchedContainer.SeccompProfilePath)
						if err != nil {
							logger.L().Ctx(ctx).Debug("ApplicationProfileManager - failed to get seccomp profile", helpers.Error(err),
								helpers.String("slug", slug),
								helpers.Int("container index", watchedContainer.ContainerIndex),
								helpers.String("container ID", watchedContainer.ContainerID),
								helpers.String("k8s workload", watchedContainer.K8sContainerID))
						}
						containers = append(containers, v1beta1.ApplicationProfileContainer{
							Name:                 info.Name,
							Endpoints:            make([]v1beta1.HTTPEndpoint, 0),
							Execs:                make([]v1beta1.ExecCalls, 0),
							Opens:                make([]v1beta1.OpenCalls, 0),
							Capabilities:         make([]string, 0),
							Syscalls:             make([]string, 0),
							PolicyByRuleId:       make(map[string]v1beta1.RulePolicy),
							IdentifiedCallStacks: make([]v1beta1.IdentifiedCallStack, 0),
							SeccompProfile:       seccompProfile,
							ImageTag:             info.ImageTag,
							ImageID:              info.ImageID,
						})
					}
					return containers
				}
				newObject.Spec.Architectures = []string{runtime.GOARCH}
				newObject.Spec.Containers = addContainers(newObject.Spec.Containers, watchedContainer.ContainerInfos[utils.Container])
				newObject.Spec.InitContainers = addContainers(newObject.Spec.InitContainers, watchedContainer.ContainerInfos[utils.InitContainer])
				newObject.Spec.EphemeralContainers = addContainers(newObject.Spec.EphemeralContainers, watchedContainer.ContainerInfos[utils.EphemeralContainer])
				// enrich container
				newContainer := utils.GetApplicationProfileContainer(newObject, watchedContainer.ContainerType, watchedContainer.ContainerIndex)
				utils.EnrichApplicationProfileContainer(newContainer, capabilities, observedSyscalls, execs, opens, endpoints, rulePolicies, callStacks, watchedContainer.ImageID, watchedContainer.ImageTag)
				// try to create object
				if err := am.storageClient.CreateApplicationProfile(newObject, namespace); err != nil {
					gotErr = err
					logger.L().Ctx(ctx).Warning("ApplicationProfileManager - failed to create application profile", helpers.Error(err),
						helpers.String("slug", slug),
						helpers.Int("container index", watchedContainer.ContainerIndex),
						helpers.String("container ID", watchedContainer.ContainerID),
						helpers.String("k8s workload", watchedContainer.K8sContainerID))
				}
			default:
				logger.L().Debug("ApplicationProfileManager - failed to patch application profile, will get existing one and adjust patch", helpers.Error(err),
					helpers.String("slug", slug),
					helpers.Int("container index", watchedContainer.ContainerIndex),
					helpers.String("container ID", watchedContainer.ContainerID),
					helpers.String("k8s workload", watchedContainer.K8sContainerID))
				// 2b. get existing object
				existingObject, err := am.storageClient.GetApplicationProfile(namespace, slug)
				if err != nil {
					gotErr = err
					logger.L().Ctx(ctx).Warning("ApplicationProfileManager - failed to get existing application profile", helpers.Error(err),
						helpers.String("slug", slug),
						helpers.Int("container index", watchedContainer.ContainerIndex),
						helpers.String("container ID", watchedContainer.ContainerID),
						helpers.String("k8s workload", watchedContainer.K8sContainerID))
				} else {
					var replaceOperations []utils.PatchOperation
					containerNames := watchedContainer.ContainerInfos[watchedContainer.ContainerType]
					// check existing container
					existingContainer := utils.GetApplicationProfileContainer(existingObject, watchedContainer.ContainerType, watchedContainer.ContainerIndex)
					if existingContainer == nil {
						info := containerNames[watchedContainer.ContainerIndex]
						seccompProfile, err := am.seccompManager.GetSeccompProfile(info.Name, watchedContainer.SeccompProfilePath)
						if err != nil {
							logger.L().Ctx(ctx).Debug("ApplicationProfileManager - failed to get seccomp profile", helpers.Error(err),
								helpers.String("slug", slug),
								helpers.Int("container index", watchedContainer.ContainerIndex),
								helpers.String("container ID", watchedContainer.ContainerID),
								helpers.String("k8s workload", watchedContainer.K8sContainerID))
						}
						existingContainer = &v1beta1.ApplicationProfileContainer{
							Name:                 info.Name,
							Endpoints:            make([]v1beta1.HTTPEndpoint, 0),
							Execs:                make([]v1beta1.ExecCalls, 0),
							Opens:                make([]v1beta1.OpenCalls, 0),
							Capabilities:         make([]string, 0),
							Syscalls:             make([]string, 0),
							PolicyByRuleId:       make(map[string]v1beta1.RulePolicy),
							IdentifiedCallStacks: make([]v1beta1.IdentifiedCallStack, 0),
							SeccompProfile:       seccompProfile,
							ImageTag:             info.ImageTag,
							ImageID:              info.ImageID,
						}
					}
					// update it
					utils.EnrichApplicationProfileContainer(existingContainer, capabilities, observedSyscalls, execs, opens, endpoints, rulePolicies, callStacks, watchedContainer.ImageID, watchedContainer.ImageTag)
					// get existing containers
					var existingContainers []v1beta1.ApplicationProfileContainer
					if watchedContainer.ContainerType == utils.Container {
						existingContainers = existingObject.Spec.Containers
					} else if watchedContainer.ContainerType == utils.InitContainer {
						existingContainers = existingObject.Spec.InitContainers
					} else {
						existingContainers = existingObject.Spec.EphemeralContainers
					}
					// replace or add container using patch
					// 3a. ensure we have a container slice
					if existingContainers == nil {
						replaceOperations = append(replaceOperations, utils.PatchOperation{
							Op:    "add",
							Path:  fmt.Sprintf("/spec/%s", watchedContainer.ContainerType),
							Value: make([]v1beta1.ApplicationProfileContainer, 0),
						})
					}
					// 3b. ensure the slice has all the containers
					for i := len(existingContainers); i < len(containerNames); i++ {
						info := containerNames[i]
						seccompProfile, err := am.seccompManager.GetSeccompProfile(info.Name, watchedContainer.SeccompProfilePath)
						if err != nil {
							logger.L().Ctx(ctx).Debug("ApplicationProfileManager - failed to get seccomp profile", helpers.Error(err),
								helpers.String("slug", slug),
								helpers.Int("container index", watchedContainer.ContainerIndex),
								helpers.String("container ID", watchedContainer.ContainerID),
								helpers.String("k8s workload", watchedContainer.K8sContainerID))
						}
						replaceOperations = append(replaceOperations, utils.PatchOperation{
							Op:   "add",
							Path: fmt.Sprintf("/spec/%s/%d", watchedContainer.ContainerType, i),
							Value: v1beta1.ApplicationProfileContainer{
								Name:                 info.Name,
								Endpoints:            make([]v1beta1.HTTPEndpoint, 0),
								Execs:                make([]v1beta1.ExecCalls, 0),
								Opens:                make([]v1beta1.OpenCalls, 0),
								Capabilities:         make([]string, 0),
								Syscalls:             make([]string, 0),
								PolicyByRuleId:       make(map[string]v1beta1.RulePolicy),
								IdentifiedCallStacks: make([]v1beta1.IdentifiedCallStack, 0),
								SeccompProfile:       seccompProfile,
								ImageTag:             info.ImageTag,
								ImageID:              info.ImageID,
							},
						})
					}
					// 3c. replace the existing container at the right index
					replaceOperations = append(replaceOperations, utils.PatchOperation{
						Op:    "replace",
						Path:  fmt.Sprintf("/spec/%s/%d", watchedContainer.ContainerType, watchedContainer.ContainerIndex),
						Value: existingContainer,
					})

					replaceOperations = utils.AppendStatusAnnotationPatchOperations(replaceOperations, watchedContainer)
					if len(existingObject.Spec.Architectures) == 0 {
						replaceOperations = append(replaceOperations, utils.PatchOperation{
							Op:    "add",
							Path:  "/spec/architectures",
							Value: []string{runtime.GOARCH},
						})
					} else {
						replaceOperations = append(replaceOperations, utils.PatchOperation{
							Op:    "add",
							Path:  "/spec/architectures/-",
							Value: runtime.GOARCH,
						})
					}

					if err := am.storageClient.PatchApplicationProfile(slug, namespace, replaceOperations, watchedContainer.SyncChannel); err != nil {
						gotErr = err
						logger.L().Ctx(ctx).Warning("ApplicationProfileManager - failed to patch application profile", helpers.Error(err),
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

			// record saved syscalls
			am.savedSyscalls.Get(watchedContainer.K8sContainerID).Append(toSaveSyscalls...)
			// record saved capabilities
			savedCapabilities := am.savedCapabilities.Get(watchedContainer.K8sContainerID)
			for _, capability := range capabilities {
				savedCapabilities.Set(capability, nil)
			}
			// record saved endpoints
			savedEndpoints := am.savedEndpoints.Get(watchedContainer.K8sContainerID)
			toSaveEndpoints.Range(func(path string, endpoint *v1beta1.HTTPEndpoint) bool {
				savedEndpoints.Set(path, endpoint)
				return true
			})
			// record saved execs
			savedExecs := am.savedExecs.Get(watchedContainer.K8sContainerID)
			toSaveExecs.Range(func(uniqueExecIdentifier string, v []string) bool {
				savedExecs.Set(uniqueExecIdentifier, v)
				return true
			})
			// record saved opens
			savedOpens := am.savedOpens.Get(watchedContainer.K8sContainerID)
			toSaveOpens.Range(func(path string, newOpens mapset.Set[string]) bool {
				if oldOpens, ok := savedOpens.Get(path); ok {
					oldOpens.(mapset.Set[string]).Append(newOpens.ToSlice()...)
				} else {
					savedOpens.Set(path, newOpens)
				}
				return true
			})

			// record saved rule policies
			toSaveRulePolicies.Range(func(ruleIdentifier string, rulePolicy *v1beta1.RulePolicy) bool {
				if !am.toSaveRulePolicies.Get(watchedContainer.K8sContainerID).Has(ruleIdentifier) {
					am.savedRulePolicies.Get(watchedContainer.K8sContainerID).Set(ruleIdentifier, rulePolicy)
				}
				return true
			})

			// record saved call stacks
			toSaveCallStacks.Range(func(identifier string, callStack *v1beta1.IdentifiedCallStack) bool {
				if !am.toSaveCallStacks.Get(watchedContainer.K8sContainerID).Has(identifier) {
					am.savedCallStacks.Get(watchedContainer.K8sContainerID).Set(identifier, callStack)
				}
				return true
			})

			logger.L().Debug("ApplicationProfileManager - saved application profile",
				helpers.Int("capabilities", len(capabilities)),
				helpers.Int("endpoints", toSaveEndpoints.Len()),
				helpers.Int("execs", toSaveExecs.Len()),
				helpers.Int("opens", toSaveOpens.Len()),
				helpers.Int("rule policies", toSaveRulePolicies.Len()),
				helpers.Int("call stacks", toSaveCallStacks.Len()),
				helpers.Int("init operations", len(initalizeOperations)),
				helpers.String("slug", slug),
				helpers.Int("container index", watchedContainer.ContainerIndex),
				helpers.String("container ID", watchedContainer.ContainerID),
				helpers.String("k8s workload", watchedContainer.K8sContainerID),
				helpers.String("status", string(watchedContainer.GetStatus())),
				helpers.String("completion status", string(watchedContainer.GetCompletionStatus())),
			)
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
		TemplateHash:           sharedData.TemplateHash,
		Wlid:                   sharedData.Wlid,
		ParentResourceVersion:  sharedData.ParentResourceVersion,
		ContainerInfos:         sharedData.ContainerInfos,
		ParentWorkloadSelector: sharedData.ParentWorkloadSelector,
		SeccompProfilePath:     sharedData.SeccompProfilePath,
		ContainerType:          sharedData.ContainerType,
		ContainerIndex:         sharedData.ContainerIndex,
		PreRunningContainer:    sharedData.PreRunningContainer,
	}

	if !am.apMetadataCache.Has(watchedContainer.Wlid) && !am.apMetadataCache.IsNamespaceFetched(container.K8s.Namespace) {
		aps, err := am.storageClient.ListApplicationProfiles(container.K8s.Namespace)
		if err != nil {
			logger.L().Ctx(am.ctx).Warning("ApplicationProfileManager - failed to list application profiles", helpers.Error(err))
			return
		}

		// Update this section to populate the new metadata cache with APMetadata
		for _, ap := range aps.Items {
			wlid, ok := ap.Annotations[helpersv1.WlidMetadataKey]
			if !ok {
				continue
			}

			status := ap.Annotations[helpersv1.StatusMetadataKey]
			completionStatus := ap.Annotations[helpersv1.CompletionMetadataKey]

			am.apMetadataCache.Set(wlid, APMetadata{
				Status:           status,
				CompletionStatus: completionStatus,
				Wlid:             wlid,
			})
		}

		am.apMetadataCache.MarkNamespaceFetched(container.K8s.Namespace)
	}

	if err := am.monitorContainer(ctx, container, watchedContainer); err != nil {
		logger.L().Debug("ApplicationProfileManager - stop monitor on container", helpers.String("reason", err.Error()),
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
	if am.cfg.SkipNamespace(notif.Container.K8s.Namespace) {
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
		am.savedCapabilities.Set(k8sContainerID, cache.NewTTL(5*am.cfg.UpdateDataPeriod, am.cfg.UpdateDataPeriod))
		am.savedEndpoints.Set(k8sContainerID, cache.NewTTL(5*am.cfg.UpdateDataPeriod, am.cfg.UpdateDataPeriod))
		am.savedExecs.Set(k8sContainerID, cache.NewTTL(5*am.cfg.UpdateDataPeriod, am.cfg.UpdateDataPeriod))
		am.savedOpens.Set(k8sContainerID, cache.NewTTL(5*am.cfg.UpdateDataPeriod, am.cfg.UpdateDataPeriod))
		am.savedSyscalls.Set(k8sContainerID, mapset.NewSet[string]())
		am.savedRulePolicies.Set(k8sContainerID, cache.NewTTL(5*am.cfg.UpdateDataPeriod, am.cfg.UpdateDataPeriod))
		am.toSaveCapabilities.Set(k8sContainerID, mapset.NewSet[string]())
		am.toSaveEndpoints.Set(k8sContainerID, new(maps.SafeMap[string, *v1beta1.HTTPEndpoint]))
		am.toSaveExecs.Set(k8sContainerID, new(maps.SafeMap[string, []string]))
		am.toSaveOpens.Set(k8sContainerID, new(maps.SafeMap[string, mapset.Set[string]]))
		am.toSaveRulePolicies.Set(k8sContainerID, new(maps.SafeMap[string, *v1beta1.RulePolicy]))
		am.savedCallStacks.Set(k8sContainerID, cache.NewTTL(5*am.cfg.UpdateDataPeriod, am.cfg.UpdateDataPeriod))
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
	// check if we already have this capability
	if _, ok := am.savedCapabilities.Get(k8sContainerID).Get(capability); ok {
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

	if _, ok := am.savedExecs.Get(k8sContainerID).Get(execIdentifier); ok {
		return
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

	// check if we already have this open
	if opens, ok := am.savedOpens.Get(k8sContainerID).Get(path); ok && opens.(mapset.Set[string]).Contains(event.Flags...) {
		return
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
	if _, ok := am.savedEndpoints.Get(k8sContainerID).Get(endpointHash); ok {
		return
	}
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

	savedPolicies := am.savedRulePolicies.Get(k8sContainerID)
	savedPolicy, ok := savedPolicies.Get(ruleId)
	if ok {
		savedPolicy := savedPolicy.(*v1beta1.RulePolicy)
		if IsPolicyIncluded(savedPolicy, newPolicy) {
			return
		}
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

	// Check if we already have this call stack
	if _, ok := am.savedCallStacks.Get(k8sContainerID).Get(callStackIdentifier); ok {
		return
	}

	// Add to call stacks map
	am.toSaveCallStacks.Get(k8sContainerID).Set(callStackIdentifier, callStack)
}
