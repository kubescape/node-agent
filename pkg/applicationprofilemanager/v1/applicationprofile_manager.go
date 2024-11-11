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

	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/cenkalti/backoff/v4"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/node-agent/pkg/applicationprofilemanager"
	"github.com/kubescape/node-agent/pkg/config"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
	storageUtils "github.com/kubescape/storage/pkg/utils"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const OpenDynamicThreshold = 50

var procRegex = regexp.MustCompile(`^/proc/\d+`)

type ApplicationProfileManager struct {
	cfg                      config.Config
	clusterName              string
	ctx                      context.Context
	containerMutexes         storageUtils.MapMutex[string]                                      // key is k8sContainerID
	trackedContainers        mapset.Set[string]                                                 // key is k8sContainerID
	removedContainers        mapset.Set[string]                                                 // key is k8sContainerID
	droppedEvents            maps.SafeMap[string, bool]                                         // key is k8sContainerID
	savedCapabilities        maps.SafeMap[string, mapset.Set[string]]                           // key is k8sContainerID
	savedEndpoints           maps.SafeMap[string, *maps.SafeMap[string, *v1beta1.HTTPEndpoint]] // key is k8sContainerID
	savedExecs               maps.SafeMap[string, *maps.SafeMap[string, []string]]              // key is k8sContainerID
	savedOpens               maps.SafeMap[string, *maps.SafeMap[string, mapset.Set[string]]]    // key is k8sContainerID
	savedSyscalls            maps.SafeMap[string, mapset.Set[string]]                           // key is k8sContainerID
	savedRulePolicies        maps.SafeMap[string, *maps.SafeMap[string, *v1beta1.RulePolicy]]   // key is k8sContainerID
	toSaveCapabilities       maps.SafeMap[string, mapset.Set[string]]                           // key is k8sContainerID
	toSaveEndpoints          maps.SafeMap[string, *maps.SafeMap[string, *v1beta1.HTTPEndpoint]] // key is k8sContainerID
	toSaveExecs              maps.SafeMap[string, *maps.SafeMap[string, []string]]              // key is k8sContainerID
	toSaveOpens              maps.SafeMap[string, *maps.SafeMap[string, mapset.Set[string]]]    // key is k8sContainerID
	toSaveRulePolicies       maps.SafeMap[string, *maps.SafeMap[string, *v1beta1.RulePolicy]]   // key is k8sContainerID
	watchedContainerChannels maps.SafeMap[string, chan error]                                   // key is ContainerID
	k8sClient                k8sclient.K8sClientInterface
	k8sObjectCache           objectcache.K8sObjectCache
	storageClient            storage.StorageClient
	syscallPeekFunc          func(nsMountId uint64) ([]string, error)
	preRunningContainerIDs   mapset.Set[string]
	seccompManager           seccompmanager.SeccompManagerClient
}

var _ applicationprofilemanager.ApplicationProfileManagerClient = (*ApplicationProfileManager)(nil)

func CreateApplicationProfileManager(ctx context.Context, cfg config.Config, clusterName string, k8sClient k8sclient.K8sClientInterface, storageClient storage.StorageClient, preRunningContainerIDs mapset.Set[string], k8sObjectCache objectcache.K8sObjectCache, seccompManager seccompmanager.SeccompManagerClient) (*ApplicationProfileManager, error) {
	return &ApplicationProfileManager{
		cfg:                    cfg,
		clusterName:            clusterName,
		ctx:                    ctx,
		k8sClient:              k8sClient,
		k8sObjectCache:         k8sObjectCache,
		storageClient:          storageClient,
		containerMutexes:       storageUtils.NewMapMutex[string](),
		trackedContainers:      mapset.NewSet[string](),
		removedContainers:      mapset.NewSet[string](),
		preRunningContainerIDs: preRunningContainerIDs,
		seccompManager:         seccompManager,
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
	// fill container type, index and names
	if watchedContainer.ContainerType == utils.Unknown {
		watchedContainer.SetContainerInfo(pod, container.K8s.ContainerName)
	}
	return nil
}

func (am *ApplicationProfileManager) deleteResources(watchedContainer *utils.WatchedContainerData) {
	// make sure we don't run deleteResources and saveProfile at the same time
	am.containerMutexes.Lock(watchedContainer.K8sContainerID)
	defer am.containerMutexes.Unlock(watchedContainer.K8sContainerID)
	am.removedContainers.Add(watchedContainer.K8sContainerID)
	// delete resources
	watchedContainer.UpdateDataTicker.Stop()
	am.trackedContainers.Remove(watchedContainer.K8sContainerID)
	am.savedCapabilities.Delete(watchedContainer.K8sContainerID)
	am.savedEndpoints.Delete(watchedContainer.K8sContainerID)
	am.savedExecs.Delete(watchedContainer.K8sContainerID)
	am.droppedEvents.Delete(watchedContainer.K8sContainerID)
	am.savedOpens.Delete(watchedContainer.K8sContainerID)
	am.savedSyscalls.Delete(watchedContainer.K8sContainerID)
	am.savedRulePolicies.Delete(watchedContainer.K8sContainerID)
	am.toSaveCapabilities.Delete(watchedContainer.K8sContainerID)
	am.toSaveEndpoints.Delete(watchedContainer.K8sContainerID)
	am.toSaveExecs.Delete(watchedContainer.K8sContainerID)
	am.toSaveOpens.Delete(watchedContainer.K8sContainerID)
	am.toSaveRulePolicies.Delete(watchedContainer.K8sContainerID)
	am.watchedContainerChannels.Delete(watchedContainer.ContainerID)
}
func (am *ApplicationProfileManager) ContainerReachedMaxTime(containerID string) {
	if channel := am.watchedContainerChannels.Get(containerID); channel != nil {
		channel <- utils.ContainerReachedMaxTime
	}
}

func (am *ApplicationProfileManager) monitorContainer(ctx context.Context, container *containercollection.Container, watchedContainer *utils.WatchedContainerData) error {
	logger.L().Debug("ApplicationProfileManager - start monitor on container",
		helpers.Interface("preRunning", am.preRunningContainerIDs.Contains(container.Runtime.ContainerID)),
		helpers.Int("container index", watchedContainer.ContainerIndex),
		helpers.String("container ID", watchedContainer.ContainerID),
		helpers.String("k8s workload", watchedContainer.K8sContainerID))

	// set completion status & status as soon as we start monitoring the container
	if am.preRunningContainerIDs.Contains(container.Runtime.ContainerID) {
		watchedContainer.SetCompletionStatus(utils.WatchedContainerCompletionStatusPartial)
	} else {
		watchedContainer.SetCompletionStatus(utils.WatchedContainerCompletionStatusFull)
	}
	watchedContainer.SetStatus(utils.WatchedContainerStatusInitializing)

	initOps := GetInitOperations(watchedContainer.ContainerType.String(), watchedContainer.ContainerIndex)
	am.saveProfile(ctx, watchedContainer, container.K8s.Namespace, initOps)

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
	am.containerMutexes.Lock(watchedContainer.K8sContainerID)
	defer am.containerMutexes.Unlock(watchedContainer.K8sContainerID)

	// verify the container hasn't already been deleted
	if !am.trackedContainers.Contains(watchedContainer.K8sContainerID) {
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
	slug, err := watchedContainer.InstanceID.GetSlug(true)
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

	// new activity
	// the process tries to use JSON patching to avoid conflicts between updates on the same object from different containers
	// 0. create both a patch and a new object
	// 1. try to apply the patch
	// 2a. the object doesn't exist - create the new object
	// 2b. the patch was invalid - get existing object to fix the patch
	// 3a. the object is missing its container slice - ADD one with the container profile at the right index
	// 3b. the object is missing the container profile - ADD the container profile at the right index
	// 3c. default - patch the container ourselves and REPLACE it at the right index
	if len(capabilities) > 0 || len(endpoints) > 0 || len(execs) > 0 || len(opens) > 0 || len(toSaveSyscalls) > 0 || len(initalizeOperations) > 0 || watchedContainer.StatusUpdated() {
		// 0. calculate patch
		operations := utils.CreateCapabilitiesPatchOperations(capabilities, observedSyscalls, execs, opens, endpoints, rulePolicies, watchedContainer.ContainerType.String(), watchedContainer.ContainerIndex)
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
			if apierrors.IsNotFound(err) {
				// 2a. new object
				newObject := &v1beta1.ApplicationProfile{
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
				addContainers := func(containers []v1beta1.ApplicationProfileContainer, containerNames []string) []v1beta1.ApplicationProfileContainer {
					for _, name := range containerNames {
						seccompProfile, err := am.seccompManager.GetSeccompProfile(name, watchedContainer.SeccompProfilePath)
						if err != nil {
							logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to get seccomp profile", helpers.Error(err),
								helpers.String("slug", slug),
								helpers.Int("container index", watchedContainer.ContainerIndex),
								helpers.String("container ID", watchedContainer.ContainerID),
								helpers.String("k8s workload", watchedContainer.K8sContainerID))
						}
						containers = append(containers, v1beta1.ApplicationProfileContainer{
							Name:           name,
							Endpoints:      make([]v1beta1.HTTPEndpoint, 0),
							Execs:          make([]v1beta1.ExecCalls, 0),
							Opens:          make([]v1beta1.OpenCalls, 0),
							Capabilities:   make([]string, 0),
							Syscalls:       make([]string, 0),
							PolicyByRuleId: make(map[string]v1beta1.RulePolicy),
							SeccompProfile: seccompProfile,
						})
					}
					return containers
				}
				newObject.Spec.Architectures = []string{runtime.GOARCH}
				newObject.Spec.Containers = addContainers(newObject.Spec.Containers, watchedContainer.ContainerNames[utils.Container])
				newObject.Spec.InitContainers = addContainers(newObject.Spec.InitContainers, watchedContainer.ContainerNames[utils.InitContainer])
				newObject.Spec.EphemeralContainers = addContainers(newObject.Spec.EphemeralContainers, watchedContainer.ContainerNames[utils.EphemeralContainer])
				// enrich container
				newContainer := utils.GetApplicationProfileContainer(newObject, watchedContainer.ContainerType, watchedContainer.ContainerIndex)
				utils.EnrichApplicationProfileContainer(newContainer, capabilities, observedSyscalls, execs, opens, endpoints, rulePolicies)
				// try to create object
				if err := am.storageClient.CreateApplicationProfile(newObject, namespace); err != nil {
					gotErr = err
					logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to create application profile", helpers.Error(err),
						helpers.String("slug", slug),
						helpers.Int("container index", watchedContainer.ContainerIndex),
						helpers.String("container ID", watchedContainer.ContainerID),
						helpers.String("k8s workload", watchedContainer.K8sContainerID))
				}
			} else {
				logger.L().Debug("ApplicationProfileManager - failed to patch application profile, will get existing one and adjust patch", helpers.Error(err),
					helpers.String("slug", slug),
					helpers.Int("container index", watchedContainer.ContainerIndex),
					helpers.String("container ID", watchedContainer.ContainerID),
					helpers.String("k8s workload", watchedContainer.K8sContainerID))
				// 2b. get existing object
				existingObject, err := am.storageClient.GetApplicationProfile(namespace, slug)
				if err != nil {
					gotErr = err
					logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to get existing application profile", helpers.Error(err),
						helpers.String("slug", slug),
						helpers.Int("container index", watchedContainer.ContainerIndex),
						helpers.String("container ID", watchedContainer.ContainerID),
						helpers.String("k8s workload", watchedContainer.K8sContainerID))
				} else {
					var replaceOperations []utils.PatchOperation
					containerNames := watchedContainer.ContainerNames[watchedContainer.ContainerType]
					// check existing container
					existingContainer := utils.GetApplicationProfileContainer(existingObject, watchedContainer.ContainerType, watchedContainer.ContainerIndex)
					if existingContainer == nil {
						name := containerNames[watchedContainer.ContainerIndex]
						seccompProfile, err := am.seccompManager.GetSeccompProfile(name, watchedContainer.SeccompProfilePath)
						if err != nil {
							logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to get seccomp profile", helpers.Error(err),
								helpers.String("slug", slug),
								helpers.Int("container index", watchedContainer.ContainerIndex),
								helpers.String("container ID", watchedContainer.ContainerID),
								helpers.String("k8s workload", watchedContainer.K8sContainerID))
						}
						logger.L().Debug("ApplicationProfileManager - got seccomp profile", helpers.Interface("profile", seccompProfile))
						existingContainer = &v1beta1.ApplicationProfileContainer{
							Name:           containerNames[watchedContainer.ContainerIndex],
							Endpoints:      make([]v1beta1.HTTPEndpoint, 0),
							Execs:          make([]v1beta1.ExecCalls, 0),
							Opens:          make([]v1beta1.OpenCalls, 0),
							Capabilities:   make([]string, 0),
							Syscalls:       make([]string, 0),
							PolicyByRuleId: make(map[string]v1beta1.RulePolicy),
							SeccompProfile: seccompProfile,
						}
					}
					// update it
					utils.EnrichApplicationProfileContainer(existingContainer, capabilities, observedSyscalls, execs, opens, endpoints, rulePolicies)
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
						name := containerNames[i]
						seccompProfile, err := am.seccompManager.GetSeccompProfile(name, watchedContainer.SeccompProfilePath)
						if err != nil {
							logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to get seccomp profile", helpers.Error(err),
								helpers.String("slug", slug),
								helpers.Int("container index", watchedContainer.ContainerIndex),
								helpers.String("container ID", watchedContainer.ContainerID),
								helpers.String("k8s workload", watchedContainer.K8sContainerID))
						}
						replaceOperations = append(replaceOperations, utils.PatchOperation{
							Op:   "add",
							Path: fmt.Sprintf("/spec/%s/%d", watchedContainer.ContainerType, i),
							Value: v1beta1.ApplicationProfileContainer{
								Name:           name,
								Endpoints:      make([]v1beta1.HTTPEndpoint, 0),
								Execs:          make([]v1beta1.ExecCalls, 0),
								Opens:          make([]v1beta1.OpenCalls, 0),
								Capabilities:   make([]string, 0),
								Syscalls:       make([]string, 0),
								PolicyByRuleId: make(map[string]v1beta1.RulePolicy),
								SeccompProfile: seccompProfile,
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
		} else {
			// for status updates to be tracked, we reset the update flag
			watchedContainer.ResetStatusUpdatedFlag()

			// record saved syscalls
			am.savedSyscalls.Get(watchedContainer.K8sContainerID).Append(toSaveSyscalls...)
			// record saved capabilities
			am.savedCapabilities.Get(watchedContainer.K8sContainerID).Append(capabilities...)
			// record saved endpoints
			toSaveEndpoints.Range(func(path string, endpoint *v1beta1.HTTPEndpoint) bool {
				if !am.savedEndpoints.Get(watchedContainer.K8sContainerID).Has(path) {
					am.savedEndpoints.Get(watchedContainer.K8sContainerID).Set(path, endpoint)
				}
				return true
			})
			// record saved execs
			toSaveExecs.Range(func(uniqueExecIdentifier string, v []string) bool {
				if !am.savedExecs.Get(watchedContainer.K8sContainerID).Has(uniqueExecIdentifier) {
					am.savedExecs.Get(watchedContainer.K8sContainerID).Set(uniqueExecIdentifier, v)
				}
				return true
			})
			// record saved opens
			savedOpens := am.savedOpens.Get(watchedContainer.K8sContainerID)
			toSaveOpens.Range(utils.SetInMap(savedOpens))
			// use a dynamic path detector to compress opens
			analyzer := dynamicpathdetector.NewPathAnalyzer(OpenDynamicThreshold)
			keys := savedOpens.Keys()
			// first pass to learn the opens
			for _, path := range keys {
				_, _ = dynamicpathdetector.AnalyzeOpen(path, analyzer)
			}
			// second pass to compress the opens
			for _, path := range keys {
				result, err := dynamicpathdetector.AnalyzeOpen(path, analyzer)
				if err != nil {
					continue
				}
				if result != path {
					// path becomes compressed
					// we avoid a lock by using Pop to remove path and retrieve its flags
					pathFlags := savedOpens.Pop(path)
					if savedOpens.Has(result) {
						// merge flags
						savedOpens.Get(result).Append(pathFlags.ToSlice()...)
					} else {
						// create new entry
						savedOpens.Set(result, pathFlags)
					}
				}
			}

			// record saved rule policies
			toSaveRulePolicies.Range(func(ruleIdentifier string, rulePolicy *v1beta1.RulePolicy) bool {
				if !am.savedRulePolicies.Get(watchedContainer.K8sContainerID).Has(ruleIdentifier) {
					am.savedRulePolicies.Get(watchedContainer.K8sContainerID).Set(ruleIdentifier, rulePolicy)
				}
				return true
			})

			logger.L().Debug("ApplicationProfileManager - saved application profile",
				helpers.Int("capabilities", len(capabilities)),
				helpers.Int("endpoints", toSaveEndpoints.Len()),
				helpers.Int("execs", toSaveExecs.Len()),
				helpers.Int("opens", toSaveOpens.Len()),
				helpers.Int("rule policies", toSaveRulePolicies.Len()),
				helpers.Int("init operations", len(initalizeOperations)),
				helpers.String("slug", slug),
				helpers.Int("container index", watchedContainer.ContainerIndex),
				helpers.String("container ID", watchedContainer.ContainerID),
				helpers.String("k8s workload", watchedContainer.K8sContainerID))
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
		UpdateDataTicker: time.NewTicker(utils.AddJitter(am.cfg.InitialDelay, am.cfg.MaxJitterPercentage)),
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
	if am.removedContainers.Contains(k8sContainerID) {
		return fmt.Errorf("container %s has been removed", k8sContainerID)
	}
	return backoff.Retry(func() error {
		if am.trackedContainers.Contains(k8sContainerID) {
			return nil
		}
		return fmt.Errorf("container %s not found", k8sContainerID)
	}, backoff.NewExponentialBackOff())
}

func (am *ApplicationProfileManager) ContainerCallback(notif containercollection.PubSubEvent) {
	// check if the container should be ignored
	if am.cfg.SkipNamespace(notif.Container.K8s.Namespace) {
		return
	}

	k8sContainerID := utils.CreateK8sContainerID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.ContainerName)
	ctx, span := otel.Tracer("").Start(am.ctx, "ApplicationProfileManager.ContainerCallback", trace.WithAttributes(attribute.String("containerID", notif.Container.Runtime.ContainerID), attribute.String("k8s workload", k8sContainerID)))
	defer span.End()

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		if am.watchedContainerChannels.Has(notif.Container.Runtime.ContainerID) {
			return
		}
		am.savedCapabilities.Set(k8sContainerID, mapset.NewSet[string]())
		am.droppedEvents.Set(k8sContainerID, false)
		am.savedEndpoints.Set(k8sContainerID, new(maps.SafeMap[string, *v1beta1.HTTPEndpoint]))
		am.savedExecs.Set(k8sContainerID, new(maps.SafeMap[string, []string]))
		am.savedOpens.Set(k8sContainerID, new(maps.SafeMap[string, mapset.Set[string]]))
		am.savedSyscalls.Set(k8sContainerID, mapset.NewSet[string]())
		am.savedRulePolicies.Set(k8sContainerID, new(maps.SafeMap[string, *v1beta1.RulePolicy]))
		am.toSaveCapabilities.Set(k8sContainerID, mapset.NewSet[string]())
		am.toSaveEndpoints.Set(k8sContainerID, new(maps.SafeMap[string, *v1beta1.HTTPEndpoint]))
		am.toSaveExecs.Set(k8sContainerID, new(maps.SafeMap[string, []string]))
		am.toSaveOpens.Set(k8sContainerID, new(maps.SafeMap[string, mapset.Set[string]]))
		am.toSaveRulePolicies.Set(k8sContainerID, new(maps.SafeMap[string, *v1beta1.RulePolicy]))
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
	if am.savedCapabilities.Get(k8sContainerID).ContainsOne(capability) {
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
	// we use a SHA256 hash of the exec to identify it uniquely (path + args, in the order they were provided)
	savedExecs := am.savedExecs.Get(k8sContainerID)
	execIdentifier := utils.CalculateSHA256FileExecHash(path, args)
	if savedExecs.Has(execIdentifier) {
		return
	}

	// add to exec map, first element is the path, the rest are the args
	execMap := am.toSaveExecs.Get(k8sContainerID)
	execMap.Set(execIdentifier, append([]string{path}, args...))
}

func (am *ApplicationProfileManager) ReportFileOpen(k8sContainerID, path string, flags []string) {
	if err := am.waitForContainer(k8sContainerID); err != nil {
		return
	}
	// deduplicate /proc/1234/* into /proc/.../* (quite a common case)
	// we perform it here instead of waiting for compression
	if strings.HasPrefix(path, "/proc/") {
		path = procRegex.ReplaceAllString(path, "/proc/"+dynamicpathdetector.DynamicIdentifier)
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

func (am *ApplicationProfileManager) ReportHTTPEvent(k8sContainerID string, event *tracerhttptype.Event) {
	if err := am.waitForContainer(k8sContainerID); err != nil {
		return
	}

	endpointIdentifier, err := GetEndpointIdentifier(event)
	if err != nil {
		return
	}

	endpoint, err := GetNewEndpoint(event, endpointIdentifier)
	if err != nil {
		return
	}

	endpointMap := am.toSaveEndpoints.Get(k8sContainerID)
	endpointHash := CalculateHTTPEndpointHash(endpoint)
	endpointMap.Set(endpointHash, endpoint)
}

func (am *ApplicationProfileManager) ReportRulePolicy(k8sContainerID, ruleId, allowedProcess string, allowedContainer bool) {
	if err := am.waitForContainer(k8sContainerID); err != nil {
		return
	}

	savedPolicies := am.savedRulePolicies.Get(k8sContainerID)
	savedPolicy := savedPolicies.Get(ruleId)

	toBeSavedPolicies := am.toSaveRulePolicies.Get(k8sContainerID)
	toBeSavedPolicy := toBeSavedPolicies.Get(ruleId)

	newPolicy := &v1beta1.RulePolicy{
		AllowedContainer: allowedContainer,
		AllowedProcesses: []string{allowedProcess},
	}

	if IsPolicyIncluded(savedPolicy, newPolicy) {
		return
	}

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
