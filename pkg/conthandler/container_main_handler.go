package conthandler

import (
	"errors"
	"fmt"
	"node-agent/pkg/config"
	"node-agent/pkg/context"
	v1 "node-agent/pkg/conthandler/v1"
	"node-agent/pkg/sbom"
	sbomV1 "node-agent/pkg/sbom/v1"
	"node-agent/pkg/storageclient"
	"sync"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerexec "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	traceropen "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/tracer"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	bolt "go.etcd.io/bbolt"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	execTraceName       = "trace_exec"
	openTraceName       = "trace_open"
	RelevantCVEsService = "RelevantCVEsService"
	StepGetSBOM         = "StepGetSBOM"
	StepValidateSBOM    = "StepValidateSBOM"
	StepEventAggregator = "StepEventAggregator"
)

var (
	containerAlreadyExistError  = errors.New("container already exist")
	containerHasTerminatedError = errors.New("container has terminated")
)

type supportedServices string

type afterTimerActionsData struct {
	containerID string
	service     supportedServices
}

type watchedContainerData struct {
	snifferTicker  *time.Ticker
	event          v1.ContainerEventData
	syncChannel    map[string]chan error
	sbomClient     sbom.SBOMClient
	imageID        string
	k8sContainerID string
}

type ContainerHandler struct {
	containerWatcher         ContainerWatcherClient
	watchedContainers        sync.Map
	afterTimerActionsChannel chan afterTimerActionsData
	storageClient            storageclient.StorageClient
	containerCollection      *containercollection.ContainerCollection
	tracerCollection         *tracercollection.TracerCollection
	tracerExec               *tracerexec.Tracer
	tracerOpen               *traceropen.Tracer
	fileDB                   *bolt.DB
}

var _ ContainerMainHandlerClient = (*ContainerHandler)(nil)

func CreateContainerHandler(contClient ContainerClient, storageClient storageclient.StorageClient) (*ContainerHandler, error) {

	contWatcher, err := CreateContainerWatcher(contClient)
	if err != nil {
		return nil, err
	}
	// Use container collection to get notified for new containers
	containerCollection := &containercollection.ContainerCollection{}
	// Create a tracer collection instance
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	if err != nil {
		return nil, fmt.Errorf("failed to create trace-collection: %s\n", err)
	}
	// Create a db instance
	db, err := bolt.Open("file.db", 0666, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create fileDB: %s\n", err)
	}

	return &ContainerHandler{
		containerWatcher:         contWatcher,
		watchedContainers:        sync.Map{},
		afterTimerActionsChannel: make(chan afterTimerActionsData, 50),
		storageClient:            storageClient,
		containerCollection:      containerCollection,
		tracerCollection:         tracerCollection,
		fileDB:                   db,
	}, nil
}

func (ch *ContainerHandler) afterTimerActions() error {
	var err error

	for {
		afterTimerActionsData := <-ch.afterTimerActionsChannel
		containerDataInterface, exist := ch.watchedContainers.Load(afterTimerActionsData.containerID)
		if !exist {
			ctx, span := otel.Tracer("").Start(context.GetBackgroundContext(), "LoadContainerIDFromMap")
			logger.L().Ctx(ctx).Warning("afterTimerActions: failed to get container data of container ID", []helpers.IDetails{helpers.String("container ID", afterTimerActionsData.containerID)}...)
			span.End()
			continue
		}
		containerData := containerDataInterface.(watchedContainerData)

		if config.GetConfigurationConfigContext().IsRelevantCVEServiceEnabled() && afterTimerActionsData.service == RelevantCVEsService {
			fileList := make(map[string]bool)
			err = ch.fileDB.View(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(containerData.k8sContainerID))
				if b == nil {
					return fmt.Errorf("bucket does not exist for container %s", containerData.k8sContainerID)
				}
				c := b.Cursor()
				for k, _ := c.First(); k != nil; k, _ = c.Next() {
					fileList[string(k)] = true
				}
				return nil
			})
			if err != nil {
				logger.L().Debug("failed to get file list", []helpers.IDetails{helpers.String("container ID", afterTimerActionsData.containerID), helpers.String("container name", containerData.event.GetContainerName()), helpers.String("k8s resource ", containerData.event.GetK8SWorkloadID()), helpers.Error(err)}...)
				continue
			}
			logger.L().Debug("fileList generated", []helpers.IDetails{helpers.String("container ID", afterTimerActionsData.containerID), helpers.String("container name", containerData.event.GetContainerName()), helpers.String("k8s resource ", containerData.event.GetK8SWorkloadID()), helpers.String("file list", fmt.Sprintf("%v", fileList))}...)
			ctxPostSBOM, spanPostSBOM := otel.Tracer("").Start(context.GetBackgroundContext(), "PostFilterSBOM")
			if err = <-containerData.syncChannel[StepGetSBOM]; err != nil {
				logger.L().Debug("failed to get SBOM", []helpers.IDetails{helpers.String("container ID", afterTimerActionsData.containerID), helpers.String("container name", containerData.event.GetContainerName()), helpers.String("k8s resource ", containerData.event.GetK8SWorkloadID()), helpers.Error(err)}...)
				continue
			}
			if err = containerData.sbomClient.ValidateSBOM(); err != nil {
				ctx, span := otel.Tracer("").Start(ctxPostSBOM, "ValidateSBOM")
				logger.L().Ctx(ctx).Warning("SBOM is incomplete", []helpers.IDetails{helpers.String("container ID", afterTimerActionsData.containerID), helpers.String("container name", containerData.event.GetContainerName()), helpers.String("k8s resource ", containerData.event.GetK8SWorkloadID()), helpers.Error(err)}...)
				containerData.syncChannel[StepValidateSBOM] <- err
				span.End()
			}
			if err = containerData.sbomClient.FilterSBOM(fileList); err != nil {
				ctx, span := otel.Tracer("").Start(ctxPostSBOM, "FilterSBOM")
				logger.L().Ctx(ctx).Warning("failed to filter SBOM", []helpers.IDetails{helpers.String("container ID", afterTimerActionsData.containerID), helpers.String("container name", containerData.event.GetContainerName()), helpers.String("k8s resource", containerData.event.GetK8SWorkloadID()), helpers.Error(err)}...)
				span.End()
				continue
			}
			filterSBOMKey, err := containerData.event.GetInstanceID().GetSlug()
			if err != nil {
				ctx, span := otel.Tracer("").Start(ctxPostSBOM, "filterSBOMKey")
				logger.L().Ctx(ctx).Warning("failed to get filterSBOMKey for store filter SBOM", []helpers.IDetails{helpers.String("container ID", afterTimerActionsData.containerID), helpers.String("container name", containerData.event.GetContainerName()), helpers.String("k8s resource", containerData.event.GetK8SWorkloadID()), helpers.Error(err)}...)
				span.End()
				continue
			}
			// it is safe to use containerData.imageID directly since we needed it to retrieve the SBOM
			if err = containerData.sbomClient.StoreFilterSBOM(containerData.imageID, filterSBOMKey); err != nil {
				if !errors.Is(err, sbom.IsAlreadyExist()) {
					ctx, span := otel.Tracer("").Start(ctxPostSBOM, "StoreFilterSBOM")
					logger.L().Ctx(ctx).Error("failed to store filtered SBOM", []helpers.IDetails{helpers.String("container ID", afterTimerActionsData.containerID), helpers.String("k8s resource", containerData.event.GetK8SWorkloadID()), helpers.Error(err)}...)
					span.End()
				}
				continue
			}
			logger.L().Info("filtered SBOM has been stored successfully", []helpers.IDetails{helpers.String("containerID", afterTimerActionsData.containerID), helpers.String("k8s resource", containerData.event.GetK8SWorkloadID())}...)
			spanPostSBOM.End()
		}
	}
}

func (ch *ContainerHandler) startTimer(watchedContainer watchedContainerData, containerID string) error {
	var err error
	select {
	case <-watchedContainer.snifferTicker.C:
		if config.GetConfigurationConfigContext().IsRelevantCVEServiceEnabled() {
			ch.afterTimerActionsChannel <- afterTimerActionsData{
				containerID: containerID,
				service:     RelevantCVEsService,
			}
		}
	case err = <-watchedContainer.syncChannel[StepEventAggregator]:
		if errors.Is(err, containerHasTerminatedError) {
			watchedContainer.snifferTicker.Stop()
			err = containerHasTerminatedError
		}
	case err = <-watchedContainer.syncChannel[StepValidateSBOM]:
		if errors.Is(err, sbomV1.SBOMIncomplete) {
			return err
		}
	}
	return err
}

func createTicker() *time.Ticker {
	return time.NewTicker(config.GetConfigurationConfigContext().GetUpdateDataPeriod())
}

func (ch *ContainerHandler) deleteResources(watchedContainer watchedContainerData, contEvent v1.ContainerEventData) {
	watchedContainer.snifferTicker.Stop()
	watchedContainer.sbomClient.CleanResources()
	ch.watchedContainers.Delete(contEvent.GetContainerID())
	event := containercollection.PubSubEvent{
		Timestamp: time.Now().Format(time.RFC3339),
		Type:      containercollection.EventTypeRemoveContainer,
		Container: contEvent.GetContainer(),
	}
	ch.tracerCollection.TracerMapsUpdater()(event)
}

func (ch *ContainerHandler) startRelevancyProcess(contEvent v1.ContainerEventData) {
	containerDataInterface, exist := ch.watchedContainers.Load(contEvent.GetContainerID())
	if !exist {
		ctx, span := otel.Tracer("").Start(context.GetBackgroundContext(), "container monitoring", trace.WithAttributes(attribute.String("containerID", contEvent.GetContainerID()), attribute.String("container workload", contEvent.GetK8SWorkloadID())))
		defer span.End()
		logger.L().Ctx(ctx).Error("startRelevancyProcess: failed to get container data", helpers.String("container ID", contEvent.GetContainerID()), helpers.String("container name", contEvent.GetContainerName()), helpers.String("k8s resources", contEvent.GetK8SWorkloadID()))
		return
	}
	watchedContainer := containerDataInterface.(watchedContainerData)

	now := time.Now()
	configStopTime := config.GetConfigurationConfigContext().GetSniffingMaxTimes()
	stopSniffingTime := now.Add(configStopTime)
	for time.Now().Before(stopSniffingTime) {
		go ch.getSBOM(contEvent)
		ctx, span := otel.Tracer("").Start(context.GetBackgroundContext(), "container monitoring", trace.WithAttributes(attribute.String("containerID", contEvent.GetContainerID()), attribute.String("container workload", contEvent.GetK8SWorkloadID())))
		err := ch.startTimer(watchedContainer, contEvent.GetContainerID())
		if err != nil {
			if errors.Is(err, containerHasTerminatedError) {
				break
			} else if errors.Is(err, sbomV1.SBOMIncomplete) {
				logger.L().Ctx(ctx).Warning("container monitoring stopped - incomplete SBOM", helpers.String("container ID", contEvent.GetContainerID()), helpers.String("container name", contEvent.GetContainerName()), helpers.String("k8s resources", contEvent.GetK8SWorkloadID()), helpers.Error(err))
				break
			}
		}
		span.End()
	}
	logger.L().Info("stop monitor on container - after monitoring time", helpers.String("container ID", contEvent.GetContainerID()), helpers.String("container name", contEvent.GetContainerName()), helpers.String("k8s resources", contEvent.GetK8SWorkloadID()))
	ch.deleteResources(watchedContainer, contEvent)
}

func createK8sContainerID(namespaceName string, podName string, containerName string) string {
	return fmt.Sprintf("%s/%s/%s", namespaceName, podName, containerName)
}

func (ch *ContainerHandler) getImageID(containerData *watchedContainerData) (string, error) {
	if containerData.imageID != "" {
		return containerData.imageID, nil
	}
	for {
		wl, err := ch.containerWatcher.GetContainerClient().GetWorkload(containerData.event.GetNamespace(), "Pod", containerData.event.GetPodName())
		if err != nil {
			return "", err
		}
		pod := wl.(*workloadinterface.Workload)
		status, err := pod.GetPodStatus()
		if err != nil {
			return "", err
		}
		for i := range status.ContainerStatuses {
			if status.ContainerStatuses[i].Name == containerData.event.GetContainerName() {
				containerData.imageID = status.ContainerStatuses[i].ImageID
			}
		}
		if containerData.imageID != "" {
			logger.L().Debug("found imageID", helpers.String("imageID", containerData.imageID), helpers.String("containerID", containerData.event.GetContainerID()))
			break
		}
		logger.L().Debug("imageID not found yet", helpers.String("containerID", containerData.event.GetContainerID()))
		time.Sleep(1 * time.Second)
	}
	return containerData.imageID, nil
}

func (ch *ContainerHandler) getSBOM(contEvent v1.ContainerEventData) {
	containerDataInterface, exist := ch.watchedContainers.Load(contEvent.GetContainerID())
	if !exist {
		logger.L().Ctx(context.GetBackgroundContext()).Error("getSBOM: failed to get container data of ContainerID, not exist in memory", helpers.String("containerID", contEvent.GetContainerID()))
		return
	}
	watchedContainer := containerDataInterface.(watchedContainerData)
	imageID, err := ch.getImageID(&watchedContainer)
	if err == nil {
		// save watchedContainer with imageID
		ch.watchedContainers.Store(contEvent.GetContainerID(), watchedContainer)
		err = watchedContainer.sbomClient.GetSBOM(contEvent.GetImageTAG(), imageID)
	}
	watchedContainer.syncChannel[StepGetSBOM] <- err
}

func (ch *ContainerHandler) handleContainerRunningEvent(contEvent v1.ContainerEventData) error {
	logger.L().Debug("handleContainerRunningEvent", helpers.Interface("contEvent", contEvent))
	_, exist := ch.watchedContainers.Load(contEvent.GetContainerID())
	if exist {
		return containerAlreadyExistError
	}
	logger.L().Info("new container has loaded - start monitor it", []helpers.IDetails{helpers.String("ContainerID", contEvent.GetContainerID()), helpers.String("Container name", contEvent.GetContainerID()), helpers.String("k8s workload", contEvent.GetK8SWorkloadID())}...)
	newWatchedContainer := watchedContainerData{
		snifferTicker: createTicker(),
		event:         contEvent,
		sbomClient:    sbom.CreateSBOMStorageClient(ch.storageClient, contEvent.GetK8SWorkloadID(), contEvent.GetInstanceID()),
		syncChannel: map[string]chan error{
			StepGetSBOM:         make(chan error, 10),
			StepEventAggregator: make(chan error, 10),
			StepValidateSBOM:    make(chan error, 10),
		},
		k8sContainerID: contEvent.GetK8SContainerID(),
	}
	ch.watchedContainers.Store(contEvent.GetContainerID(), newWatchedContainer)
	go ch.startRelevancyProcess(contEvent)
	return nil
}

func (ch *ContainerHandler) handleContainerTerminatedEvent(contEvent v1.ContainerEventData) error {
	k8sContainerID := contEvent.GetK8SContainerID()
	if watchedContainer, ok := ch.watchedContainers.LoadAndDelete(contEvent.GetContainerID()); ok {
		data, ok := watchedContainer.(watchedContainerData)
		if !ok {
			return fmt.Errorf("failed to stop container ID %s", contEvent.GetContainerID())
		}
		err := ch.fileDB.Update(func(tx *bolt.Tx) error {
			err := tx.DeleteBucket([]byte(k8sContainerID))
			if err != nil {
				return fmt.Errorf("delete bucket: %s", err)
			}
			logger.L().Debug("deleted file bucket", helpers.String("k8sContainerID", k8sContainerID))
			return nil
		})
		if err != nil {
			return err
		}
		data.syncChannel[StepEventAggregator] <- containerHasTerminatedError
	}
	return nil
}

func (ch *ContainerHandler) reportFileAccessInPod(namespace, pod, container, file string) {
	// log accessed files for all containers to avoid race condition
	// this will record unnecessary files for containers that are not monitored
	if file == "" {
		return
	}
	k8sContainerID := createK8sContainerID(namespace, pod, container)
	err := ch.fileDB.Batch(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(k8sContainerID))
		if err != nil {
			return err
		}
		return b.Put([]byte(file), nil)
	})
	if err != nil {
		logger.L().Error("failed to add file to container file list", helpers.Error(err), helpers.Interface("k8sContainerID", k8sContainerID), helpers.String("file", file))
	}
}

func (ch *ContainerHandler) StartMainHandler() error {
	go func() {
		_ = ch.afterTimerActions()
	}()

	callback := func(notif containercollection.PubSubEvent) {
		logger.L().Debug("GetEventCallback", helpers.String("namespaceName", notif.Container.Namespace), helpers.String("podName", notif.Container.Podname), helpers.String("containerName", notif.Container.Name), helpers.String("containerID", notif.Container.ID), helpers.String("type", notif.Type.String()))
		wl, err := ch.containerWatcher.GetContainerClient().GetWorkload(notif.Container.Namespace, "Pod", notif.Container.Podname)
		if err != nil {
			logger.L().Ctx(context.GetBackgroundContext()).Error("failed to get pod", helpers.Error(err), helpers.String("namespace", notif.Container.Namespace), helpers.String("Pod name", notif.Container.Podname))
			return
		}
		workload := wl.(*workloadinterface.Workload)
		containerEventData, err := ch.containerWatcher.ParsePodData(workload, notif.Container)
		if err != nil {
			logger.L().Ctx(context.GetBackgroundContext()).Error("failed to parse pod data", helpers.Error(err), helpers.Interface("workload", workload), helpers.Interface("container", notif.Container))
			return
		}
		switch notif.Type {
		case containercollection.EventTypeAddContainer:
			logger.L().Debug("container has started", helpers.String("namespace", notif.Container.Namespace), helpers.String("Pod name", notif.Container.Podname), helpers.String("ContainerID", notif.Container.ID), helpers.String("Container name", notif.Container.Name))
			err := ch.handleContainerRunningEvent(*containerEventData)
			if err != nil {
				ctx, span := otel.Tracer("").Start(context.GetBackgroundContext(), "mainContainerHandler")
				logger.L().Ctx(ctx).Warning("handle container running event failed", helpers.String("ContainerID", containerEventData.GetContainerID()), helpers.String("Container name", containerEventData.GetContainerID()), helpers.String("k8s workload", containerEventData.GetK8SWorkloadID()), helpers.Error(err))
				span.End()
			}
		case containercollection.EventTypeRemoveContainer:
			logger.L().Debug("container has Terminated", helpers.String("namespace", notif.Container.Namespace), helpers.String("Pod name", notif.Container.Podname), helpers.String("ContainerID", notif.Container.ID), helpers.String("Container name", notif.Container.Name))
			err := ch.handleContainerTerminatedEvent(*containerEventData)
			if err != nil {
				ctx, span := otel.Tracer("").Start(context.GetBackgroundContext(), "mainContainerHandler")
				logger.L().Ctx(ctx).Warning("handle container terminated event failed", helpers.String("ContainerID", containerEventData.GetContainerID()), helpers.String("Container name", containerEventData.GetContainerID()), helpers.String("k8s workload", containerEventData.GetK8SWorkloadID()), helpers.Error(err))
				span.End()
			}
		}
	}
	containerEventFuncs := []containercollection.FuncNotify{callback}

	// Define the different options for the container collection instance
	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithTracerCollection(ch.tracerCollection),

		// Get containers created with runc
		containercollection.WithRuncFanotify(),

		// Get containers created with docker
		containercollection.WithCgroupEnrichment(),

		// Enrich events with Linux namespaces information, it is needed for per container filtering
		containercollection.WithLinuxNamespaceEnrichment(),

		// Enrich those containers with data from the Kubernetes API
		containercollection.WithKubernetesEnrichment(ch.containerWatcher.GetNodeName(), ch.containerWatcher.GetContainerClient().GetK8sConfig()),

		// Get Notifications from the container collection
		containercollection.WithPubSub(containerEventFuncs...),
	}

	// Initialize the container collection
	if err := ch.containerCollection.Initialize(opts...); err != nil {
		return fmt.Errorf("failed to initialize container collection: %s\n", err)
	}

	// Empty selector to get all containers
	containerSelector := containercollection.ContainerSelector{}

	// Define a callback to handle exec events
	execEventCallback := func(event *tracerexectype.Event) {
		if event.Type != types.NORMAL {
			// dropped event
			logger.L().Ctx(context.GetBackgroundContext()).Warning("container monitoring got drop events - we may miss some realtime data", helpers.String("namespace", event.Namespace), helpers.String("pod", event.Pod), helpers.String("container", event.Container), helpers.String("error", event.Message))
			return
		}
		if event.Retval > -1 {
			procImageName := event.Comm
			if len(event.Args) > 0 {
				procImageName = event.Args[0]
			}
			go ch.reportFileAccessInPod(event.Namespace, event.Pod, event.Container, procImageName)
		}
	}
	if err := ch.tracerCollection.AddTracer(execTraceName, containerSelector); err != nil {
		return fmt.Errorf("error adding exec tracer: %s\n", err)
	}

	// Define a callback to handle open events
	openEventCallback := func(event *traceropentype.Event) {
		if event.Type != types.NORMAL {
			// dropped event
			logger.L().Ctx(context.GetBackgroundContext()).Warning("container monitoring got drop events - we may miss some realtime data", helpers.String("namespace", event.Namespace), helpers.String("pod", event.Pod), helpers.String("container", event.Container), helpers.String("error", event.Message))
			return
		}
		if event.Ret > -1 {
			go ch.reportFileAccessInPod(event.Namespace, event.Pod, event.Container, event.Path)
		}
	}
	if err := ch.tracerCollection.AddTracer(openTraceName, containerSelector); err != nil {
		return fmt.Errorf("error adding open tracer: %s\n", err)
	}

	// Get mount namespace map to filter by containers
	execMountnsmap, err := ch.tracerCollection.TracerMountNsMap(execTraceName)
	if err != nil {
		return fmt.Errorf("failed to get execMountnsmap: %s\n", err)
	}

	// Get mount namespace map to filter by containers
	openMountnsmap, err := ch.tracerCollection.TracerMountNsMap(openTraceName)
	if err != nil {
		return fmt.Errorf("failed to get openMountnsmap: %s\n", err)
	}

	// Create the exec tracer
	ch.tracerExec, err = tracerexec.NewTracer(&tracerexec.Config{MountnsMap: execMountnsmap}, ch.containerCollection, execEventCallback)
	if err != nil {
		return fmt.Errorf("error creating tracerExec: %s\n", err)
	}

	// Create the exec tracer
	ch.tracerOpen, err = traceropen.NewTracer(&traceropen.Config{MountnsMap: openMountnsmap}, ch.containerCollection, openEventCallback)
	if err != nil {
		return fmt.Errorf("error creating tracerOpen: %s\n", err)
	}

	logger.L().Info("main container handler started")

	return nil
}

func (ch *ContainerHandler) printNsMap(id string) {
	nsMap, _ := ch.tracerCollection.TracerMountNsMap(id)
	var (
		key     string
		value   uint32
		entries = nsMap.Iterate()
	)
	for entries.Next(&key, &value) { // Order of keys is non-deterministic due to randomized map seed
		logger.L().Debug("map entry", helpers.String("key", key), helpers.Int("value", int(value)))
	}
}

func (ch *ContainerHandler) StopMainHandler() {
	ch.containerCollection.Close()
	ch.tracerExec.Stop()
	_ = ch.tracerCollection.RemoveTracer(execTraceName)
	ch.tracerOpen.Stop()
	_ = ch.tracerCollection.RemoveTracer(openTraceName)
	ch.tracerCollection.Close()
	_ = ch.fileDB.Close()
}
