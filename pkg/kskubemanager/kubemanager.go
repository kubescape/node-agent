// This is copied from inspektor gadget's pkg/operators/kubemanager/kubemanager.go
// and adapted to use the container-collection and tracer-collection instances
// provided by our container-watcher

package kskubemanager

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/google/uuid"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/compat"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/spf13/viper"
)

const (
	OperatorName = "KsKubeManager"

	// Global parameter keys
	ParamHookMode               = "hook-mode"
	ParamFallbackPodInformer    = "fallback-podinformer"
	ParamHookLivenessSocketFile = "hook-liveness-socketfile"

	// Instance parameter keys
	ParamAllNamespaces = "all-namespaces"
)

const (
	// Hook modes
	hookModeAuto         = "auto"
	hookModeCrio         = "crio"
	hookModeNRI          = "nri"
	hookModePodInformer  = "podinformer"
	hookModeFanotifyEbpf = "fanotify+ebpf"
)

var supportedHookModes = []string{
	hookModeAuto,
	hookModeCrio,
	hookModeNRI,
	hookModePodInformer,
	hookModeFanotifyEbpf,
}

type KubeManager struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
}

var _ operators.DataOperator = (*KubeManager)(nil)

func NewKsKubeManager(containerCollection *containercollection.ContainerCollection, tracerCollection *tracercollection.TracerCollection) *KubeManager {
	return &KubeManager{
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
	}
}

func (k *KubeManager) Name() string {
	return OperatorName
}

func (k *KubeManager) Description() string {
	return "KubeManager handles container/pod/namespace information using Container-Collection and Tracer-Collection."
}

func (k *KubeManager) GlobalParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:          ParamFallbackPodInformer,
			DefaultValue: "true",
			Description:  "Use pod informer as a fallback for the main hook",
			TypeHint:     params.TypeBool,
		},
		{
			Key:            ParamHookMode,
			DefaultValue:   hookModeAuto,
			Description:    "Mechanism to collect container information",
			TypeHint:       params.TypeString,
			PossibleValues: supportedHookModes,
		},
		{
			Key:          ParamHookLivenessSocketFile,
			DefaultValue: types.DefaultHookAndLivenessSocketFile,
			Description:  "Path to the socket file for serving hook's requests for adding/removing containers and for liveness checks",
			TypeHint:     params.TypeString,
		},
	}
}

func (k *KubeManager) ParamDescs() params.ParamDescs {
	return append(common.GetContainerSelectorParams(true),
		&params.ParamDesc{
			Key:          ParamAllNamespaces,
			Alias:        "A",
			Description:  "Show data from pods in all namespaces",
			TypeHint:     params.TypeBool,
			DefaultValue: "false",
		})
}

func (k *KubeManager) Init(params *params.Params) error {
	// initialization is done in the containerwatcher package, we use existing containerCollection and tracerCollection
	return nil
}

func (k *KubeManager) Close() error {
	return nil
}

type KubeManagerInstance struct {
	id           string
	manager      *KubeManager
	enrichEvents bool
	mountnsmap   *ebpf.Map
	subscribed   bool

	attachedContainers map[string]*containercollection.Container
	attacher           kubemanager.Attacher
	params             *params.Params
	gadgetInstance     any
	gadgetCtx          operators.GadgetContext

	eventWrappers map[datasource.DataSource]*compat.EventWrapperBase

	containersPublisher *common.ContainersPublisher
}

func (m *KubeManagerInstance) Name() string {
	return OperatorName
}

func (m *KubeManagerInstance) PreGadgetRun() error {
	log := logger.L()

	if m.gadgetInstance != nil {
		err := m.handleGadgetInstance(log)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *KubeManagerInstance) handleGadgetInstance(log helpers.ILogger) error {
	containerSelector := newContainerSelector(m.params)

	if setter, ok := m.gadgetInstance.(kubemanager.MountNsMapSetter); ok {
		err := m.manager.tracerCollection.AddTracer(m.id, containerSelector)
		if err != nil {
			return fmt.Errorf("adding tracer: %w", err)
		}

		// Create mount namespace map to filter by containers
		mountnsmap, err := m.manager.tracerCollection.TracerMountNsMap(m.id)
		if err != nil {
			m.manager.tracerCollection.RemoveTracer(m.id)
			return fmt.Errorf("creating mountns map: %w", err)
		}

		// DEBUG: verify mountnsmap presence and FD (if available)
		if mountnsmap == nil {
			log.Warning("TracerMountNsMap returned nil mountnsmap")
		} else {
			fd := -1
			// Use a typed assertion to avoid depending on a particular ebpf Map API.
			if im, ok := interface{}(mountnsmap).(interface{ FD() int }); ok {
				fd = im.FD()
			}
			log.Debug("set mountnsmap for gadget", helpers.Int("fd", fd), helpers.Interface("map", mountnsmap))
		}
		setter.SetMountNsMap(mountnsmap)

		m.mountnsmap = mountnsmap
	}

	if attacher, ok := m.gadgetInstance.(kubemanager.Attacher); ok {
		m.attacher = attacher
		m.attachedContainers = make(map[string]*containercollection.Container)

		attachContainerFunc := func(container *containercollection.Container) {
			// DEBUG: check mountnsmap at attach time
			if m.mountnsmap == nil {
				log.Warning("mountnsmap is nil at attach time", helpers.String("container", container.K8s.ContainerName), helpers.String("containerID", container.Runtime.ContainerID))
			} else {
				fd := -1
				if im, ok := interface{}(m.mountnsmap).(interface{ FD() int }); ok {
					fd = im.FD()
				}
				log.Debug("mountnsmap at attach time", helpers.Int("fd", fd), helpers.Interface("map", m.mountnsmap), helpers.String("container", container.K8s.ContainerName))
			}

			log.Debug("calling gadget.AttachContainer()")
			err := attacher.AttachContainer(container)
			if err != nil {
				var ve *ebpf.VerifierError
				if errors.As(err, &ve) {
					log.Debug("start tracing container, verifier error", helpers.String("container", container.K8s.ContainerName), helpers.Error(ve))
				}

				log.Warning("start tracing container", helpers.String("container", container.K8s.ContainerName), helpers.Error(err))
				return
			}

			m.attachedContainers[container.Runtime.ContainerID] = container

			log.Debug("tracer attached",
				helpers.String("container", container.K8s.ContainerName), helpers.Int("pid", int(container.ContainerPid())), helpers.Int("mntns", int(container.Mntns)), helpers.Int("netns", int(container.Netns)))
		}

		detachContainerFunc := func(container *containercollection.Container) {
			log.Debug("calling gadget.Detach()")
			delete(m.attachedContainers, container.Runtime.ContainerID)

			err := attacher.DetachContainer(container)
			if err != nil {
				log.Warning("stop tracing container", helpers.String("container", container.K8s.ContainerName), helpers.Error(err))
				return
			}
			log.Debug("tracer detached",
				helpers.String("container", container.K8s.ContainerName), helpers.Int("pid", int(container.ContainerPid())), helpers.Int("mntns", int(container.Mntns)), helpers.Int("netns", int(container.Netns)))
		}

		m.subscribed = true

		log.Debug("add subscription to containerCollection")
		containers := m.manager.containerCollection.Subscribe(
			m.id,
			containerSelector,
			func(event containercollection.PubSubEvent) {
				log.Debug("event", helpers.String("type", event.Type.String()), helpers.String("containerID", event.Container.Runtime.ContainerID))
				switch event.Type {
				case containercollection.EventTypeAddContainer:
					attachContainerFunc(event.Container)
				case containercollection.EventTypeRemoveContainer:
					detachContainerFunc(event.Container)
				case containercollection.EventTypePreCreateContainer:
					// nothing to do
				default:
					log.Error("unknown event type",
						helpers.Interface("expected1", containercollection.EventTypePreCreateContainer),
						helpers.Interface("expected2", containercollection.EventTypeAddContainer),
						helpers.Interface("expected3", containercollection.EventTypeRemoveContainer),
						helpers.Interface("got", event.Type))
				}
			},
		)

		for _, container := range containers {
			attachContainerFunc(container)
		}
	}
	return nil
}

func newContainerSelector(params *params.Params) containercollection.ContainerSelector {
	containerSelector := common.NewContainerSelector(params)
	if params.Get(ParamAllNamespaces).AsBool() {
		containerSelector.K8s.Namespace = ""
	}
	return containerSelector
}

func (m *KubeManagerInstance) PostGadgetRun() error {
	if m.mountnsmap != nil {
		logger.L().Debug("calling RemoveTracer()")
		m.manager.tracerCollection.RemoveTracer(m.id)
	}

	if m.subscribed {
		logger.L().Debug("calling Unsubscribe()")
		m.manager.containerCollection.Unsubscribe(m.id)

		// emit detach for all remaining containers
		for _, container := range m.attachedContainers {
			m.attacher.DetachContainer(container)
		}
	}

	return nil
}

func (k *KubeManager) GlobalParams() api.Params {
	return apihelpers.ParamDescsToParams(k.GlobalParamDescs())
}

func (k *KubeManager) InstanceParams() api.Params {
	return apihelpers.ParamDescsToParams(k.ParamDescs())
}

func (k *KubeManager) InstantiateDataOperator(gadgetCtx operators.GadgetContext, paramValues api.ParamValues) (
	operators.DataOperatorInstance, error,
) {
	params := k.ParamDescs().ToParams()
	err := params.CopyFromMap(paramValues, "")
	if err != nil {
		return nil, err
	}

	cfg, ok := gadgetCtx.GetVar("config")
	if !ok {
		return nil, fmt.Errorf("missing configuration")
	}
	v, ok := cfg.(*viper.Viper)
	if !ok {
		return nil, fmt.Errorf("invalid configuration format")
	}

	enableContainersDs := v.GetBool("annotations.enable-containers-datasource")

	var containersPublisher *common.ContainersPublisher
	if enableContainersDs {
		containersPublisher, err = common.NewContainersPublisher(gadgetCtx, k.containerCollection)
		if err != nil {
			return nil, fmt.Errorf("creating containers publisher: %w", err)
		}
	}

	traceInstance := &KubeManagerInstance{
		manager:            k,
		enrichEvents:       false,
		attachedContainers: make(map[string]*containercollection.Container),
		params:             params,
		gadgetCtx:          gadgetCtx,
		id:                 uuid.New().String(),

		eventWrappers: make(map[datasource.DataSource]*compat.EventWrapperBase),

		containersPublisher: containersPublisher,
	}

	activate := false

	// Check, whether the gadget requested a map from us
	if t, ok := gadgetCtx.GetVar(gadgets.MntNsFilterMapName); ok {
		if _, ok := t.(*ebpf.Map); ok {
			logger.L().Debug("gadget requested map", helpers.String("map", gadgets.MntNsFilterMapName))
			activate = true
		}
	}

	// Check for NeedContainerEvents; this is set for example for tchandlers, as they
	// require the Attacher interface to be aware of containers
	if val, ok := gadgetCtx.GetVar("NeedContainerEvents"); ok {
		if b, ok := val.(bool); ok && b {
			activate = true
		}
	}

	wrappers, err := compat.GetEventWrappers(gadgetCtx)
	if err != nil {
		return nil, fmt.Errorf("getting event wrappers: %w", err)
	}
	traceInstance.eventWrappers = wrappers
	if len(wrappers) > 0 {
		activate = true
	}

	if !activate {
		return nil, nil
	}

	return traceInstance, nil
}

func (k *KubeManager) Priority() int {
	return -1
}

func (m *KubeManagerInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	m.gadgetInstance, _ = gadgetCtx.GetVar("ebpfInstance")

	compat.Subscribe(
		m.eventWrappers,
		m.manager.containerCollection.EnrichEventByMntNs,
		m.manager.containerCollection.EnrichEventByNetNs,
		0,
	)

	containerSelector := newContainerSelector(m.params)

	if m.manager.containerCollection == nil {
		return fmt.Errorf("container-collection isn't available")
	}

	// Create mount namespace map to filter by containers
	err := m.manager.tracerCollection.AddTracer(m.id, containerSelector)
	if err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	mountnsmap, err := m.manager.tracerCollection.TracerMountNsMap(m.id)
	if err != nil {
		m.manager.tracerCollection.RemoveTracer(m.id)
		return fmt.Errorf("creating mountnsmap: %w", err)
	}

	logger.L().Debug("set mountnsmap for gadget")
	gadgetCtx.SetVar(gadgets.MntNsFilterMapName, mountnsmap)
	gadgetCtx.SetVar(gadgets.FilterByMntNsName, true)

	m.mountnsmap = mountnsmap
	// using PreGadgetRun() for the time being to register attacher funcs
	return m.PreGadgetRun()
}

func (m *KubeManagerInstance) Start(gadgetCtx operators.GadgetContext) error {
	if m.containersPublisher == nil {
		return nil
	}

	containerSelector := newContainerSelector(m.params)

	return m.containersPublisher.PublishContainers(true, []*containercollection.Container{}, containerSelector)
}

func (m *KubeManagerInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (m *KubeManagerInstance) Close(gadgetCtx operators.GadgetContext) error {
	m.manager.tracerCollection.RemoveTracer(m.id)

	if m.containersPublisher != nil {
		m.containersPublisher.Unsubscribe()
	}

	return nil
}
