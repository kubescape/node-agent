package integration

import (
	"context"
	"fmt"
	stdmaps "maps"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/node-agent/pkg/watcher"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	orasoci "oras.land/oras-go/v2/content/oci"
)

// ServiceOptions deliberately has no inferred host/runtime-helper exemptions.
// Callers must explicitly enable this service and ship the matching mutator image.
type ServiceOptions struct {
	Kubernetes                                        kubernetes.Interface
	Dynamic                                           dynamic.Interface
	Containers                                        *containercollection.ContainerCollection
	Tracers                                           *tracercollection.TracerCollection
	NodeName, AgentNamespace, ImageName, ImageArchive string
	ContainerdSocket, ControlRoot                     string
	MaxOwners                                         uint64
	Sources                                           sandboxpolicy.SourceResolver
	Receivers                                         *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]
	Enricher                                          containerwatcher.TaskBasedEnricher
	OnError                                           func(error)
	// PrivilegeImageName enables the privilege section. Empty rejects it.
	PrivilegeImageName string
	// NetworkImageName enables the network section. Empty rejects it.
	NetworkImageName string
	// FileImageName enables the file section. Empty rejects it.
	FileImageName string
}

// slotSections reports whether a section with node-wide slots is enabled.
func (o ServiceOptions) slotSections() bool {
	return o.PrivilegeImageName != "" || o.NetworkImageName != "" || o.FileImageName != ""
}

type serviceBackend interface {
	sandboxpolicy.Backend
	Close(context.Context) error
}

type Service struct {
	Controller    *sandboxpolicy.Controller
	backend       serviceBackend
	exporter      *sandboxpolicy.VerdictExporter
	closeRuntime  func() error
	options       ServiceOptions
	mu            sync.RWMutex
	bindings      map[string]sandboxpolicy.Binding
	snapshot      func(context.Context) ([]sandboxpolicy.Binding, error)
	cancel        context.CancelFunc
	done          chan struct{}
	closeMu       sync.Mutex
	backendClosed bool
	runtimeClosed bool
	subscribed    bool
	closed        bool
	wake          chan struct{}
	inputEpoch    atomic.Uint64
	snapshotEpoch atomic.Uint64
	// podsScheduled is set by a Pending-pod or policy event; lastPrepare
	// bounds how often privilege slot preparation lists the node's pods.
	podsScheduled atomic.Bool
	lastPrepare   time.Time
	// hadSlotPolicies: the last refresh saw a privilege or network policy.
	hadSlotPolicies bool
	// lastClusterCIDRs bounds how often the clusterInternal class is read;
	// clusterCIDRs keeps the last good value of each part.
	lastClusterCIDRs time.Time
	clusterCIDRs     ClusterCIDRReader
	// The fields below are used only by the refresh loop.
	// scheduled and qos are the containers and QoS classes of the node's pods
	// from the last slot preparation, used when there are no informers.
	scheduled []sandboxpolicy.Binding
	qos       map[types.UID]corev1.PodQOSClass
	// podFirstSeen is when a pod with a pod plan was first seen. podPolling is
	// set while such a pod has no pod cgroup yet, for up to prepareInterval.
	podFirstSeen map[types.UID]time.Time
	podPolling   bool
	// podPods, podQoS and podPlans are the inputs of the last bindPods,
	// reused by the poll. podPollErr is the last error the poll reported.
	podPods    []sandboxpolicy.Binding
	podQoS     map[types.UID]corev1.PodQOSClass
	podPlans   map[types.UID]sandboxpolicy.Plan
	podPollErr string
	// podCgroupID returns the cgroup ID of a pod cgroup path (replaced in tests).
	podCgroupID func(string) (uint64, error)
	// pods and namespaces are the informers of the node's pods and of all
	// namespaces (nil without a privilege or network image).
	pods, namespaces informers.SharedInformerFactory
}

// prepareInterval is the longest time between two slot preparations.
const prepareInterval = 30 * time.Second

// clusterCIDRsInterval is the time between two reads of the cluster CIDRs.
const clusterCIDRsInterval = time.Minute

// podPollInterval is how often a scheduled pod is checked for its pod cgroup,
// for up to prepareInterval after it is scheduled. The kubelet creates the pod
// cgroup before the pod sandbox, so the pod cgroup is bound before the first
// container starts.
const podPollInterval = 50 * time.Millisecond

// NewService prepares the public watcher/exporter/native runtime bridge. It does
// not authorize any cgroup or start enforcement until Start is called.
func NewService(ctx context.Context, options ServiceOptions) (*Service, error) {
	if options.Kubernetes == nil || options.Dynamic == nil || options.Containers == nil || options.Tracers == nil || options.NodeName == "" || options.AgentNamespace == "" || options.ImageName == "" || options.ImageArchive == "" || options.ContainerdSocket == "" || options.ControlRoot == "" || options.MaxOwners == 0 || options.MaxOwners > igbackend.FullBackendMaxBindings {
		return nil, fmt.Errorf("sandbox service requires clients, discovery, node identity and explicit image/archive")
	}
	node, err := options.Kubernetes.CoreV1().Nodes().Get(ctx, options.NodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("sandbox node identity: %w", err)
	}
	store, err := orasoci.NewFromTar(ctx, options.ImageArchive)
	if err != nil {
		return nil, fmt.Errorf("sandbox image archive: %w", err)
	}
	r := local.New()
	if err = r.Init(nil); err != nil {
		return nil, fmt.Errorf("sandbox native runtime: %w", err)
	}
	s := &Service{options: options, bindings: map[string]sandboxpolicy.Binding{}, closeRuntime: r.Close, done: make(chan struct{}), wake: make(chan struct{}, 1)}
	cgroupRoot := filepath.Join(host.HostRoot, "sys/fs/cgroup")
	s.podCgroupID = func(path string) (uint64, error) { return cgroupID(cgroupRoot, path) }
	if options.slotSections() {
		s.pods = informers.NewSharedInformerFactoryWithOptions(options.Kubernetes, 0, informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			o.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", options.NodeName).String()
		}))
		s.namespaces = informers.NewSharedInformerFactory(options.Kubernetes, 0)
		s.watchPods()
	}
	s.exporter, err = sandboxpolicy.NewVerdictExporter(sandboxpolicy.ExporterOptions{Capacity: 1024, Receivers: options.Receivers, Enricher: options.Enricher, ResolveBinding: s.resolveBinding})
	if err != nil {
		_ = r.Close()
		return nil, err
	}
	budget, err := fullruntime.NewBudget(fullruntime.BudgetLimits{Owners: options.MaxOwners, MapPayloadBytes: options.MaxOwners * fullruntime.OwnerMapPayloadLimit, ProgramInstructions: options.MaxOwners * fullruntime.OwnerInstructionLimit, HistoryEntries: options.MaxOwners * fullruntime.OwnerHistoryLimit})
	if err != nil {
		_ = r.Close()
		return nil, err
	}
	source, err := igbackend.NewContainerdFullSource(options.ContainerdSocket, host.HostRoot, host.HostProcFs, filepath.Join(host.HostRoot, "sys/fs/cgroup"), igbackend.ImageIndexLimits{})
	if err != nil {
		_ = r.Close()
		return nil, err
	}
	// Source refuses Close while any acquired lease remains. It is released only
	// after backend cleanup confirms native links and borrowed map FDs are gone.
	s.closeRuntime = func() error {
		if err := source.Close(); err != nil {
			return err
		}
		return r.Close()
	}
	engine, err := igbackend.NewNativeFullEngine(r, kubemanager.NewKubeManager(options.Containers, options.Tracers), store, options.ImageName, options.ControlRoot, budget, s.report)
	if err != nil {
		_ = s.closeRuntime()
		return nil, err
	}
	full, err := igbackend.NewFull(engine, source, s.exporter, s.report)
	if err != nil {
		_ = s.closeRuntime()
		return nil, err
	}
	var privilege sandboxpolicy.Backend
	var privilegeUnavailable error
	if options.PrivilegeImageName != "" {
		privilegeUnavailable = igbackend.CheckBPFLSM(host.HostRoot)
	}
	if options.PrivilegeImageName != "" && privilegeUnavailable == nil {
		privilegeEngine, err := igbackend.NewNativePrivilegeEngine(r, kubemanager.NewKubeManager(options.Containers, options.Tracers), store, options.PrivilegeImageName)
		if err == nil {
			privilege, err = igbackend.NewPrivilege(privilegeEngine, igbackend.LinuxValidator{ProcRoot: host.HostProcFs, CgroupRoot: filepath.Join(host.HostRoot, "sys/fs/cgroup")}, options.NodeName)
		}
		if err != nil {
			_ = full.Close(ctx)
			_ = s.closeRuntime()
			return nil, err
		}
	}
	var network sandboxpolicy.Backend
	var networkUnavailable error
	if options.NetworkImageName != "" {
		// The cgroup tier needs IG support for cgroup sock_addr attach; until
		// then no probe is passed and the LSM tier is used.
		var tier igbackend.NetworkTier
		tier, networkUnavailable = igbackend.SelectNetworkTier(host.HostRoot, nil)
		if networkUnavailable == nil {
			networkEngine, err := igbackend.NewNativeNetworkEngine(r, kubemanager.NewKubeManager(options.Containers, options.Tracers), store, options.NetworkImageName, tier)
			if err == nil {
				network, err = igbackend.NewNetwork(networkEngine, igbackend.LinuxValidator{ProcRoot: host.HostProcFs, CgroupRoot: filepath.Join(host.HostRoot, "sys/fs/cgroup")}, options.NodeName)
			}
			if err != nil {
				_ = full.Close(ctx)
				if privilege != nil {
					_ = privilege.(serviceBackend).Close(ctx)
				}
				_ = s.closeRuntime()
				return nil, err
			}
		}
	}
	var file sandboxpolicy.Backend
	var fileUnavailable error
	var fileNode sandboxpolicy.FileNode
	if options.FileImageName != "" {
		fileUnavailable = igbackend.CheckFile(host.HostRoot)
		fileNode = igbackend.FileNode()
	}
	if options.FileImageName != "" && fileUnavailable == nil {
		fileEngine, err := igbackend.NewNativeFileEngine(r, kubemanager.NewKubeManager(options.Containers, options.Tracers), store, options.FileImageName)
		if err == nil {
			file, err = igbackend.NewFile(fileEngine, igbackend.LinuxValidator{ProcRoot: host.HostProcFs, CgroupRoot: filepath.Join(host.HostRoot, "sys/fs/cgroup")}, options.NodeName)
		}
		if err != nil {
			_ = full.Close(ctx)
			for _, b := range []sandboxpolicy.Backend{privilege, network} {
				if b != nil {
					_ = b.(serviceBackend).Close(ctx)
				}
			}
			_ = s.closeRuntime()
			return nil, err
		}
	}
	sections, err := sandboxpolicy.NewSectionBackend(full, privilege, privilegeUnavailable)
	if err != nil {
		_ = full.Close(ctx)
		_ = s.closeRuntime()
		return nil, err
	}
	s.backend = sections.WithNetwork(network, networkUnavailable).WithFile(file, fileUnavailable)
	s.Controller, err = sandboxpolicy.NewController(options.Dynamic, s.backend, options.Sources, readinessWriter{inner: &sandboxpolicy.DynamicStatusWriter{Client: options.Dynamic}, observed: &s.inputEpoch, snapshot: &s.snapshotEpoch}, sandboxpolicy.Options{Node: api.NodeReference{Name: node.Name, UID: node.UID}, AgentNamespace: options.AgentNamespace, File: fileNode})
	if err != nil {
		_ = s.backend.Close(ctx)
		_ = s.closeRuntime()
		return nil, err
	}
	s.Controller.SetClusterCIDRsReader(s.readClusterCIDRs)
	return s, nil
}

// Watch events are hints only. Generic watcher queues may deliver old updates
// after a relist/deletion; applying their payload could resurrect removed policy.
// Refresh always reads authoritative configuration and cannot revive queued UIDs.
func (s *Service) WatchResources() []watcher.WatchResource {
	return s.Controller.WatchResources()
}
func (s *Service) AddHandler(_ context.Context, obj runtime.Object)    { s.configurationHint(obj) }
func (s *Service) ModifyHandler(_ context.Context, obj runtime.Object) { s.configurationHint(obj) }
func (s *Service) DeleteHandler(_ context.Context, obj runtime.Object) { s.configurationHint(obj) }
func (s *Service) configurationHint(obj runtime.Object) {
	if obj == nil {
		return
	}
	switch obj.GetObjectKind().GroupVersionKind().Kind {
	case "SandboxPolicy", "ClusterSandboxPolicy", "SandboxPolicyClasses":
		// A policy change can need a new slot for the pod bindings.
		s.podsScheduled.Store(true)
		s.ContainerCallback(containercollection.PubSubEvent{})
	}
}

// watchPods wakes the refresh loop on changes of the node's pods. A Pending pod
// also asks for a slot preparation. A label or ephemeral container change can
// change the pod plan, so the pod bindings are computed again. It is a
// dedicated informer: the generic watcher delivers an event only after the
// object has had no update for 5 s, which is later than the start of the
// pod's containers.
func (s *Service) watchPods() {
	hint := func(old, obj any) {
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			s.ContainerCallback(containercollection.PubSubEvent{}) // deleted
			return
		}
		if pod.Status.Phase == corev1.PodPending {
			s.podsScheduled.Store(true)
			s.ContainerCallback(containercollection.PubSubEvent{})
			return
		}
		if before, ok := old.(*corev1.Pod); !ok || !stdmaps.Equal(before.Labels, pod.Labels) || len(before.Spec.EphemeralContainers) != len(pod.Spec.EphemeralContainers) {
			s.ContainerCallback(containercollection.PubSubEvent{})
		}
	}
	_, _ = s.namespaces.Core().V1().Namespaces().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		// A pod can arrive before its new namespace: it was dropped, so
		// prepare again.
		AddFunc: func(any) {
			s.podsScheduled.Store(true)
			s.ContainerCallback(containercollection.PubSubEvent{})
		},
		UpdateFunc: func(old, obj any) {
			before, ok1 := old.(*corev1.Namespace)
			after, ok2 := obj.(*corev1.Namespace)
			if !ok1 || !ok2 || !stdmaps.Equal(before.Labels, after.Labels) {
				s.ContainerCallback(containercollection.PubSubEvent{})
			}
		},
	})
	_, _ = s.pods.Core().V1().Pods().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { hint(nil, obj) },
		UpdateFunc: hint,
		DeleteFunc: func(any) { hint(nil, nil) },
	})
}

// Start is called after container discovery is running and before the generic
// dynamic watcher starts. Relisting repairs watch disconnections and re-resolves
// source profiles/selector labels. Failed snapshots never become an empty list.
func (s *Service) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.cancel != nil || s.closed {
		s.mu.Unlock()
		return fmt.Errorf("sandbox service already started")
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	if s.options.Containers != nil {
		s.options.Containers.Subscribe(s, containercollection.ContainerSelector{}, s.ContainerCallback)
		s.subscribed = true
	}
	s.mu.Unlock()
	go s.exporter.Run(runCtx)
	if s.pods != nil {
		s.pods.Start(runCtx.Done())
		s.namespaces.Start(runCtx.Done())
		// Bounded: the caches only add hints, refresh works without them.
		syncCtx, cancelSync := context.WithTimeout(runCtx, 10*time.Second)
		s.pods.WaitForCacheSync(syncCtx.Done())
		s.namespaces.WaitForCacheSync(syncCtx.Done())
		cancelSync()
	}
	// Drain observed startup churn into the readiness barrier before handing
	// work to the background loop. Persistent churn stays explicitly NotReady.
drain:
	for attempt := 0; attempt < 4; attempt++ {
		s.refresh(runCtx)
		select {
		case <-s.wake:
			if attempt == 3 {
				select {
				case s.wake <- struct{}{}:
				default:
				}
			}
			continue
		default:
			break drain
		}
	}
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			var poll <-chan time.Time
			if s.podPolling {
				poll = time.After(podPollInterval)
			}
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				s.refresh(runCtx)
			case <-s.wake:
				s.refresh(runCtx)
			case <-poll:
				s.pollPods(runCtx)
			}
		}
	}()
	return nil
}
func (s *Service) refresh(ctx context.Context) {
	s.snapshotEpoch.Store(s.inputEpoch.Load())
	// Prepare after a Pending-pod or policy event, else at most every
	// prepareInterval.
	hasSlotPolicies := s.Controller.HasSlotPolicies()
	if s.options.slotSections() && s.options.Kubernetes != nil && !hasSlotPolicies && s.hadSlotPolicies {
		// The last slot policy is gone: one preparation with no active
		// section clears the prepared sets (it never starts a gadget).
		if err := s.Controller.PrepareScheduled(ctx, nil); err != nil {
			s.report(fmt.Errorf("slot preparation: %w", err))
		}
	}
	s.hadSlotPolicies = hasSlotPolicies
	if s.options.slotSections() && s.options.Kubernetes != nil && hasSlotPolicies &&
		(s.podsScheduled.Swap(false) || time.Since(s.lastPrepare) >= prepareInterval) {
		s.lastPrepare = time.Now()
		scheduled, qos, err := s.scheduledPods(ctx)
		if err == nil {
			s.scheduled, s.qos = scheduled, qos
			err = s.Controller.PrepareScheduled(ctx, scheduled)
		}
		if err != nil {
			s.report(fmt.Errorf("slot preparation: %w", err))
		}
	}
	// Every refresh, so a policy change also reaches the pod bindings: before
	// the container bindings change, and after, when they created a slot.
	s.bindPods(ctx)
	defer s.bindPods(ctx)
	// Configuration and selected-runtime discovery share one commit barrier. A
	// candidate cannot report Ready between its relist and a failed binding list.
	err := s.Controller.Refresh(ctx, func(ctx context.Context, selected func(sandboxpolicy.Binding) bool) ([]sandboxpolicy.Binding, error) {
		var bindings []sandboxpolicy.Binding
		var err error
		if s.snapshot != nil {
			bindings, err = s.snapshot(ctx)
		} else {
			bindings, err = SnapshotSelectedBindings(ctx, s.options.Kubernetes, s.options.Containers, s.options.NodeName, selected)
		}
		if err != nil {
			return nil, fmt.Errorf("sandbox binding snapshot retained: %w", err)
		}
		// Publish exact correlation before native startup can emit its first verdict.
		// This cache is metadata, not an enforcement readiness or commit declaration.
		s.mu.Lock()
		next := make(map[string]sandboxpolicy.Binding, len(bindings))
		for _, b := range bindings {
			b.PodLabels = copyLabels(b.PodLabels)
			b.NamespaceLabels = copyLabels(b.NamespaceLabels)
			next[b.ContainerID] = b
		}
		s.bindings = next
		s.mu.Unlock()
		return bindings, nil
	})
	if err != nil {
		s.report(err)
	}
}

// readClusterCIDRs reads the clusterInternal sources at most every
// clusterCIDRsInterval. Refresh calls it only while an active policy names the
// class, after it loads the configuration and before it compiles, so the
// first compile of a new policy already has the class.
func (s *Service) readClusterCIDRs(ctx context.Context) (sandboxpolicy.ClusterCIDRs, bool) {
	if s.options.NetworkImageName == "" || s.options.Kubernetes == nil || time.Since(s.lastClusterCIDRs) < clusterCIDRsInterval {
		return sandboxpolicy.ClusterCIDRs{}, false
	}
	s.lastClusterCIDRs = time.Now()
	cidrs, err := s.clusterCIDRs.Read(ctx, s.options.Kubernetes)
	if err != nil {
		logger.L().Warning("sandbox clusterInternal class: read failed", helpers.Error(err))
	}
	return cidrs, true
}

// bindPods binds the pod cgroup of every scheduled pod that has a pod plan
// (see Controller.PodPlans) and unbinds the others. It reads the node's pods
// from the informer cache and makes no API call. A pod whose cgroup does not
// exist yet sets podPolling, so it is checked again soon, for up to
// prepareInterval after it was first seen.
func (s *Service) bindPods(ctx context.Context) {
	if _, ok := s.backend.(sandboxpolicy.PodBinder); !ok || s.Controller == nil {
		return
	}
	// Only the privilege section binds pod cgroups (a network-only node does
	// no pod work here).
	if sections, isSections := s.backend.(*sandboxpolicy.SectionBackend); isSections && sections.SectionUnavailable(sandboxpolicy.SectionPrivilege) != nil {
		return
	}
	s.podPolling = false // set again below when a pod cgroup is missing
	scheduled, qos := s.scheduled, s.qos
	if s.pods != nil {
		var err error
		if scheduled, qos, err = s.scheduledPods(ctx); err != nil {
			s.report(fmt.Errorf("privilege pod binding: %w", err))
			return
		}
	}
	plans, ok := s.Controller.PodPlans(scheduled)
	if !ok {
		s.podPlans = nil
		return // the policies are not known: keep the pod bindings
	}
	s.podPods, s.podQoS, s.podPlans = scheduled, qos, plans
	s.podPollErr = ""
	s.bindPodPlans(ctx, scheduled, qos, plans, false)
}

// pollPods checks again for the pod cgroups that were missing. It reuses the
// pods and plans of the last bindPods, so the 50 ms poll does not list pods
// and compile policies.
func (s *Service) pollPods(ctx context.Context) {
	s.podPolling = false
	if s.podPlans == nil {
		return
	}
	s.bindPodPlans(ctx, s.podPods, s.podQoS, s.podPlans, true)
}

func (s *Service) bindPodPlans(ctx context.Context, scheduled []sandboxpolicy.Binding, qos map[types.UID]corev1.PodQOSClass, known map[types.UID]sandboxpolicy.Plan, poll bool) {
	binder := s.backend.(sandboxpolicy.PodBinder)
	plans := make(map[types.UID]sandboxpolicy.Plan, len(known))
	for k, v := range known {
		plans[k] = v
	}
	var pods []sandboxpolicy.PodBinding
	now := time.Now()
	firstSeen := map[types.UID]time.Time{}
	polling := false
	if len(plans) > 0 {
		layout, known, containerCgroups := s.podCgroupLayout()
		for _, c := range scheduled {
			plan, ok := plans[c.PodUID]
			if !ok {
				continue
			}
			delete(plans, c.PodUID)
			seen, ok := s.podFirstSeen[c.PodUID]
			if !ok {
				seen = now
			}
			firstSeen[c.PodUID] = seen
			path := layout.path(c.PodUID, qos[c.PodUID])
			if !known || path == "" || s.podCgroupID == nil {
				continue
			}
			id, err := s.podCgroupID(path)
			if err != nil || id == 0 {
				polling = polling || now.Sub(seen) < prepareInterval
				continue
			}
			// A runtime that runs the container in the pod cgroup itself:
			// the container binding owns it.
			if containerCgroups[id] {
				continue
			}
			pods = append(pods, sandboxpolicy.PodBinding{PodUID: c.PodUID, Namespace: c.Namespace, PodName: c.PodName, CgroupID: id, CgroupPath: path, Plan: plan})
		}
	}
	s.podFirstSeen, s.podPolling = firstSeen, polling
	if err := binder.BindPods(ctx, pods); err != nil {
		// The poll runs every 50 ms: report a repeated error once.
		if !poll || err.Error() != s.podPollErr {
			s.report(fmt.Errorf("privilege pod binding: %w", err))
		}
		if poll {
			s.podPollErr = err.Error()
		}
	}
}

// scheduledPods returns the containers and QoS classes of the node's pods (see
// ScheduledContainers), from the informer caches when there are informers.
func (s *Service) scheduledPods(ctx context.Context) ([]sandboxpolicy.Binding, map[types.UID]corev1.PodQOSClass, error) {
	if s.pods == nil {
		scheduled, qos, err := ScheduledContainers(ctx, s.options.Kubernetes, s.options.NodeName)
		return scheduled, qos, err
	}
	pods, err := s.pods.Core().V1().Pods().Lister().List(labels.Everything())
	if err != nil {
		return nil, nil, err
	}
	namespaces, err := s.namespaces.Core().V1().Namespaces().Lister().List(labels.Everything())
	if err != nil {
		return nil, nil, err
	}
	namespaceLabels := make(map[string]map[string]string, len(namespaces))
	for _, ns := range namespaces {
		namespaceLabels[ns.Name] = ns.Labels
	}
	scheduled, qos := scheduledContainers(pods, namespaceLabels, s.options.NodeName)
	return scheduled, qos, nil
}

// podCgroupLayout reads the pod cgroup layout from a running pod container,
// and returns the cgroup IDs of the running containers.
func (s *Service) podCgroupLayout() (podCgroupLayout, bool, map[uint64]bool) {
	var layout podCgroupLayout
	found := false
	cgroups := map[uint64]bool{}
	if s.options.Containers == nil {
		return layout, false, cgroups
	}
	s.options.Containers.ContainerRange(func(c *containercollection.Container) {
		if c == nil {
			return
		}
		cgroups[c.CgroupID] = true
		if !found {
			layout, found = learnPodCgroupLayout(c.CgroupV2, types.UID(c.K8s.PodUID))
		}
	})
	return layout, found, cgroups
}

// ContainerCallback is deliberately nonblocking: event delivery must never hold
// discovery locks while a gadget is loading or Kubernetes is unavailable.
func (s *Service) ContainerCallback(containercollection.PubSubEvent) {
	s.inputEpoch.Add(1)
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Service) resolveBinding(v sandboxpolicy.Verdict) (sandboxpolicy.Binding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.bindings[v.ContainerID]
	return b, ok && b.CgroupID == v.CgroupID && b.PodUID == v.PodUID && b.PID == v.BindingPID && b.MountNamespace == v.MountNamespace
}

// ExporterStats exposes telemetry loss separately from enforcement readiness.
func (s *Service) ExporterStats() sandboxpolicy.ExporterStats { return s.exporter.Stats() }

func (s *Service) report(err error) {
	if err != nil && s.options.OnError != nil {
		s.options.OnError(err)
	}
}

// Close withdraws exact owned bindings before releasing their runtime. It waits
// for the reconciliation loop before cleanup so no concurrent pass can reinstall.
func (s *Service) Close(ctx context.Context) error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	s.mu.Lock()
	s.closed = true
	cancel := s.cancel
	if s.subscribed {
		s.options.Containers.Unsubscribe(s)
		s.subscribed = false
	}
	s.mu.Unlock()
	if cancel != nil {
		cancel()
		select {
		case <-s.done:
		case <-ctx.Done():
			return ctx.Err()
		}
		if s.pods != nil {
			s.pods.Shutdown()
			s.namespaces.Shutdown()
		}
	}
	if !s.backendClosed {
		if err := s.backend.Close(ctx); err != nil {
			return err
		}
		s.backendClosed = true
	}
	if !s.runtimeClosed {
		if err := s.closeRuntime(); err != nil {
			return err
		}
		s.runtimeClosed = true
	}
	return nil
}

// KernelEventStats exposes lifetime kernel verdict-ring statistics separately
// from ExporterStats. Unavailable counts/errors mean totals are incomplete;
// these evaluator counters do not cover early native-owner exec refusals.
func (s *Service) KernelEventStats(ctx context.Context) (igbackend.KernelEventStats, error) {
	var backend any = s.backend
	if sections, isSections := s.backend.(*sandboxpolicy.SectionBackend); isSections {
		backend = sections.Exec()
	}
	source, ok := backend.(interface {
		KernelEventStats(context.Context) (igbackend.KernelEventStats, error)
	})
	if !ok {
		return igbackend.KernelEventStats{}, fmt.Errorf("kernel event statistics unavailable")
	}
	return source.KernelEventStats(ctx)
}
