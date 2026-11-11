package integration

import (
	"context"
	"errors"
	"fmt"
	stdmaps "maps"
	"path/filepath"
	"strings"
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
	// QualifiedKernels lists the kernel releases (uname -r) on which the
	// slot sections (privilege, network, file) may report Ready; empty uses
	// igbackend.QualifiedKernels, and "*" admits every kernel. On another
	// kernel they enforce but stay NotReady (<Section>KernelUnqualified).
	QualifiedKernels []string
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
	// podsScheduled is set by a Pending-pod event, policyChanged by a policy
	// event; lastPrepare bounds how often slot preparation lists the node's
	// pods.
	podsScheduled atomic.Bool
	policyChanged atomic.Bool
	lastPrepare   time.Time
	// hadSlotPolicies: the last refresh saw a privilege, network or file policy.
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
	started   map[types.UID]bool
	// podFirstSeen is when a pod with a pod plan was first seen. podPolling is
	// set while such a pod has no pod cgroup yet, for up to prepareInterval.
	podFirstSeen map[types.UID]time.Time
	podPolling   bool
	// podPods, podQoS and podPlans are the inputs of the last bindPods,
	// reused by the poll. podPollErr is the last error the poll reported.
	podPods    []sandboxpolicy.Binding
	podQoS     map[types.UID]corev1.PodQOSClass
	podStarted map[types.UID]bool
	podPlans   map[types.UID]sandboxpolicy.Plan
	podPollErr string
	// podCgroupID returns the cgroup ID of a pod cgroup path (replaced in tests).
	podCgroupID func(string) (uint64, error)
	// pods and namespaces are the informers of the node's pods and of all
	// namespaces (nil without a privilege or network image).
	pods, namespaces informers.SharedInformerFactory
	// sectionExporter queues the privilege, network and file verdicts apart
	// from exec's, so section denies never fill exec's queue.
	sectionExporter *sandboxpolicy.SectionExporter
	// cgroups and podCgroups index the container and pod bindings by
	// cgroup ID, for the section verdicts (they carry only the cgroup).
	cgroups    map[uint64]sandboxpolicy.Binding
	podCgroups map[uint64]sandboxpolicy.Binding
	// sectionOwners are the node-wide section backends, by section name.
	sectionOwners map[string]sectionOwner
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
	s.sectionExporter, err = sandboxpolicy.NewSectionExporter(sandboxpolicy.SectionExporterOptions{Capacity: 1024, Receivers: options.Receivers, ResolveCgroup: s.resolveCgroup, SlotPolicies: s.slotPolicies})
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
	lsmUnavailable := igbackend.CheckNodeBPFLSM(host.HostRoot)
	if options.PrivilegeImageName != "" {
		privilegeUnavailable = igbackend.CheckBPFLSM(host.HostRoot)
	}
	if options.PrivilegeImageName != "" && privilegeUnavailable == nil {
		privilegeEngine, err := igbackend.NewNativePrivilegeEngine(r, kubemanager.NewKubeManager(options.Containers, options.Tracers), store, options.PrivilegeImageName, s.reportSection)
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
		// The gadget uses BPF LSM programs; without BPF LSM the network
		// section is reported unavailable (BPFLSMInactive).
		networkUnavailable = igbackend.CheckNetworkBPFLSM(host.HostRoot)
		if networkUnavailable == nil {
			networkEngine, err := igbackend.NewNativeNetworkEngine(r, kubemanager.NewKubeManager(options.Containers, options.Tracers), store, options.NetworkImageName, s.reportSection)
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
		fileEngine, err := igbackend.NewNativeFileEngine(r, kubemanager.NewKubeManager(options.Containers, options.Tracers), store, options.FileImageName, s.reportSection)
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
	owners := map[string]sectionOwner{}
	for name, b := range map[string]sandboxpolicy.Backend{sandboxpolicy.SectionPrivilege: privilege, sandboxpolicy.SectionNetwork: network, sandboxpolicy.SectionFile: file} {
		if o, ok := b.(sectionOwner); ok {
			owners[name] = o
		}
	}
	s.mu.Lock()
	s.sectionOwners = owners
	s.mu.Unlock()
	enableRestartSurvival(map[string]sandboxpolicy.Backend{sandboxpolicy.SectionPrivilege: privilege, sandboxpolicy.SectionNetwork: network, sandboxpolicy.SectionFile: file}, s.report)
	sections, err := sandboxpolicy.NewSectionBackend(full, privilege, privilegeUnavailable)
	if err != nil {
		_ = full.Close(ctx)
		_ = s.closeRuntime()
		return nil, err
	}
	s.backend = sections.WithNetwork(network, networkUnavailable).WithFile(file, fileUnavailable)
	for name, enabled := range map[string]bool{sandboxpolicy.SectionPrivilege: privilege != nil, sandboxpolicy.SectionNetwork: network != nil, sandboxpolicy.SectionFile: file != nil} {
		if enabled {
			sections.SetSectionUnqualified(name, kernelGate(name, options.QualifiedKernels))
		}
	}
	s.Controller, err = sandboxpolicy.NewController(options.Dynamic, s.backend, options.Sources, readinessWriter{inner: &sandboxpolicy.DynamicStatusWriter{Client: options.Dynamic}, observed: &s.inputEpoch, snapshot: &s.snapshotEpoch}, sandboxpolicy.Options{Node: api.NodeReference{Name: node.Name, UID: node.UID}, AgentNamespace: options.AgentNamespace, File: fileNode, EnforcementUnavailable: lsmUnavailable})
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
		// A policy change can need new slots: the next refresh prepares
		// after it loads the new policies.
		s.policyChanged.Store(true)
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
	go func() {
		if err := s.exporter.Run(runCtx); err != nil && !errors.Is(err, context.Canceled) {
			s.report(fmt.Errorf("sandbox verdict exporter: %w", err))
		}
	}()
	go func() {
		if err := s.sectionExporter.Run(runCtx); err != nil && !errors.Is(err, context.Canceled) {
			s.report(fmt.Errorf("sandbox section verdict exporter: %w", err))
		}
	}()
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
	// Prepare after a Pending-pod event, else at most every prepareInterval;
	// after a policy event, prepare once Refresh has loaded the policies.
	hasSlotPolicies := s.Controller.HasSlotPolicies()
	preparing := s.options.slotSections() && s.options.Kubernetes != nil
	if preparing && !hasSlotPolicies && s.hadSlotPolicies {
		// The last slot policy is gone: one preparation with no active
		// section clears the prepared sets (it never starts a gadget).
		if err := s.Controller.PrepareScheduled(ctx, nil); err != nil {
			s.report(fmt.Errorf("slot preparation: %w", err))
		}
	}
	s.hadSlotPolicies = hasSlotPolicies
	policyChanged := s.policyChanged.Swap(false)
	if preparing && hasSlotPolicies && (s.podsScheduled.Swap(false) || time.Since(s.lastPrepare) >= prepareInterval) {
		s.prepare(ctx)
	}
	// Every refresh, so a policy change also reaches the pod bindings: before
	// the container bindings change, and after, when they created a slot.
	s.bindPods(ctx)
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
		s.cgroups = make(map[uint64]sandboxpolicy.Binding, len(next))
		for _, b := range next {
			s.cgroups[b.CgroupID] = b
		}
		s.mu.Unlock()
		return bindings, nil
	})
	if err != nil {
		s.report(err)
	}
	// The policies were just loaded (the first ones, as at start) or changed:
	// prepare with them now, so each active policy has its slot before a pod
	// matches it, and the first instance start already has these slots.
	if preparing && (policyChanged || !hasSlotPolicies) && s.Controller.HasSlotPolicies() {
		s.prepare(ctx)
	}
	podsBound := s.bindPods(ctx)
	// Converged, pod bindings included: the node backends drop the last-good
	// state of the previous node-agent run (see igbackend restart survival).
	if err != nil || !podsBound {
		return
	}
	if settler, ok := s.backend.(sandboxpolicy.Settler); ok {
		if err := settler.Settle(ctx); err != nil {
			s.report(fmt.Errorf("sandbox restart survival: %w", err))
		}
	}
}

// prepare passes the containers of the node's scheduled pods to the slot
// preparation (Controller.PrepareScheduled).
func (s *Service) prepare(ctx context.Context) {
	s.lastPrepare = time.Now()
	scheduled, qos, started, err := s.scheduledPods(ctx)
	if err == nil {
		s.scheduled, s.qos, s.started = scheduled, qos, started
		err = s.Controller.PrepareScheduled(ctx, scheduled)
	}
	if err != nil {
		s.report(fmt.Errorf("slot preparation: %w", err))
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
// It reports whether every pod binding is in place (true with no pod work).
func (s *Service) bindPods(ctx context.Context) bool {
	if _, ok := s.backend.(sandboxpolicy.PodBinder); !ok || s.Controller == nil {
		return true
	}
	// No available section binds pod cgroups: no pod work.
	if sections, isSections := s.backend.(*sandboxpolicy.SectionBackend); isSections && !sections.BindsPods() {
		return true
	}
	s.podPolling = false // set again below when a pod cgroup is missing
	scheduled, qos, started := s.scheduled, s.qos, s.started
	if s.pods != nil {
		var err error
		if scheduled, qos, started, err = s.scheduledPods(ctx); err != nil {
			s.report(fmt.Errorf("pod binding: %w", err))
			return false
		}
	}
	plans, ok := s.Controller.PodPlans(scheduled)
	if !ok {
		s.podPlans = nil
		return false // the policies are not known: keep the pod bindings
	}
	s.podPods, s.podQoS, s.podStarted, s.podPlans = scheduled, qos, started, plans
	s.podPollErr = ""
	return s.bindPodPlans(ctx, scheduled, qos, started, plans, false)
}

// pollPods checks again for the pod cgroups that were missing. It reuses the
// pods and plans of the last bindPods, so the 50 ms poll does not list pods
// and compile policies.
func (s *Service) pollPods(ctx context.Context) {
	s.podPolling = false
	if s.podPlans == nil {
		return
	}
	s.bindPodPlans(ctx, s.podPods, s.podQoS, s.podStarted, s.podPlans, true)
}

// bindPodPlans reports whether every pod binding is in place: no error and
// no pod cgroup still awaited.
func (s *Service) bindPodPlans(ctx context.Context, scheduled []sandboxpolicy.Binding, qos map[types.UID]corev1.PodQOSClass, apiStarted map[types.UID]bool, known map[types.UID]sandboxpolicy.Plan, poll bool) bool {
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
		layout, known, containerCgroups, started, containerPaths := s.podCgroupLayout()
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
			pods = append(pods, sandboxpolicy.PodBinding{PodUID: c.PodUID, Namespace: c.Namespace, PodName: c.PodName, CgroupID: id, CgroupPath: path, Plan: plan,
				ContainersStarted: started[c.PodUID] || apiStarted[c.PodUID] || underPod(containerPaths, path)})
		}
	}
	s.podFirstSeen, s.podPolling = firstSeen, polling
	podCgroups := make(map[uint64]sandboxpolicy.Binding, len(pods))
	for _, p := range pods {
		podCgroups[p.CgroupID] = sandboxpolicy.Binding{CgroupID: p.CgroupID, CgroupPath: p.CgroupPath, PodUID: p.PodUID, Namespace: p.Namespace, PodName: p.PodName}
	}
	s.mu.Lock()
	s.podCgroups = podCgroups
	s.mu.Unlock()
	if err := binder.BindPods(ctx, pods); err != nil {
		// The poll runs every 50 ms: report a repeated error once.
		if !poll || err.Error() != s.podPollErr {
			s.report(fmt.Errorf("pod binding: %w", err))
		}
		if poll {
			s.podPollErr = err.Error()
		}
		return false
	}
	return !polling
}

// scheduledPods returns the containers and QoS classes of the node's pods (see
// ScheduledContainers), from the informer caches when there are informers.
func (s *Service) scheduledPods(ctx context.Context) ([]sandboxpolicy.Binding, map[types.UID]corev1.PodQOSClass, map[types.UID]bool, error) {
	if s.pods == nil {
		return ScheduledContainers(ctx, s.options.Kubernetes, s.options.NodeName)
	}
	pods, err := s.pods.Core().V1().Pods().Lister().List(labels.Everything())
	if err != nil {
		return nil, nil, nil, err
	}
	namespaces, err := s.namespaces.Core().V1().Namespaces().Lister().List(labels.Everything())
	if err != nil {
		return nil, nil, nil, err
	}
	namespaceLabels := make(map[string]map[string]string, len(namespaces))
	for _, ns := range namespaces {
		namespaceLabels[ns.Name] = ns.Labels
	}
	scheduled, qos, started := scheduledContainers(pods, namespaceLabels, s.options.NodeName)
	return scheduled, qos, started, nil
}

// podCgroupLayout reads the pod cgroup layout from a running pod container,
// and returns the cgroup IDs of the running containers.
func (s *Service) podCgroupLayout() (podCgroupLayout, bool, map[uint64]bool, map[types.UID]bool, []string) {
	var layout podCgroupLayout
	found := false
	cgroups := map[uint64]bool{}
	// The pods with a container that exists, by pod UID and by cgroup path
	// (a container whose pod UID is not enriched yet). The collection drops
	// pause containers. Together with the pod's API status this is a
	// snapshot: a container created after it is not seen until the next
	// call (see sandboxpolicy.PodBinding).
	started := map[types.UID]bool{}
	var paths []string
	if s.options.Containers == nil {
		return layout, false, cgroups, started, paths
	}
	s.options.Containers.ContainerRange(func(c *containercollection.Container) {
		if c == nil {
			return
		}
		cgroups[c.CgroupID] = true
		if c.K8s.PodUID != "" {
			started[types.UID(c.K8s.PodUID)] = true
		}
		if c.CgroupV2 != "" {
			paths = append(paths, c.CgroupV2)
		}
		if !found {
			layout, found = learnPodCgroupLayout(c.CgroupV2, types.UID(c.K8s.PodUID))
		}
	})
	return layout, found, cgroups, started, paths
}

// underPod reports whether a container cgroup path lies under the pod cgroup
// path. Both come from the same host view; the container path may carry a
// longer prefix, so the pod path is matched as a path segment sequence.
func underPod(containerPaths []string, podPath string) bool {
	pod := "/" + strings.Trim(podPath, "/") + "/"
	if pod == "//" {
		return false
	}
	for _, p := range containerPaths {
		if strings.Contains(p+"/", pod) && !strings.HasSuffix(strings.TrimRight(p, "/")+"/", pod) {
			return true
		}
	}
	return false
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

// resolveCgroup finds the container or pod binding of a section verdict.
func (s *Service) resolveCgroup(id uint64) (sandboxpolicy.Binding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if b, ok := s.cgroups[id]; ok {
		return b, true
	}
	b, ok := s.podCgroups[id]
	return b, ok
}

// sectionOwner is a node-wide section backend (igbackend's node owner).
type sectionOwner interface {
	SlotPolicies(generation uint64, slot uint32) ([]sandboxpolicy.CompiledPolicy, bool)
	VerdictStats() igbackend.VerdictStats
}

func (s *Service) slotPolicies(section string, generation uint64, slot uint32) ([]sandboxpolicy.CompiledPolicy, bool) {
	s.mu.RLock()
	owner := s.sectionOwners[section]
	s.mu.RUnlock()
	if owner == nil {
		return nil, false
	}
	return owner.SlotPolicies(generation, slot)
}

// reportSection is the gadgets' SectionReporter. A full queue is counted in
// SectionExporterStats.Dropped.
func (s *Service) reportSection(event sandboxpolicy.SectionEvent) {
	_ = s.sectionExporter.ReportSection(context.Background(), event)
}

// SectionExporterStats is the telemetry loss of the section verdict queue.
func (s *Service) SectionExporterStats() sandboxpolicy.ExporterStats {
	return s.sectionExporter.Stats()
}

// ExporterStats exposes telemetry loss separately from enforcement readiness.
func (s *Service) ExporterStats() sandboxpolicy.ExporterStats { return s.exporter.Stats() }

// SectionVerdictStats exposes the kernel verdict counters of each running
// section gadget: denies the kernel could not report (ring buffer full or
// rate limited) are counted there, not lost silently.
func (s *Service) SectionVerdictStats() map[string]igbackend.VerdictStats {
	s.mu.RLock()
	owners := s.sectionOwners
	s.mu.RUnlock()
	stats := make(map[string]igbackend.VerdictStats, len(owners))
	for name, o := range owners {
		stats[name] = o.VerdictStats()
	}
	return stats
}

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

// kernelGate returns why a slot section must not report Ready on this kernel
// (reason <Section>KernelUnqualified), or nil on a qualified kernel.
func kernelGate(section string, qualified []string) error {
	reason := strings.ToUpper(section[:1]) + section[1:] + "KernelUnqualified"
	release, err := igbackend.KernelRelease()
	if err != nil {
		return &sandboxpolicy.EnforcementUnavailableError{Section: section, Reason: reason, Enforcing: true, Detail: fmt.Sprintf("kernel release: %v", err)}
	}
	var u *sandboxpolicy.EnforcementUnavailableError
	if err := igbackend.CheckQualifiedKernel(release, qualified); errors.As(err, &u) {
		return &sandboxpolicy.EnforcementUnavailableError{Section: section, Reason: reason, Enforcing: true, Detail: u.Detail}
	}
	return nil
}
