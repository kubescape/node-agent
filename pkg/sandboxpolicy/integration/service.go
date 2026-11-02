package integration

import (
	"context"
	"fmt"
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
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/node-agent/pkg/watcher"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
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
	// podsScheduled is set by a Pending-pod event; lastPrepare bounds how
	// often privilege slot preparation lists the node's pods.
	podsScheduled atomic.Bool
	lastPrepare   time.Time
}

// prepareInterval is the longest time between two slot preparations.
const prepareInterval = 30 * time.Second

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
	if options.PrivilegeImageName != "" {
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
	s.backend, err = sandboxpolicy.NewSectionBackend(full, privilege)
	if err != nil {
		_ = full.Close(ctx)
		_ = s.closeRuntime()
		return nil, err
	}
	s.Controller, err = sandboxpolicy.NewController(options.Dynamic, s.backend, options.Sources, readinessWriter{inner: &sandboxpolicy.DynamicStatusWriter{Client: options.Dynamic}, observed: &s.inputEpoch, snapshot: &s.snapshotEpoch}, sandboxpolicy.Options{Node: api.NodeReference{Name: node.Name, UID: node.UID}, AgentNamespace: options.AgentNamespace})
	if err != nil {
		_ = s.backend.Close(ctx)
		_ = s.closeRuntime()
		return nil, err
	}
	return s, nil
}

// Watch events are hints only. Generic watcher queues may deliver old updates
// after a relist/deletion; applying their payload could resurrect removed policy.
// Refresh always reads authoritative configuration and cannot revive queued UIDs.
// WatchResources adds this node's pods, so a scheduled pod can get its privilege
// slot before its containers start.
func (s *Service) WatchResources() []watcher.WatchResource {
	resources := s.Controller.WatchResources()
	if s.options.PrivilegeImageName == "" {
		return resources
	}
	pods := watcher.NewWatchResource(schema.GroupVersionResource{Version: "v1", Resource: "pods"}, metav1.ListOptions{FieldSelector: "spec.nodeName=" + s.options.NodeName})
	return append(resources, pods)
}
func (s *Service) AddHandler(_ context.Context, obj runtime.Object)    { s.configurationHint(obj) }
func (s *Service) ModifyHandler(_ context.Context, obj runtime.Object) { s.configurationHint(obj) }
func (s *Service) DeleteHandler(_ context.Context, obj runtime.Object) { s.configurationHint(obj) }
func (s *Service) configurationHint(obj runtime.Object) {
	if obj == nil {
		return
	}
	if pod, ok := obj.(*corev1.Pod); ok {
		if s.options.PrivilegeImageName != "" && pod.Spec.NodeName == s.options.NodeName && pod.Status.Phase == corev1.PodPending {
			s.podsScheduled.Store(true)
			s.ContainerCallback(containercollection.PubSubEvent{})
		}
		return
	}
	switch obj.GetObjectKind().GroupVersionKind().Kind {
	case "SandboxPolicy", "ClusterSandboxPolicy", "SandboxPolicyClasses":
		s.ContainerCallback(containercollection.PubSubEvent{})
	}
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
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				s.refresh(runCtx)
			case <-s.wake:
				s.refresh(runCtx)
			}
		}
	}()
	return nil
}
func (s *Service) refresh(ctx context.Context) {
	s.snapshotEpoch.Store(s.inputEpoch.Load())
	// Prepare after a Pending-pod event, else at most every prepareInterval,
	// so the extra pod and namespace listing does not run on every refresh.
	if s.options.PrivilegeImageName != "" && s.options.Kubernetes != nil && s.Controller.HasPrivilegePolicies() &&
		(s.podsScheduled.Swap(false) || time.Since(s.lastPrepare) >= prepareInterval) {
		s.lastPrepare = time.Now()
		scheduled, err := ScheduledContainers(ctx, s.options.Kubernetes, s.options.NodeName)
		if err == nil {
			err = s.Controller.PrepareScheduled(ctx, scheduled)
		}
		if err != nil {
			s.report(fmt.Errorf("privilege slot preparation: %w", err))
		}
	}
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
