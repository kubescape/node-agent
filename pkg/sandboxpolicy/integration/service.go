package integration

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	stdmaps "maps"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/node-agent/pkg/watcher"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
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
// Callers must explicitly enable this service. ImageName is read only by
// sandbox_shared_qualification builds (the shared candidate image); default
// builds run the compiled-in product image and ignore it. ControlRoot and
// MaxOwners are legacy inputs that nothing reads (a set ControlRoot or a
// non-default MaxOwners is reported once on OnWarning).
type ServiceOptions struct {
	Kubernetes                                        kubernetes.Interface
	Dynamic                                           dynamic.Interface
	Containers                                        *containercollection.ContainerCollection
	Tracers                                           *tracercollection.TracerCollection
	NodeName, AgentNamespace, ImageName, ImageArchive string
	ContainerdSocket, ControlRoot                     string
	MaxOwners                                         uint64
	Engine                                            config.SandboxPolicyEngineConfig
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
	// PodName is node-agent's own pod: at shutdown, its DaemonSet tells an
	// uninstall (remove the pinned sets) from a restart (keep them).
	PodName string
	// RuntimeHelperExemption is the host operator's consent to the runtime
	// helper exemption on pod cgroup bindings (default off). See
	// igbackend.PrivilegeBackend.SetRuntimeHelperExemption.
	RuntimeHelperExemption bool
	// OnWarning receives start-time configuration notices that change no
	// enforcement (deprecated or ignored keys); nil drops them.
	OnWarning func(error)
	// Metrics receives the verdict telemetry counters (nil: not exported).
	Metrics metricsmanager.MetricsManager
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
	stopExporter  context.CancelFunc // exporter's own ctx; Close ends it after withdrawal and drain
	closeMu       sync.Mutex
	backendClosed bool
	exporterDone  bool
	runtimeClosed bool
	stopReported  bool
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
	// summaryErrors: the last verdict summary drain error of each section
	// (logged once while it repeats).
	summaryErrors sync.Map
	// cgroups and podCgroups index the container and pod bindings by
	// cgroup ID, for the section verdicts (they carry only the cgroup).
	cgroups    map[uint64]sandboxpolicy.Binding
	podCgroups map[uint64]sandboxpolicy.Binding
	// sectionOwners are the node-wide section backends, by section name.
	sectionOwners map[string]sectionOwner
	// hintMu serializes watch delivery with the configuration-list and refresh
	// boundaries. No API or backend calls run under it.
	hintMu        sync.Mutex
	listingHints  map[policyRevision]struct{} // non-nil until all lists finish
	matchedHint   bool                        // a replay may need to wake a retry if this pass fails
	refreshFailed bool
	// health is the shared engine's node health (nil for other engines).
	health sharedHealth
	// decodeErrors counts verdict events dropped by igbackend.ErrVerdictDecode.
	decodeErrors atomic.Uint64
	telemetry    verdictTelemetry // service loop goroutine only
	// dsWatch follows node-agent's own DaemonSet (nil: not started);
	// uninstall is the shutdown decision (decideUninstall); pinsRemoved:
	// removePinsOnUninstall ran.
	dsWatch                                  *daemonSetWatch
	uninstallDecided, uninstall, pinsRemoved bool
	// adoptedWithoutPolicy is the last reported count of adopted bindings
	// whose policy is gone, by section (service loop goroutine only).
	adoptedWithoutPolicy map[string]int
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
	if options.Kubernetes == nil || options.Dynamic == nil || options.Containers == nil || options.Tracers == nil || options.NodeName == "" || options.AgentNamespace == "" || options.ImageArchive == "" || options.ContainerdSocket == "" {
		return nil, fmt.Errorf("sandbox service requires clients, discovery, node identity and explicit archive")
	}
	if options.OnWarning != nil && options.MaxOwners != 0 && options.MaxOwners != config.SandboxPolicyMaxOwnersDefault {
		options.OnWarning(fmt.Errorf("sandboxPolicyMaxOwners %d is ignored: nothing reads it", options.MaxOwners))
	}
	if options.OnWarning != nil && options.ControlRoot != "" {
		options.OnWarning(fmt.Errorf("sandboxPolicyControlRoot %q is ignored: nothing reads it", options.ControlRoot))
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
	options.Receivers = withVerdictLog(options.Receivers)
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
	engine, err := newFullEngine(ctx, r, kubemanager.NewKubeManager(options.Containers, options.Tracers), store, options, s.report)
	if err != nil {
		_ = s.closeRuntime()
		return nil, err
	}
	s.health, _ = engine.(sharedHealth)
	full, err := igbackend.NewFull(engine, source, s.exporter, s.report)
	if err != nil {
		_ = s.closeRuntime()
		return nil, err
	}
	var privilege sandboxpolicy.Backend
	var privilegeUnavailable error
	lsmUnavailable := igbackend.CheckNodeBPFLSM(host.HostRoot)
	if options.PrivilegeImageName != "" {
		// IG's kernel admission (fullruntime.AdmitKernel): on a kernel it
		// refuses the section is not loaded.
		privilegeUnavailable = igbackend.VerifySectionKernel(sandboxpolicy.SectionPrivilege)
		if privilegeUnavailable == nil {
			privilegeUnavailable = igbackend.CheckBPFLSM(host.HostRoot)
		}
	}
	if options.PrivilegeImageName != "" && privilegeUnavailable == nil {
		privilegeEngine, err := igbackend.NewNativePrivilegeEngine(r, kubemanager.NewKubeManager(options.Containers, options.Tracers), store, options.PrivilegeImageName, s.reportSection)
		if err == nil {
			var p *igbackend.PrivilegeBackend
			p, err = igbackend.NewPrivilege(privilegeEngine, igbackend.LinuxValidator{ProcRoot: host.HostProcFs, CgroupRoot: filepath.Join(host.HostRoot, "sys/fs/cgroup")}, options.NodeName)
			if err == nil {
				p.SetRuntimeHelperExemption(options.RuntimeHelperExemption)
				privilege = p
			}
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
		// IG's kernel admission, then BPF LSM: on a failure the section is
		// not loaded (reported unavailable).
		networkUnavailable = igbackend.VerifySectionKernel(sandboxpolicy.SectionNetwork)
		if networkUnavailable == nil {
			networkUnavailable = igbackend.CheckNetworkBPFLSM(host.HostRoot)
		}
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
		// IG's kernel admission, then the file host checks: on a failure
		// the section (and the root barrier it loads) is not loaded.
		fileUnavailable = igbackend.VerifySectionKernel(sandboxpolicy.SectionFile)
		if fileUnavailable == nil {
			fileUnavailable = igbackend.CheckFile(host.HostRoot)
		}
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
	kept := enableRestartSurvival(map[string]restartSection{
		sandboxpolicy.SectionPrivilege: {privilege, options.PrivilegeImageName != ""},
		sandboxpolicy.SectionNetwork:   {network, options.NetworkImageName != ""},
		sandboxpolicy.SectionFile:      {file, options.FileImageName != ""},
	}, s.report)
	privilegeUnavailable = keptPins(privilegeUnavailable, kept[sandboxpolicy.SectionPrivilege])
	networkUnavailable = keptPins(networkUnavailable, kept[sandboxpolicy.SectionNetwork])
	fileUnavailable = keptPins(fileUnavailable, kept[sandboxpolicy.SectionFile])
	sections, err := sandboxpolicy.NewSectionBackend(full, privilege, privilegeUnavailable)
	if err != nil {
		_ = full.Close(ctx)
		_ = s.closeRuntime()
		return nil, err
	}
	s.backend = sections.WithNetwork(network, networkUnavailable).WithFile(file, fileUnavailable)
	s.Controller, err = sandboxpolicy.NewController(options.Dynamic, s.backend, options.Sources, readinessWriter{inner: engineStatusWriter(engine, &sandboxpolicy.DynamicStatusWriter{Client: options.Dynamic}), observed: &s.inputEpoch, snapshot: &s.snapshotEpoch}, sandboxpolicy.Options{Node: api.NodeReference{Name: node.Name, UID: node.UID}, AgentNamespace: options.AgentNamespace, File: fileNode, EnforcementUnavailable: lsmUnavailable, KernelRuntime: igbackend.CheckSectionKernelRuntime})
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
func (s *Service) WatchResources() []watcher.WatchResource          { return s.Controller.WatchResources() }
func (s *Service) AddHandler(_ context.Context, obj runtime.Object) { s.configurationHint(obj, false) }
func (s *Service) ModifyHandler(_ context.Context, obj runtime.Object) {
	s.configurationHint(obj, false)
}
func (s *Service) DeleteHandler(_ context.Context, obj runtime.Object) {
	s.configurationHint(obj, true)
}

type policyRevision struct {
	uid     types.UID
	version string
}

func (s *Service) configurationHint(obj runtime.Object, deleted bool) {
	if obj == nil {
		return
	}
	switch obj.GetObjectKind().GroupVersionKind().Kind {
	case "SandboxPolicy", "ClusterSandboxPolicy", "SandboxPolicyClasses":
		if !deleted {
			object, err := meta.Accessor(obj)
			if err == nil && object.GetUID() != "" && object.GetResourceVersion() != "" {
				s.revisionHint(policyRevision{object.GetUID(), object.GetResourceVersion()})
				return
			}
		}
		s.onPolicyChange()
	}
}

func (s *Service) revisionHint(revision policyRevision) {
	s.hintMu.Lock()
	defer s.hintMu.Unlock()
	if s.listingHints != nil {
		s.listingHints[revision] = struct{}{}
		return
	}
	if !s.Controller.HasConfigurationVersion(revision.uid, revision.version) {
		s.onPolicyChange()
		return
	}
	s.matchedHint = true
	if s.refreshFailed {
		s.queueRefresh()
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
	// The exporter outlives runCtx: verdicts reported while Close withdraws
	// enforcement must still reach the receivers.
	exporterCtx, stopExporter := context.WithCancel(context.WithoutCancel(ctx))
	s.stopExporter = stopExporter
	if s.options.Containers != nil {
		s.options.Containers.Subscribe(s, containercollection.ContainerSelector{}, s.ContainerCallback)
		s.subscribed = true
	}
	s.mu.Unlock()
	// Close waits on s.done once s.cancel is set. If Start unwinds (a panic)
	// before the loop that closes it is launched, close it here so Close
	// still reports AgentStopping and withdraws instead of timing out.
	loopStarted := false
	defer func() {
		if !loopStarted {
			close(s.done)
		}
	}()
	go func() {
		if err := s.exporter.Run(exporterCtx); err != nil && !errors.Is(err, context.Canceled) {
			s.report(fmt.Errorf("sandbox verdict exporter: %w", err))
		}
	}()
	// Like the exec exporter, it outlives runCtx: section verdicts reported
	// while Close withdraws enforcement must still reach the receivers.
	go func() {
		if err := s.sectionExporter.Run(exporterCtx); err != nil && !errors.Is(err, context.Canceled) {
			s.report(fmt.Errorf("sandbox section verdict exporter: %w", err))
		}
	}()
	// Close's Stop must find the exporter started, or it drops the queue
	// instead of draining it.
	select {
	case <-s.exporter.Started():
	case <-ctx.Done():
		return ctx.Err()
	}
	if s.pods != nil {
		s.pods.Start(runCtx.Done())
		s.namespaces.Start(runCtx.Done())
		// Bounded: the caches only add hints, refresh works without them.
		syncCtx, cancelSync := context.WithTimeout(runCtx, 10*time.Second)
		s.pods.WaitForCacheSync(syncCtx.Done())
		s.namespaces.WaitForCacheSync(syncCtx.Done())
		cancelSync()
	}
	// Restart survival: follow the own DaemonSet, so shutdown can tell an
	// uninstall from a restart without a read that an uninstall's removed
	// RBAC would refuse.
	if RestartPinRoot() != "" && s.options.Kubernetes != nil {
		watch, err := watchOwnDaemonSet(runCtx, s.options.Kubernetes, s.options.AgentNamespace, s.options.PodName)
		if err != nil {
			logger.L().Warning("sandbox restart survival: cannot follow the node-agent DaemonSet; shutdown reads it once", helpers.Error(err))
		}
		s.mu.Lock()
		s.dsWatch = watch
		s.mu.Unlock()
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
	loopStarted = true
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		telemetry := time.NewTicker(telemetryInterval)
		defer telemetry.Stop()
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
			case now := <-telemetry.C:
				s.exportTelemetry(runCtx, now)
			}
		}
	}()
	return nil
}
func (s *Service) refresh(ctx context.Context) {
	s.hintMu.Lock()
	s.listingHints = make(map[policyRevision]struct{})
	s.matchedHint = false
	s.refreshFailed = false
	s.snapshotEpoch.Store(s.inputEpoch.Load())
	s.hintMu.Unlock()
	// Every refresh (about every 5 s): the fail-rate windows need a recent
	// sample, else the status is unknown.
	if r, ok := s.backend.(sandboxpolicy.RateReporter); ok {
		r.SampleRates(time.Now())
	}
	s.drainVerdictSummaries()
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
	// snapshot is the binding snapshot of this refresh, when it was complete.
	var snapshot []sandboxpolicy.Binding
	snapshotComplete := false
	err := s.Controller.Refresh(ctx, func(ctx context.Context, selected func(sandboxpolicy.Binding) bool) ([]sandboxpolicy.Binding, error) {
		s.hintMu.Lock()
		for revision := range s.listingHints {
			if s.Controller.HasConfigurationVersion(revision.uid, revision.version) {
				s.matchedHint = true
			} else {
				s.onPolicyChange()
			}
		}
		s.listingHints = nil
		s.hintMu.Unlock()
		var bindings []sandboxpolicy.Binding
		var err error
		if s.snapshot != nil {
			bindings, err = s.snapshot(ctx)
		} else {
			bindings, err = SnapshotSelectedBindings(ctx, s.options.Kubernetes, s.options.Containers, s.options.NodeName, selected)
		}
		var pending *sandboxpolicy.BindingPendingError
		if errors.As(err, &pending) && bindings != nil {
			err = fmt.Errorf("sandbox binding snapshot partial: %w", err)
		} else if err != nil {
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
		snapshot, snapshotComplete = bindings, err == nil
		return bindings, err
	})
	s.hintMu.Lock()
	s.refreshFailed = err != nil
	// If listing failed, the binding callback never classified its hints.
	if len(s.listingHints) > 0 {
		s.onPolicyChange()
	} else if s.refreshFailed && s.matchedHint {
		s.queueRefresh()
	}
	s.listingHints = nil
	s.hintMu.Unlock()
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
	// Restart survival (see igbackend). It needs a complete binding snapshot
	// and every pod binding in place. Each section then settles on its own
	// when its bindings committed (SectionBackend.Settle): a failing binding
	// of another section or a failed status write does not hold it back.
	// The controller must also have accepted the snapshot and built every
	// binding's full plan (no policy error, no retiring binding): only then
	// does "no plan" mean "no policy".
	// The policy listing alone tells a gone policy: report it also on a
	// node that does not converge.
	s.reportAdoptedWithoutPolicy()
	// Past the settle deadline, a binding whose policies are all gone from
	// a complete listing is dropped without waiting for convergence.
	s.listPolicies()
	if !snapshotComplete || !s.Controller.PlansComplete() || !podsBound {
		return
	}
	sections, isSections := s.backend.(*sandboxpolicy.SectionBackend)
	if isSections {
		sections.SnapshotComplete(snapshot)
	} else if err != nil {
		return // a single backend: only a converged refresh settles it
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
	// unresolved: a pod with a plan whose cgroup was not found; its pod
	// binding is not in place, so restart survival does not settle.
	polling, unresolved := false, false
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
				unresolved = true
				continue
			}
			id, err := s.podCgroupID(path)
			if err != nil || id == 0 {
				polling = polling || now.Sub(seen) < prepareInterval
				// A cgroup that does not exist holds no binding; a
				// failed lookup of one that may exist is unresolved.
				unresolved = unresolved || (err != nil && !errors.Is(err, fs.ErrNotExist))
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
		// A section backend tracks the failure per section (a failed
		// section does not settle); other backends do not.
		if _, tracked := s.backend.(*sandboxpolicy.SectionBackend); !tracked {
			return false
		}
	}
	return !polling && !unresolved
}

// reportAdoptedWithoutPolicy reports the kernel bindings of the previous
// node-agent run whose policy is gone (restart survival). No policy status
// carries them, so the node reports them: a metric per section, and a warning
// when the count changes. At the settle deadline the section drops them.
func (s *Service) reportAdoptedWithoutPolicy() {
	counts, ok := s.Controller.AdoptedWithoutPolicy()
	if !ok {
		return
	}
	for section := range s.adoptedWithoutPolicy {
		if _, still := counts[section]; !still {
			counts[section] = 0
		}
	}
	for section, n := range counts {
		if s.adoptedWithoutPolicy[section] == n {
			continue
		}
		if n > 0 {
			logger.L().Warning("sandbox restart survival: adopted kernel bindings enforce a policy that no longer exists; they keep enforcing until the section settles",
				helpers.String("section", section), helpers.Int("bindings", n))
		}
		if s.options.Metrics != nil {
			s.options.Metrics.SetSandboxPolicyAdoptedWithoutPolicy(section, n)
		}
	}
	s.adoptedWithoutPolicy = counts
}

// policyLister is a section owner that drops, past the settle deadline,
// the adopted bindings whose policies left the listing (igbackend).
type policyLister interface {
	PoliciesListed(uids, names map[string]bool) error
}

// listPolicies gives each section owner the last complete policy listing.
// A failed listing gives nothing: no policy is read as gone.
func (s *Service) listPolicies() {
	uids, names, ok := s.Controller.ListedPolicies()
	if !ok {
		return
	}
	s.mu.RLock()
	owners := make(map[string]sectionOwner, len(s.sectionOwners))
	for name, o := range s.sectionOwners {
		owners[name] = o
	}
	s.mu.RUnlock()
	for name, o := range owners {
		if l, ok := o.(policyLister); ok {
			if err := l.PoliciesListed(uids, names); err != nil {
				s.report(fmt.Errorf("sandbox %s restart settle: %w", name, err))
			}
		}
	}
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
	s.invalidateInputs()
}

// onPolicyChange invalidates the inputs after a policy change. A policy change
// can need new slots: the next refresh prepares after it loads the new policies.
func (s *Service) onPolicyChange() {
	s.policyChanged.Store(true)
	s.invalidateInputs()
}

func (s *Service) invalidateInputs() {
	s.inputEpoch.Add(1)
	s.queueRefresh()
}

func (s *Service) queueRefresh() {
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

// summaryDrainer is a section owner that drains its lost-verdict summaries.
type summaryDrainer interface {
	DrainVerdictSummaries() ([]sandboxpolicy.VerdictSummary, error)
}

// drainVerdictSummaries logs one record per summary of denies the kernel
// could not report, and gives it to the receivers that take summaries
// (synchronously: a receiver must not block). Best effort: a drain error (an
// instance without the map, or stopping) is logged once while it repeats;
// the rate_limited and dropped counters keep the number.
func (s *Service) drainVerdictSummaries() {
	s.mu.RLock()
	owners := s.sectionOwners
	s.mu.RUnlock()
	for section, owner := range owners {
		d, ok := owner.(summaryDrainer)
		if !ok {
			continue
		}
		summaries, err := d.DrainVerdictSummaries()
		// One warning per section while the same error repeats; a drain
		// that succeeds again resets it.
		if err == nil {
			s.summaryErrors.Delete(section)
		} else if last, _ := s.summaryErrors.Swap(section, err.Error()); last != err.Error() {
			logger.L().Warning("sandbox "+section+" verdict summaries: drain failed", helpers.Error(err))
		}
		for _, sum := range summaries {
			delivered := 0
			if s.sectionExporter != nil {
				sum, delivered = s.sectionExporter.ReportVerdictSummary(sum)
			}
			logger.L().Info("sandbox "+sum.Section+" verdict summary", helpers.String("rule", sum.Rule), helpers.String("mode", string(sum.Mode)),
				helpers.String("hook", sum.Hook), helpers.String("detail", sum.Detail), helpers.String("firstComm", sum.FirstComm), helpers.Int("firstPid", int(sum.FirstPID)),
				helpers.String("lastComm", sum.LastComm), helpers.Int("lastPid", int(sum.LastPID)), helpers.String("cgroup", strconv.FormatUint(sum.CgroupID, 10)),
				helpers.String("count", strconv.FormatUint(sum.Count, 10)), helpers.String("reason", sum.Reason),
				helpers.String("first", sum.First.UTC().Format(time.RFC3339Nano)), helpers.String("last", sum.Last.UTC().Format(time.RFC3339Nano)),
				helpers.Int("slot", int(sum.Slot)), helpers.String("generation", strconv.FormatUint(sum.Generation, 10)),
				helpers.String("container", sum.Binding.ContainerID), helpers.Int("receivers", delivered))
		}
	}
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
	if errors.Is(err, igbackend.ErrVerdictDecode) {
		s.decodeErrors.Add(1)
	}
	if err != nil && s.options.OnError != nil {
		s.options.OnError(err)
	}
}

// AgentStoppingTimeout bounds how long Close waits for its best-effort
// AgentStopping status writes.
const AgentStoppingTimeout = sandboxpolicy.AgentStoppingTimeout

// Close withdraws exact owned bindings before releasing their runtime. It waits
// for the reconciliation loop before cleanup so no concurrent pass can reinstall.
// Before withdrawing, it reports Ready False (AgentStopping) for every exec
// policy, best-effort within AgentStoppingTimeout; no status is written after.
// Only after withdrawal does it stop the verdict exporter, which delivers the
// verdicts still queued (including those reported during withdrawal) for at
// most VerdictDrainTimeout within ctx; what is still queued then is counted as
// dropped. If Close returns early (ctx ends while waiting for the loop, or
// backend.Close fails), the exporter keeps delivering until a later Close.
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
	// First, while node-agent's RBAC still exists: an uninstall removes it.
	s.decideUninstall(ctx)
	if cancel != nil {
		cancel()
		select {
		case <-s.done:
		case <-ctx.Done():
			// The loop did not stop in time. After an uninstall the pins go
			// anyway: no next node-agent takes them over (a set the loop
			// still pins after this stays until the node reboots).
			s.removePinsOnUninstall()
			return ctx.Err()
		}
		if s.pods != nil {
			s.pods.Shutdown()
			s.namespaces.Shutdown()
		}
	}
	// After an uninstall no node-agent takes the pinned sets over: remove
	// them now, once the refresh loop can no longer pin a new set, and before
	// the slower steps below (a SIGKILL at the end of the grace period would
	// leave them). The running links stay held by this process until it
	// exits, so enforcement goes on until then.
	s.removePinsOnUninstall()
	if !s.stopReported && s.Controller != nil {
		// The loop has joined: no reconciliation writes concurrently, and
		// StopReporting ends every later write.
		stopCtx, cancelStop := context.WithTimeout(ctx, AgentStoppingTimeout)
		if err := s.Controller.StopReporting(stopCtx); err != nil {
			s.report(fmt.Errorf("sandbox agent stopping status (continuing shutdown): %w", err))
		}
		cancelStop()
		s.stopReported = true
	}
	if !s.backendClosed {
		if err := s.backend.Close(ctx); err != nil {
			return err
		}
		s.backendClosed = true
	}
	if !s.exporterDone {
		// Bounded separately so a stuck receiver cannot spend Close's whole
		// budget before the runtime is released.
		drainCtx, cancelDrain := context.WithTimeout(ctx, sandboxpolicy.VerdictDrainTimeout)
		if err := s.exporter.Stop(drainCtx); err != nil {
			s.report(fmt.Errorf("sandbox verdict exporter drain (continuing shutdown): %w", err))
		}
		cancelDrain()
		s.mu.Lock()
		stopExporter := s.stopExporter
		s.mu.Unlock()
		if stopExporter != nil {
			stopExporter()
		}
		s.exporterDone = true
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
