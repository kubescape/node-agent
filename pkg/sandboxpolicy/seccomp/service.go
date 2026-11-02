package seccomp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	nriapi "github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/watcher"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// AnnotationKey records the profile revision injected into a container. The
// runtime keeps it, so a restarted node-agent can tell which containers are
// already protected.
const AnnotationKey = "kubescape.io/sandbox-seccomp"

const (
	pluginName     = "kubescape-sandbox"
	pluginIndex    = "50"
	refreshPeriod  = 5 * time.Second
	reconnectDelay = 30 * time.Second
	namespaceTTL   = time.Minute
	// Watch events trigger a policy list; this period only repairs missed events.
	policyListPeriod = time.Minute
	podListPeriod    = 30 * time.Second
	// firstAttemptWait bounds how long the first report waits for NRI.
	firstAttemptWait = 10 * time.Second
	// hotPathLimit bounds API lookups inside CreateContainer, well under NRI's
	// default 2 s plugin request timeout, after which the runtime drops the plugin.
	hotPathLimit = 500 * time.Millisecond
	lookupLimit  = 2 * time.Second
	// fallbackGrace keeps unreferenced fallback files for pods about to start.
	fallbackGrace = 10 * time.Minute
)

// Options configures the seccomp layer. Pods returns a cached pod, or nil.
type Options struct {
	Dynamic        dynamic.Interface
	Kubernetes     kubernetes.Interface
	Pods           func(namespace, name string) *corev1.Pod
	NodeName       string
	AgentNamespace string
	NRISocket      string
	ProfilesDir    string
	Arch           string
	// RuntimeDefault returns a default profile for a capability set, used when
	// the runtime does not report its own.
	RuntimeDefault func(capabilities []string) *specs.LinuxSeccomp
	// ExecEnforcement is true when the exec controller runs. Its enforced
	// policies then get the root barrier they rely on.
	ExecEnforcement bool
	// Contributes is true when the exec controller writes the node reports; the
	// service then adds its state to them instead of writing its own.
	Contributes bool
	Writer      sandboxpolicy.StatusWriter
	// Receivers get a Verdict for each logged decision of an injected profile.
	Receivers Receivers
	OnError   func(error)
}

// desired is the profile one container should run with.
type desired struct {
	revision string
	base     Base
	profile  *specs.LinuxSeccomp
	rules    map[types.UID]map[string]api.RuleMode // policy -> rule -> mode
	index    map[string][]Match                    // syscall -> rules that deny it
	notes    []string
}

type tracked struct {
	namespace, pod, podUID, container string
	info                              RuntimeInfo
	applied                           string             // revision injected at creation; empty if none
	index                             map[string][]Match // attribution for the applied revision
}

// pending is one container whose running profile differs from the desired one.
type pending struct {
	container string
	reason    string
	rules     map[types.UID]map[string]api.RuleMode
}

// Service injects SandboxPolicy seccomp profiles through NRI, and writes them as
// opt-in Localhost files where the runtime cannot take an injected profile.
type Service struct {
	options Options

	policies  atomic.Pointer[[]sandboxpolicy.PolicyView]
	nriActive atomic.Bool
	// nriProblem says why injection is unavailable, for the pending reason.
	nriProblem atomic.Pointer[string]

	mu          sync.Mutex
	containers  map[string]*tracked
	pending     []pending
	notes       map[types.UID][]string
	unsupport   map[types.UID][]Unsupported
	namespaces  map[string]namespaceEntry
	listed      time.Time
	podsListed  time.Time
	nodePods    []corev1.Pod
	policyDirty atomic.Bool

	wake chan struct{}
	node api.NodeReference
	// attempted closes after the first NRI connection attempt, so the first
	// report does not claim NRI is missing while it is still connecting.
	attempted chan struct{}
	attemptMu sync.Once
}

type namespaceEntry struct {
	labels  map[string]string
	fetched time.Time
}

func NewService(options Options) (*Service, error) {
	if options.Dynamic == nil || options.Kubernetes == nil || options.Pods == nil || options.NodeName == "" || options.RuntimeDefault == nil {
		return nil, fmt.Errorf("seccomp layer requires clients, pod lookup, node name and runtime default profile")
	}
	if options.Arch != "amd64" && options.Arch != "arm64" {
		return nil, fmt.Errorf("seccomp layer does not support architecture %q", options.Arch)
	}
	if options.NRISocket == "" {
		options.NRISocket = nriapi.DefaultSocketPath
	}
	if options.OnError == nil {
		options.OnError = func(error) {}
	}
	empty := []sandboxpolicy.PolicyView{}
	s := &Service{options: options, containers: map[string]*tracked{}, unsupport: map[types.UID][]Unsupported{}, namespaces: map[string]namespaceEntry{}, wake: make(chan struct{}, 1), attempted: make(chan struct{})}
	s.policies.Store(&empty)
	s.setNRIProblem("NRI unavailable")
	s.policyDirty.Store(true)
	return s, nil
}

// Start keeps the NRI connection and a refresh loop running until ctx ends. It
// does not wait for NRI: a node without NRI uses the fallback files.
func (s *Service) Start(ctx context.Context) error {
	node, err := s.options.Kubernetes.CoreV1().Nodes().Get(ctx, s.options.NodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("seccomp layer node identity: %w", err)
	}
	s.node = api.NodeReference{Name: node.Name, UID: node.UID}
	go s.runNRI(ctx)
	go func() {
		select {
		case <-s.attempted:
		case <-time.After(firstAttemptWait):
		case <-ctx.Done():
		}
		s.refresh(ctx)
		ticker := time.NewTicker(refreshPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-s.wake:
			}
			s.refresh(ctx)
		}
	}()
	return nil
}

// Watch events only mark the policies for a fresh list; the list is authoritative.
func (s *Service) WatchResources() []watcher.WatchResource {
	return []watcher.WatchResource{watcher.NewWatchResource(sandboxpolicy.PolicyGVR, metav1.ListOptions{}), watcher.NewWatchResource(sandboxpolicy.ClusterPolicyGVR, metav1.ListOptions{})}
}
func (s *Service) AddHandler(context.Context, runtime.Object)    { s.policyChanged() }
func (s *Service) ModifyHandler(context.Context, runtime.Object) { s.policyChanged() }
func (s *Service) DeleteHandler(context.Context, runtime.Object) { s.policyChanged() }

func (s *Service) policyChanged() {
	s.policyDirty.Store(true)
	s.Wake()
}

// Wake asks for a refresh.
func (s *Service) Wake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Service) setNRIProblem(reason string) { s.nriProblem.Store(&reason) }

func (s *Service) runNRI(ctx context.Context) {
	for ctx.Err() == nil {
		plugin, err := stub.New(s, stub.WithPluginName(pluginName), stub.WithPluginIdx(pluginIndex), stub.WithSocketPath(s.options.NRISocket),
			stub.WithOnClose(func() { s.nriActive.Store(false) }))
		if err == nil {
			err = plugin.Run(ctx)
		}
		s.nriActive.Store(false)
		s.markAttempted()
		if err != nil && ctx.Err() == nil {
			s.options.OnError(fmt.Errorf("seccomp layer NRI connection: %w", err))
		}
		select {
		case <-ctx.Done():
		case <-time.After(reconnectDelay):
		}
	}
}

// Configure checks that the runtime can apply a seccomp adjustment. An older
// runtime may accept the adjustment and silently drop the profile, so the
// layer then stays on the fallback files.
func (s *Service) Configure(_ context.Context, _, runtimeName, version string) (stub.EventMask, error) {
	if ok, need := runtimeSupportsSeccomp(runtimeName, version); !ok {
		s.setNRIProblem(fmt.Sprintf("%s %s cannot inject seccomp profiles through NRI (needs %s)", runtimeName, version, need))
		return 0, fmt.Errorf("runtime %s %s does not support seccomp adjustment", runtimeName, version)
	}
	s.setNRIProblem("NRI unavailable")
	return 0, nil
}

// runtimeSupportsSeccomp: seccomp adjustment exists from containerd 2.2.0 and
// CRI-O 1.34.0.
func runtimeSupportsSeccomp(name, version string) (bool, string) {
	need := map[string][2]int{"containerd": {2, 2}, "cri-o": {1, 34}, "crio": {1, 34}}
	min, known := need[strings.ToLower(name)]
	if !known {
		return false, "containerd >= 2.2.0 or CRI-O >= 1.34.0"
	}
	want := fmt.Sprintf("%s >= %d.%d.0", name, min[0], min[1])
	parts := strings.SplitN(strings.TrimPrefix(version, "v"), ".", 3)
	if len(parts) < 2 {
		return false, want
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false, want
	}
	return major > min[0] || (major == min[0] && minor >= min[1]), want
}

// Synchronize receives every existing container when the plugin registers.
func (s *Service) Synchronize(_ context.Context, pods []*nriapi.PodSandbox, containers []*nriapi.Container) ([]*nriapi.ContainerUpdate, error) {
	byID := make(map[string]*nriapi.PodSandbox, len(pods))
	for _, p := range pods {
		byID[p.GetId()] = p
	}
	s.mu.Lock()
	s.containers = make(map[string]*tracked, len(containers))
	for _, c := range containers {
		if c.GetState() == nriapi.ContainerState_CONTAINER_STOPPED {
			continue
		}
		if p := byID[c.GetPodSandboxId()]; p != nil {
			s.containers[c.GetId()] = &tracked{namespace: p.GetNamespace(), pod: p.GetName(), podUID: p.GetUid(), container: c.GetName(), info: runtimeInfo(c), applied: c.GetAnnotations()[AnnotationKey]}
		}
	}
	s.mu.Unlock()
	s.nriActive.Store(true)
	s.markAttempted()
	s.Wake()
	return nil, nil
}

func (s *Service) markAttempted() { s.attemptMu.Do(func() { close(s.attempted) }) }

// CreateContainer injects the profile. It never fails container creation: a
// container it cannot protect is reported as pending instead. It only reads
// caches, with short bounded lookups, to stay within NRI's request timeout.
func (s *Service) CreateContainer(ctx context.Context, pod *nriapi.PodSandbox, ctr *nriapi.Container) (*nriapi.ContainerAdjustment, []*nriapi.ContainerUpdate, error) {
	entry := &tracked{namespace: pod.GetNamespace(), pod: pod.GetName(), podUID: pod.GetUid(), container: ctr.GetName(), info: runtimeInfo(ctr)}
	defer func() {
		s.mu.Lock()
		s.containers[ctr.GetId()] = entry
		s.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(ctx, 2*hotPathLimit)
	defer cancel()
	if s.policyDirty.Load() {
		// a policy changed and the refresh has not run yet: decide on the new set
		s.reloadPolicies(ctx)
	}
	k8sPod := s.lookupPod(ctx, pod.GetNamespace(), pod.GetName(), pod.GetUid(), hotPathLimit)
	if k8sPod == nil {
		s.options.OnError(fmt.Errorf("seccomp layer: pod %s/%s not found at container creation", pod.GetNamespace(), pod.GetName()))
		return nil, nil, nil
	}
	want, err := s.desiredFor(ctx, k8sPod, ctr.GetName(), entry.info, true, hotPathLimit)
	if err != nil || want == nil {
		var skipped errSkipped
		if err != nil && !errors.As(err, &skipped) {
			s.options.OnError(fmt.Errorf("seccomp layer %s/%s/%s: %w", pod.GetNamespace(), pod.GetName(), ctr.GetName(), err))
		}
		return nil, nil, nil
	}
	adjust := &nriapi.ContainerAdjustment{}
	adjust.SetLinuxSeccompPolicy(nriapi.FromOCILinuxSeccomp(want.profile))
	adjust.AddAnnotation(AnnotationKey, want.revision)
	entry.applied, entry.index = want.revision, want.index
	return adjust, nil, nil
}

// StopContainer forgets a container: a restart creates a new one.
func (s *Service) StopContainer(_ context.Context, _ *nriapi.PodSandbox, ctr *nriapi.Container) ([]*nriapi.ContainerUpdate, error) {
	s.forget(ctr.GetId())
	return nil, nil
}

func (s *Service) RemoveContainer(_ context.Context, _ *nriapi.PodSandbox, ctr *nriapi.Container) error {
	s.forget(ctr.GetId())
	return nil
}

func (s *Service) forget(id string) {
	s.mu.Lock()
	delete(s.containers, id)
	s.mu.Unlock()
}

// runtimeInfo reads what the runtime reports before adjustment. containerd
// reports the kind, and for RuntimeDefault also the exact profile.
func runtimeInfo(ctr *nriapi.Container) RuntimeInfo {
	linux := ctr.GetLinux()
	profile, policy := linux.GetSeccompProfile(), linux.GetSeccompPolicy()
	if profile == nil && policy == nil {
		return RuntimeInfo{}
	}
	info := RuntimeInfo{Known: true, Kind: RuntimeProfileRuntimeDefault, Policy: toOCI(policy)}
	switch profile.GetProfileType() {
	case nriapi.SecurityProfile_UNCONFINED:
		info.Kind = RuntimeProfileUnconfined
	case nriapi.SecurityProfile_LOCALHOST:
		info.Kind = RuntimeProfileLocalhost
	}
	return info
}

func toOCI(p *nriapi.LinuxSeccomp) *specs.LinuxSeccomp {
	if p == nil {
		return nil
	}
	// nriapi.ToOCILinuxSyscalls (v0.10) dereferences a nil pointer for any entry
	// with an errno, so convert here.
	out := &specs.LinuxSeccomp{DefaultAction: specs.LinuxSeccompAction(p.DefaultAction), ListenerPath: p.ListenerPath, ListenerMetadata: p.ListenerMetadata}
	for _, sc := range p.Syscalls {
		entry := specs.LinuxSyscall{Names: append([]string(nil), sc.Names...), Action: specs.LinuxSeccompAction(sc.Action), Args: nriapi.ToOCILinuxSeccompArgs(sc.Args)}
		if sc.ErrnoRet != nil {
			errno := uint(sc.ErrnoRet.Value)
			entry.ErrnoRet = &errno
		}
		out.Syscalls = append(out.Syscalls, entry)
	}
	if p.DefaultErrno != nil {
		errno := uint(p.DefaultErrno.Value)
		out.DefaultErrnoRet = &errno
	}
	for _, a := range p.Architectures {
		out.Architectures = append(out.Architectures, specs.Arch(a))
	}
	for _, f := range p.Flags {
		out.Flags = append(out.Flags, specs.LinuxSeccompFlag(f))
	}
	return out
}

// lookupPod returns the pod with this UID. The cache can still hold a deleted
// pod of the same name, so a UID mismatch falls back to the API server.
func (s *Service) lookupPod(ctx context.Context, namespace, name, uid string, limit time.Duration) *corev1.Pod {
	if pod := s.options.Pods(namespace, name); pod != nil && string(pod.UID) == uid {
		return pod
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	pod, err := s.options.Kubernetes.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil || string(pod.UID) != uid {
		return nil
	}
	return pod
}

func (s *Service) namespaceLabels(ctx context.Context, name string, limit time.Duration) (map[string]string, error) {
	s.mu.Lock()
	cached, ok := s.namespaces[name]
	s.mu.Unlock()
	if ok && time.Since(cached.fetched) < namespaceTTL {
		return cached.labels, nil
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	ns, err := s.options.Kubernetes.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if ok {
			return cached.labels, nil // stale labels beat a missing profile
		}
		return nil, err
	}
	s.mu.Lock()
	s.namespaces[name] = namespaceEntry{labels: ns.Labels, fetched: time.Now()}
	s.mu.Unlock()
	return ns.Labels, nil
}

// desiredFor returns nil when no active policy asks for anything in this
// container. A container whose own profile must be kept returns errSkipped.
// When injecting, an assumed base is not good enough: replacing a profile the
// kubelet may have chosen could loosen it.
func (s *Service) desiredFor(ctx context.Context, pod *corev1.Pod, name string, info RuntimeInfo, injecting bool, limit time.Duration) (*desired, error) {
	container, ok := ResolveContainer(pod, name, info)
	if !ok {
		return nil, fmt.Errorf("container %q is not in the pod spec", name)
	}
	nsLabels, err := s.namespaceLabels(ctx, pod.Namespace, limit)
	if err != nil {
		return nil, fmt.Errorf("namespace labels: %w", err)
	}
	binding := sandboxpolicy.Binding{Namespace: pod.Namespace, PodName: pod.Name, PodUID: pod.UID, ContainerName: name, Kind: container.Kind, PodLabels: pod.Labels, NamespaceLabels: nsLabels}
	var rules []Rule
	for _, view := range *s.policies.Load() {
		if !view.Matches(binding) {
			continue
		}
		if s.options.ExecEnforcement && view.Spec.Mode == api.ModeEnforce && (view.Spec.Exec != nil || len(view.Spec.Sources) > 0) {
			rules = append(rules, RootBarrierRules(view.Identity)...)
		}
		compiled, err := CompilePolicy(view.Identity, view.Spec)
		if err != nil {
			continue // reported per policy by refresh
		}
		rules = append(rules, compiled.Rules...)
	}
	if len(rules) == 0 {
		return nil, nil
	}
	if container.Skip == "" && injecting && container.Assumed {
		container.Skip = "runtime did not report the container's seccomp profile"
	}
	if container.Skip != "" {
		return &desired{rules: ruleModes(rules)}, errSkipped{container.Skip}
	}
	in := Input{Base: container.Base, Arch: s.options.Arch, Default: container.Default}
	if container.Base == BaseRuntimeDefault && in.Default == nil {
		in.Default = s.options.RuntimeDefault(container.Capabilities)
	}
	profile, notes, err := Build(in, rules)
	if err != nil {
		return &desired{rules: ruleModes(rules)}, err
	}
	data, err := json.Marshal(profile)
	if err != nil {
		return &desired{rules: ruleModes(rules)}, err
	}
	sum := sha256.Sum256(data)
	return &desired{revision: hex.EncodeToString(sum[:8]), base: container.Base, profile: profile, rules: ruleModes(rules), index: matchIndex(rules), notes: notes}, nil
}

func ruleModes(rules []Rule) map[types.UID]map[string]api.RuleMode {
	out := map[types.UID]map[string]api.RuleMode{}
	for _, r := range rules {
		if out[r.Policy.UID] == nil {
			out[r.Policy.UID] = map[string]api.RuleMode{}
		}
		out[r.Policy.UID][r.Name] = stronger(out[r.Policy.UID][r.Name], r.Mode)
	}
	return out
}

func matchIndex(rules []Rule) map[string][]Match {
	out := map[string][]Match{}
	for _, r := range rules {
		for _, name := range r.Syscalls {
			out[name] = append(out[name], Match{Policy: r.Policy, Rule: r.Name, Origin: r.Origin, Mode: r.Mode, Flags: r.Flags})
		}
	}
	return out
}

type errSkipped struct{ reason string }

func (e errSkipped) Error() string { return e.reason }

// refresh finds containers whose running profile is not the desired one,
// writes fallback files and reports. Policies are listed after a watch event
// and periodically, never on every tick.
func (s *Service) refresh(ctx context.Context) {
	listed := true
	s.mu.Lock()
	due := time.Since(s.listed) >= policyListPeriod
	s.mu.Unlock()
	if s.policyDirty.Load() || due {
		listed = s.reloadPolicies(ctx)
	}
	var next []pending
	notes := map[types.UID][]string{}
	if s.nriActive.Load() {
		next = s.pendingFromNRI(ctx, notes)
	} else {
		next = s.pendingFromPods(ctx, notes)
	}
	s.mu.Lock()
	s.pending, s.notes = next, notes
	s.mu.Unlock()
	if !s.options.Contributes && s.options.Writer != nil && listed {
		s.writeReports(ctx, *s.policies.Load())
	}
}

// reloadPolicies lists the policies. A failed list keeps the last coherent set
// and the dirty mark; it is never treated as an empty set.
func (s *Service) reloadPolicies(ctx context.Context) bool {
	s.policyDirty.Store(false)
	views, unsupported, err := s.loadPolicies(ctx)
	if err != nil {
		s.policyDirty.Store(true)
		s.options.OnError(fmt.Errorf("seccomp layer policy list: %w", err))
		return false
	}
	s.policies.Store(&views)
	s.mu.Lock()
	s.unsupport, s.listed = unsupported, time.Now()
	s.pruneNamespaces()
	s.mu.Unlock()
	return true
}

func (s *Service) pruneNamespaces() {
	for name, entry := range s.namespaces {
		if time.Since(entry.fetched) > 10*namespaceTTL {
			delete(s.namespaces, name)
		}
	}
}

func (s *Service) loadPolicies(ctx context.Context) ([]sandboxpolicy.PolicyView, map[types.UID][]Unsupported, error) {
	var views []sandboxpolicy.PolicyView
	unsupported := map[types.UID][]Unsupported{}
	for _, gvr := range []schema.GroupVersionResource{sandboxpolicy.PolicyGVR, sandboxpolicy.ClusterPolicyGVR} {
		list, err := s.options.Dynamic.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, nil, err
		}
		for i := range list.Items {
			view := sandboxpolicy.ParsePolicy(&list.Items[i])
			views = append(views, view)
			if view.Err != nil || view.Spec.Privilege == nil {
				continue
			}
			compiled, err := CompilePolicy(view.Identity, view.Spec)
			if err != nil {
				unsupported[view.Identity.UID] = []Unsupported{{Policy: view.Identity, Rule: "privilege", Reason: err.Error()}}
				continue
			}
			unsupported[view.Identity.UID] = compiled.Unsupported
		}
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Identity.UID < views[j].Identity.UID })
	return views, unsupported, nil
}

// classify turns the desired state of a selected container into a pending
// entry, or nil when the container runs the desired profile.
func classify(id string, want *desired, err error, applied string, optedIn func(string) bool) *pending {
	var skipped errSkipped
	switch {
	case errors.As(err, &skipped):
		return &pending{container: id, reason: skipped.reason, rules: want.rules}
	case err != nil && want != nil:
		return &pending{container: id, reason: "cannot build the profile: " + err.Error(), rules: want.rules}
	case err != nil || want == nil || want.revision == applied:
		return nil
	case optedIn(FallbackFile(want.base, want.revision)):
		return nil
	case applied == "":
		return &pending{container: id, reason: "container started before the policy or while node-agent was unavailable", rules: want.rules}
	}
	return &pending{container: id, reason: "policy changed after the container started", rules: want.rules}
}

// addNotes records Build's limitation notes for every policy in the profile.
func addNotes(notes map[types.UID][]string, want *desired) {
	if want == nil {
		return
	}
	for uid := range want.rules {
		notes[uid] = append(notes[uid], want.notes...)
	}
}

func (s *Service) pendingFromNRI(ctx context.Context, notes map[types.UID][]string) []pending {
	s.mu.Lock()
	containers := make(map[string]tracked, len(s.containers))
	for id, c := range s.containers {
		containers[id] = *c
	}
	s.mu.Unlock()
	var out []pending
	for id, c := range containers {
		pod := s.lookupPod(ctx, c.namespace, c.pod, c.podUID, lookupLimit)
		if pod == nil {
			continue
		}
		want, err := s.desiredFor(ctx, pod, c.container, c.info, true, lookupLimit)
		addNotes(notes, want)
		if err == nil && want != nil && want.revision == c.applied && c.index == nil {
			// recovered after a restart: attribute events with the applied rules
			s.mu.Lock()
			if entry := s.containers[id]; entry != nil {
				entry.index = want.index
			}
			s.mu.Unlock()
		}
		optedIn := func(file string) bool { return referencesFile(pod, c.container, file) }
		if p := classify(c.namespace+"/"+c.pod+"/"+c.container, want, err, c.applied, optedIn); p != nil {
			out = append(out, *p)
		}
	}
	return out
}

// pendingFromPods handles nodes where NRI is unavailable: every selected
// container is pending unless it references its fallback file, which is
// written here. Pods are listed every podListPeriod, not every tick.
func (s *Service) pendingFromPods(ctx context.Context, notes map[types.UID][]string) []pending {
	s.mu.Lock()
	due := time.Since(s.podsListed) >= podListPeriod
	pods := s.nodePods
	s.mu.Unlock()
	if due {
		list, err := s.options.Kubernetes.CoreV1().Pods("").List(ctx, metav1.ListOptions{FieldSelector: "spec.nodeName=" + s.options.NodeName})
		if err != nil {
			s.options.OnError(fmt.Errorf("seccomp layer pod list: %w", err))
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.pending
		}
		pods = list.Items
		s.mu.Lock()
		s.nodePods, s.podsListed = pods, time.Now()
		s.mu.Unlock()
	}
	problem := *s.nriProblem.Load()
	keep := map[string]bool{}
	var out []pending
	for i := range pods {
		pod := &pods[i]
		if pod.Status.Phase != corev1.PodRunning && pod.Status.Phase != corev1.PodPending {
			continue
		}
		names := make([]string, 0, len(pod.Spec.InitContainers)+len(pod.Spec.Containers)+len(pod.Spec.EphemeralContainers))
		for _, c := range pod.Spec.InitContainers {
			names = append(names, c.Name)
		}
		for _, c := range pod.Spec.Containers {
			names = append(names, c.Name)
		}
		for _, c := range pod.Spec.EphemeralContainers {
			names = append(names, c.Name)
		}
		for _, name := range names {
			if file, ok := localhostFile(pod, name); ok {
				keep[file] = true
			}
			want, err := s.desiredFor(ctx, pod, name, RuntimeInfo{}, false, lookupLimit)
			addNotes(notes, want)
			id := pod.Namespace + "/" + pod.Name + "/" + name
			if err == nil && want != nil {
				file := FallbackFile(want.base, want.revision)
				keep[file] = true
				if err := s.writeFallback(file, want.profile); err != nil {
					s.options.OnError(err)
				}
				if referencesFile(pod, name, file) {
					continue
				}
				out = append(out, pending{container: id, reason: problem + "; reference Localhost profile " + file + " to apply", rules: want.rules})
				continue
			}
			if p := classify(id, want, err, "", func(string) bool { return false }); p != nil {
				out = append(out, *p)
			}
		}
	}
	if due {
		s.cleanFallback(keep)
	}
	return out
}

func localhostFile(pod *corev1.Pod, container string) (string, bool) {
	var profile *corev1.SeccompProfile
	if pod.Spec.SecurityContext != nil {
		profile = pod.Spec.SecurityContext.SeccompProfile
	}
	if c, _, ok := findContainer(pod, container); ok && c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil {
		profile = c.SecurityContext.SeccompProfile
	}
	if profile == nil || profile.Type != corev1.SeccompProfileTypeLocalhost || profile.LocalhostProfile == nil {
		return "", false
	}
	return *profile.LocalhostProfile, true
}

func referencesFile(pod *corev1.Pod, container, file string) bool {
	got, ok := localhostFile(pod, container)
	return ok && got == file
}

func (s *Service) writeFallback(file string, profile *specs.LinuxSeccomp) error {
	if s.options.ProfilesDir == "" {
		return nil
	}
	path := filepath.Join(s.options.ProfilesDir, file)
	if _, err := os.Stat(path); err == nil {
		return nil // content-addressed: an existing file is already correct
	}
	data, err := json.Marshal(profile)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// cleanFallback removes old fallback files that no pod on the node uses or
// could use now.
func (s *Service) cleanFallback(keep map[string]bool) {
	if s.options.ProfilesDir == "" {
		return
	}
	dir := filepath.Join(s.options.ProfilesDir, FallbackDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if _, own := fallbackBase(FallbackDir + "/" + name); !own || !strings.HasSuffix(name, ".json") || keep[FallbackDir+"/"+name] {
			continue
		}
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > fallbackGrace {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}

// Condition types this layer adds to a policy's node report.
const (
	ConditionAppliesOnRestart = "SeccompAppliesOnRestart"
	ConditionUnsupported      = "SeccompRulesNotEnforced"
)

// Contribute reports, for one policy, the rules waiting for a container restart
// with the reasons, and the rules seccomp cannot express.
func (s *Service) Contribute(policy types.UID) ([]string, []metav1.Condition) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var names []string
	reasons := map[string]int{} // reason -> containers
	for _, p := range s.pending {
		if len(p.rules[policy]) == 0 {
			continue
		}
		reasons[p.reason]++
		for rule := range p.rules[policy] {
			names = append(names, rule)
		}
	}
	var conditions []metav1.Condition
	if len(reasons) > 0 {
		ordered := make([]string, 0, len(reasons))
		for reason, count := range reasons {
			ordered = append(ordered, fmt.Sprintf("%d container(s): %s", count, reason))
		}
		sort.Strings(ordered)
		conditions = append(conditions, metav1.Condition{Type: ConditionAppliesOnRestart, Status: metav1.ConditionTrue, Reason: "ContainersNeedRestart", Message: bounded(strings.Join(ordered, "; "))})
	}
	if unsupported, notes := s.unsupport[policy], sortedUnique(s.notes[policy]); len(unsupported)+len(notes) > 0 {
		parts := make([]string, 0, len(unsupported)+len(notes))
		for _, u := range unsupported {
			parts = append(parts, u.Rule+": "+u.Reason)
		}
		parts = append(parts, notes...)
		conditions = append(conditions, metav1.Condition{Type: ConditionUnsupported, Status: metav1.ConditionTrue, Reason: "NotExpressibleInSeccomp", Message: bounded(strings.Join(parts, "; "))})
	}
	return sortedUnique(names), conditions
}

type staticContributor struct {
	pending    []string
	conditions []metav1.Condition
}

func (c staticContributor) Contribute(types.UID) ([]string, []metav1.Condition) {
	return c.pending, c.conditions
}

// bounded cuts a condition message to the CRD limit on a rune boundary.
func bounded(text string) string {
	if len(text) <= api.MaxStatusDiagnosticLength {
		return text
	}
	cut := api.MaxStatusDiagnosticLength - len("…")
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + "…"
}

// writeReports is used when the exec controller is disabled, so the seccomp
// layer is the only writer of this node's reports.
func (s *Service) writeReports(ctx context.Context, views []sandboxpolicy.PolicyView) {
	now := metav1.Now()
	for _, view := range views {
		if view.Err != nil || view.Spec.Privilege == nil {
			continue
		}
		status := &api.NodeStatus{Tier: "seccomp-only", ObservedGeneration: view.Identity.Generation, LastReported: now}
		pending, conditions := s.Contribute(view.Identity.UID)
		// ContributeStatus turns Ready False when anything is pending or not enforced
		status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled", Message: "seccomp layer", ObservedGeneration: view.Identity.Generation, LastTransitionTime: now}}
		static := staticContributor{pending: pending, conditions: conditions}
		sandboxpolicy.ContributeStatus(status, view.Identity.UID, view.Identity.Generation, now, static)
		namespace := view.Identity.Namespace
		if view.Identity.Kind == "ClusterSandboxPolicy" {
			namespace = s.options.AgentNamespace
		}
		report := &api.SandboxPolicyNodeStatus{
			TypeMeta:   metav1.TypeMeta{APIVersion: api.SchemeGroupVersion.String(), Kind: "SandboxPolicyNodeStatus"},
			ObjectMeta: metav1.ObjectMeta{Name: api.NodeStatusName(view.Identity.UID, s.node.UID), Namespace: namespace, OwnerReferences: []metav1.OwnerReference{{APIVersion: api.SchemeGroupVersion.String(), Kind: view.Identity.Kind, Name: view.Identity.Name, UID: view.Identity.UID}}},
			Spec:       api.SandboxPolicyNodeStatusSpec{PolicyRef: api.SandboxPolicyReference{Kind: view.Identity.Kind, Name: view.Identity.Name, UID: view.Identity.UID}, NodeRef: s.node},
			Status:     status,
		}
		if err := s.options.Writer.WriteStatus(ctx, report); err != nil {
			s.options.OnError(fmt.Errorf("seccomp layer status: %w", err))
		}
	}
}
