package sandboxpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kubescape/node-agent/pkg/watcher"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

var PolicyGVR = api.SchemeGroupVersion.WithResource("sandboxpolicies")
var ClusterPolicyGVR = api.SchemeGroupVersion.WithResource("clustersandboxpolicies")
var ClassesGVR = api.SchemeGroupVersion.WithResource("sandboxpolicyclasses")
var NodeStatusGVR = api.SchemeGroupVersion.WithResource("sandboxpolicynodestatuses")

// Options identifies this node and the namespace for cluster-policy reports.
type Options struct {
	Node           api.NodeReference
	AgentNamespace string
	// File describes the node for the file translation.
	File FileNode
	// EnforcementUnavailable says why no section can enforce or audit on this
	// node (for example, BPF LSM is not active). It comes from a probe at startup;
	// nil means the probe passed.
	EnforcementUnavailable error
	// KernelRuntime re-reads the kernel controls that can change while the
	// agent runs (ftrace, livepatch) for a loaded section. It is called at
	// every status write; an error means no binding of that section is
	// protected. Nil: no check.
	KernelRuntime func(section string) error
}

type installed struct {
	binding               Binding
	plan                  Plan
	cleanupPending        bool
	protectionUnconfirmed bool
}

type Controller struct {
	mu           sync.Mutex
	client       dynamic.Interface
	backend      Backend
	resolver     SourceResolver
	writer       StatusWriter
	options      Options
	objects      map[string]*unstructured.Unstructured
	bindings     map[string]Binding
	active       map[string]installed
	withdrawals  map[string]installed
	lastError    error
	bindingError error
	configError  error
	// clusterCIDRs fills the clusterInternal class (SetClusterCIDRs).
	clusterCIDRs ClusterCIDRs
	// readClusterCIDRs, when set, reads the class (SetClusterCIDRsReader).
	readClusterCIDRs func(context.Context) (ClusterCIDRs, bool)
	// networkPlans holds the translated network section of each valid
	// policy from the last reconciliation, for status and preparation.
	networkPlans map[types.UID]*NetworkPlan
	// filePlans holds the translated file section of each valid policy.
	filePlans map[types.UID]*FilePlan
	// podLastGood is the last plan PodPlans computed for each pod (not the
	// plan a backend bound): a policy that fails keeps its version there, as
	// a container binding keeps its last-good compiled policy. PodPlans
	// replaces the map on each call, so it must be given every pod on the
	// node; a pod left out loses its entry.
	podLastGood map[types.UID]Plan
	// classes and classErrors are from the last reconcile (see PodPlans).
	classes     api.PolicyClasses
	classErrors map[string]error
	// bindingPending is a non-fatal *BindingPendingError from the last snapshot:
	// its bindings were applied, but every policy stays Ready False.
	bindingPending error
	// failedBindings counts, per policy UID, the bindings of the last
	// reconcile that selected the policy and failed to apply it.
	failedBindings map[string]int
	// stopped: StopReporting ran; no status is written after it.
	stopped atomic.Bool
	// Refresh publishes immutable versions so watch handlers can check them
	// without waiting for reconciliation or backend operations.
	configurationVersions atomic.Pointer[map[types.UID]string]
}

var _ watcher.Adaptor = (*Controller)(nil)

func NewController(client dynamic.Interface, backend Backend, resolver SourceResolver, writer StatusWriter, options Options) (*Controller, error) {
	if client == nil || backend == nil {
		return nil, fmt.Errorf("dynamic client and backend are required")
	}
	if options.Node.Name == "" || options.Node.UID == "" || options.AgentNamespace == "" {
		return nil, fmt.Errorf("node name/UID and agent namespace are required")
	}
	return &Controller{client: client, backend: backend, resolver: resolver, writer: writer, options: options, objects: make(map[string]*unstructured.Unstructured), bindings: make(map[string]Binding), active: make(map[string]installed), withdrawals: make(map[string]installed)}, nil
}

func (*Controller) WatchResources() []watcher.WatchResource {
	return []watcher.WatchResource{watcher.NewWatchResource(PolicyGVR, metav1.ListOptions{}), watcher.NewWatchResource(ClusterPolicyGVR, metav1.ListOptions{}), watcher.NewWatchResource(ClassesGVR, metav1.ListOptions{})}
}

// InitialSync is also the reconnect/relist recovery path. A failed list never
// commits a partial snapshot or withdraws last-good enforcement.
func (c *Controller) InitialSync(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	snapshot, err := c.loadConfiguration(ctx)
	if err != nil {
		c.configError = err
		c.lastError = c.reconcile(ctx)
		return c.lastError
	}
	c.objects = snapshot
	c.configError = nil
	c.lastError = c.reconcile(ctx)
	return c.lastError
}

func (c *Controller) AddHandler(ctx context.Context, obj runtime.Object) { c.change(ctx, obj, false) }
func (c *Controller) ModifyHandler(ctx context.Context, obj runtime.Object) {
	c.change(ctx, obj, false)
}
func (c *Controller) DeleteHandler(ctx context.Context, obj runtime.Object) { c.change(ctx, obj, true) }

func (c *Controller) change(ctx context.Context, obj runtime.Object, deleted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		c.lastError = err
		return
	}
	u := &unstructured.Unstructured{Object: raw}
	switch u.GetKind() {
	case "SandboxPolicy", "ClusterSandboxPolicy", "SandboxPolicyClasses":
	default:
		return
	}
	// While a coherent configuration snapshot is unavailable, event payloads
	// cannot restore freshness or authorize any transition. Only InitialSync can.
	if c.configError != nil {
		c.lastError = c.reconcile(ctx)
		return
	}
	key := objectKey(u)
	previous := c.objects[key]
	if deleted {
		if previous == nil || previous.GetUID() != u.GetUID() {
			return
		}
		delete(c.objects, key)
	} else {
		if previous != nil && previous.GetUID() == u.GetUID() && previous.GetGeneration() > u.GetGeneration() {
			return
		}
		if previous != nil && previous.GetUID() == u.GetUID() && previous.GetGeneration() == u.GetGeneration() && digest(previous.Object["spec"]) == digest(u.Object["spec"]) {
			return
		}
		c.objects[key] = u.DeepCopy()
	}
	c.lastError = c.reconcile(ctx)
}

// SetBindings replaces an authoritative container snapshot. Call it on container,
// pod-label or namespace-label changes; absent entries are explicitly withdrawn.
// Snapshot subscriptions and live cgroup identity verification belong to the caller
// and Backend respectively. The controller never infers a binding from selectors.
func (c *Controller) SetBindings(ctx context.Context, bindings []Binding) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	next, err := validatedBindings(bindings)
	if err != nil {
		return c.rejectBindings(ctx, err)
	}
	c.bindingError = nil
	c.bindingPending = nil
	c.bindings = next
	c.lastError = c.reconcile(ctx)
	return c.lastError
}

// ReportBindingFailure retains the last authoritative snapshot and publishes
// NotReady when discovery or Kubernetes metadata cannot produce a complete one.
// Only a subsequent successful binding snapshot (SetBindings or Refresh) clears it.
func (c *Controller) ReportBindingFailure(ctx context.Context, failure error) error {
	if failure == nil {
		return fmt.Errorf("binding failure must be non-nil")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rejectBindings(ctx, failure)
}

// Reconcile retries failed backends/status writes and refreshes source imports.
// Invoke on referenced profile updates and periodically for status heartbeats.
func (c *Controller) Reconcile(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastError = c.reconcile(ctx)
	return c.lastError
}

// SetClusterCIDRs sets the pod and service CIDRs of the clusterInternal
// class. The next reconciliation uses them. It reports whether they changed.
func (c *Controller) SetClusterCIDRs(cidrs ClusterCIDRs) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	changed := !reflect.DeepEqual(c.clusterCIDRs, cidrs)
	c.clusterCIDRs = cidrs
	return changed
}

// SetClusterCIDRsReader sets the reader of the clusterInternal class. Refresh
// calls it after it loads a configuration in which an active policy names the
// class, and before it compiles, so the first compile of such a policy already
// has the class. read reports false when it did not read (for example, it
// limits how often it reads); the class then keeps its value. read runs under
// the reconciliation lock and must not call Controller methods.
func (c *Controller) SetClusterCIDRsReader(read func(context.Context) (ClusterCIDRs, bool)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readClusterCIDRs = read
}

// UsesClusterInternal reports whether an active policy names the
// clusterInternal class in a network rule or an except entry, so the caller
// reads the cluster CIDRs only when a policy needs them.
func (c *Controller) UsesClusterInternal() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.usesClusterInternal()
}

// usesClusterInternal is called with c.mu held.
func (c *Controller) usesClusterInternal() bool {
	names := func(t *api.NetworkTarget) bool {
		return t != nil && slices.Contains(t.DestClass, ClassClusterInternal)
	}
	for _, p := range c.slotPolicies() {
		if p.spec.Network == nil {
			continue
		}
		for _, r := range p.spec.Network.Rules {
			if names(&r.Target) {
				return true
			}
			for _, e := range r.Except {
				if names(e.Target) {
					return true
				}
			}
		}
	}
	return false
}

// PrepareScheduled passes, for every container of the given pods (scheduled to
// this node and not finished), the privilege, network and file policies it
// will get to a backend that can prepare them, then one plan per active policy with
// only that policy. So each section prepares a slot for each of its active
// policies before any pod matches it: from the first start of node-agent, and
// when a policy appears or changes. The pod plans come first, so a backend
// that cannot fit every slot keeps theirs. Before pods exist only the policies
// are known, so only a container matched by exactly one policy of a section
// finds its combination this way; a container matched by several policies of
// a section needs their combined slot, which the pod plan prepares once the
// pod is scheduled (an instance replacement). The subsets are not enumerated.
// It is a hint and changes no binding state.
func (c *Controller) PrepareScheduled(ctx context.Context, containers []Binding) error {
	c.mu.Lock()
	preparer, ok := c.backend.(SlotPreparer)
	if !ok || c.configError != nil {
		c.mu.Unlock()
		return nil
	}
	policies := c.slotPolicies()
	networkPlans, filePlans := c.networkPlans, c.filePlans
	c.mu.Unlock()
	active := map[string]bool{}
	for _, p := range policies {
		active[SectionPrivilege] = active[SectionPrivilege] || p.spec.Privilege != nil
		// A network section that did not translate loads no gadget.
		active[SectionNetwork] = active[SectionNetwork] || networkPlans[p.identity.UID] != nil
		active[SectionFile] = active[SectionFile] || filePlans[p.identity.UID] != nil
	}
	// slotPolicy returns the privilege, network and file sections of a policy,
	// and false when it has none (an untranslated network or file section
	// counts as none).
	slotPolicy := func(p desiredPolicy) (CompiledPolicy, bool) {
		compiled := CompiledPolicy{Identity: p.identity, Mode: p.spec.Mode, Privilege: p.spec.Privilege.DeepCopy(), Network: networkPlans[p.identity.UID], File: filePlans[p.identity.UID]}
		return compiled, compiled.Privilege != nil || compiled.Network != nil || compiled.File != nil
	}
	var nonEmpty []Plan
	for _, b := range containers {
		var plan Plan
		for _, p := range policies {
			if compiled, ok := slotPolicy(p); ok && p.matches(b) {
				plan.Policies = append(plan.Policies, compiled)
			}
		}
		if len(plan.Policies) > 0 {
			nonEmpty = append(nonEmpty, plan)
		}
	}
	for _, p := range policies {
		if compiled, ok := slotPolicy(p); ok {
			nonEmpty = append(nonEmpty, Plan{Policies: []CompiledPolicy{compiled}})
		}
	}
	// Outside c.mu: a preparation may start a gadget instance.
	if sections, ok := preparer.(SectionPreparer); ok {
		return sections.PrepareSections(ctx, nonEmpty, active)
	}
	return preparer.Prepare(ctx, nonEmpty)
}

// PodPlans returns the pod plan of each pod scheduled to this node (all its
// declared containers must be given). A pod plan is bound at the pod cgroup
// before the containers start, so a container is judged from its first
// command. It is built per section (privilege, network, file): a section is in the
// pod plan only when every declared container of the pod gets the same
// nonempty set of that section's policies, because a pod binding also judges
// every container of the pod. So a pod can have a network pod binding and no
// privilege one, or both. A pod with no such section has no pod plan. A
// container must also pass the checks that its own binding needs (see
// podContainerPlan), so a pod binding never applies a policy that the
// container binding refuses. As in reconcile, a policy that fails (invalid, a
// class error, does not compile) keeps its version from the pod's last plan,
// or is left out when it has none; the other policies still apply. A pod with
// too many policies gets an empty plan: keep its current pod binding, as a
// container binding keeps its plan. Only an authoritative result (containers
// with different policies, no policy of the section, a policy that needs a
// ContainerProfile) removes it. It returns false when the policies are not
// known (a configuration error).
func (c *Controller) PodPlans(containers []Binding) (map[types.UID]Plan, bool) {
	c.mu.Lock()
	if c.configError != nil {
		c.mu.Unlock()
		return nil, false
	}
	var policies []desiredPolicy
	for _, obj := range c.objects {
		if obj.GetKind() != "SandboxPolicyClasses" {
			p := parsePolicy(obj)
			// A network section that did not translate fails the container
			// binding too (see reconcile).
			if p.err == nil && p.spec.Network != nil && p.spec.Mode != api.ModeOff && c.networkPlans[p.identity.UID] == nil {
				p.err = fmt.Errorf("network section is not translated")
			}
			if p.err == nil && p.spec.File != nil && p.spec.Mode != api.ModeOff && c.filePlans[p.identity.UID] == nil {
				p.err = fmt.Errorf("file section is not translated")
			}
			policies = append(policies, p)
		}
	}
	classes, classErrors, networkPlans, filePlans, lastGood := c.classes, c.classErrors, c.networkPlans, c.filePlans, c.podLastGood
	c.mu.Unlock()
	containerPlans := map[types.UID][]Plan{}
	failed := map[types.UID]bool{}
	keep := map[types.UID]bool{}
	for _, b := range containers {
		plan, state := podContainerPlan(policies, classes, classErrors, networkPlans, filePlans, lastGood[b.PodUID].Policies, b)
		if state == podPlanKeep {
			keep[b.PodUID] = true
		}
		if failed[b.PodUID] {
			continue
		}
		if state != podPlanReady {
			failed[b.PodUID] = true
			delete(containerPlans, b.PodUID)
			continue
		}
		containerPlans[b.PodUID] = append(containerPlans[b.PodUID], plan)
	}
	pods := map[types.UID]Plan{}
	for uid, plans := range containerPlans {
		if plan := podPlan(plans); len(plan.Policies) > 0 {
			pods[uid] = plan
		}
	}
	next := map[types.UID]Plan{}
	for uid, plan := range pods {
		next[uid] = plan
	}
	for uid := range keep {
		pods[uid] = Plan{} // incomplete input: keep the current binding
		if plan, ok := lastGood[uid]; ok {
			next[uid] = plan
		}
	}
	c.mu.Lock()
	c.podLastGood = next
	c.mu.Unlock()
	return pods, true
}

// podPlan keeps, from the container plans of one pod, each section whose
// policies are the same nonempty set in every container plan.
func podPlan(plans []Plan) Plan {
	only := func(plan Plan, part func(CompiledPolicy) any) Plan {
		var out Plan
		for _, p := range plan.Policies {
			if part(p) != nil {
				out.Policies = append(out.Policies, p)
			}
		}
		return out
	}
	keep := make([]bool, len(sectionParts))
	for i, sec := range sectionParts {
		first := only(plans[0], sec.part)
		keep[i] = len(first.Policies) > 0
		for _, plan := range plans[1:] {
			keep[i] = keep[i] && samePolicies(first, only(plan, sec.part))
		}
	}
	var out Plan
	for _, p := range plans[0].Policies {
		kept := false
		for i, sec := range sectionParts {
			if !keep[i] {
				sec.strip(&p)
			}
			kept = kept || sec.part(p) != nil
		}
		if kept {
			out.Policies = append(out.Policies, p)
		}
	}
	return out
}

type podPlanState int

const (
	podPlanNone  podPlanState = iota // no pod binding (authoritative)
	podPlanReady                     // the pod plan
	podPlanKeep                      // incomplete input: keep the current binding
)

// podContainerPlan returns the privilege, network and file policies of a
// container for a pod binding, with the checks of the container's own binding
// (reconcile). A policy that fails there (invalid and possibly selecting it, a
// class error, does not compile) keeps its version in lastGood (the pod's last
// plan), or is left out. Too many policies keep the current binding
// (podPlanKeep). A policy with sources depends on the ContainerProfile, which
// only the container binding resolves: no pod binding (podPlanNone).
func podContainerPlan(policies []desiredPolicy, classes api.PolicyClasses, classErrors map[string]error, networkPlans map[types.UID]*NetworkPlan, filePlans map[types.UID]*FilePlan, lastGood []CompiledPolicy, b Binding) (Plan, podPlanState) {
	var plan Plan
	selected := 0
	keepLastGood := func(p desiredPolicy) {
		for _, previous := range lastGood {
			if previous.Identity.UID == p.identity.UID {
				plan.Policies = append(plan.Policies, previous)
				return
			}
		}
	}
	for _, p := range policies {
		if p.err != nil {
			if p.identity.Kind == "SandboxPolicy" && p.identity.Namespace != b.Namespace {
				continue
			}
			selected++
			keepLastGood(p)
			continue
		}
		if p.spec.Mode == api.ModeOff || !p.matches(b) {
			continue
		}
		selected++
		if len(p.spec.Sources) > 0 {
			// Needs the ContainerProfile, which only the container binding
			// resolves.
			return Plan{}, podPlanNone
		}
		if policyClassError(p, classErrors) != nil {
			keepLastGood(p)
			continue
		}
		if _, err := Compile(context.Background(), p.identity, p.spec, classes, b, nil); err != nil {
			keepLastGood(p)
			continue
		}
		compiled := CompiledPolicy{Identity: p.identity, Mode: p.spec.Mode, Privilege: p.spec.Privilege.DeepCopy(), Network: networkPlans[p.identity.UID], File: filePlans[p.identity.UID]}
		if compiled.Privilege != nil || compiled.Network != nil || compiled.File != nil {
			plan.Policies = append(plan.Policies, compiled)
		}
	}
	if selected > MaxPoliciesPerBinding {
		return Plan{}, podPlanKeep
	}
	if len(plan.Policies) == 0 {
		return Plan{}, podPlanNone
	}
	return plan, podPlanReady
}

// policyClassError returns the errors of the shared path classes that p's exec
// rules use, as reconcile does (a class that p defines itself is not shared).
func policyClassError(p desiredPolicy, classErrors map[string]error) error {
	if p.spec.Exec == nil {
		return nil
	}
	var err error
	for _, rule := range p.spec.Exec.Rules {
		for _, name := range rule.Target.PathClass {
			if p.spec.Classes != nil {
				if _, local := p.spec.Classes.PathClasses[name]; local {
					continue
				}
			}
			err = errors.Join(err, classErrors[name])
		}
	}
	return err
}

// samePolicies compares the policy objects and generations of two plans.
func samePolicies(a, b Plan) bool {
	if len(a.Policies) != len(b.Policies) {
		return false
	}
	ids := map[PolicyIdentity]int{}
	for _, p := range a.Policies {
		ids[p.Identity]++
	}
	for _, p := range b.Policies {
		if ids[p.Identity] == 0 {
			return false
		}
		ids[p.Identity]--
	}
	return true
}

// HasSlotPolicies reports whether any active policy has a privilege, a
// network or a file section (the sections with node-wide slots).
func (c *Controller) HasSlotPolicies() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.slotPolicies()) > 0
}

// slotPolicies is called with c.mu held. They are sorted by UID.
func (c *Controller) slotPolicies() []desiredPolicy {
	var policies []desiredPolicy
	for _, obj := range c.objects {
		if obj.GetKind() == "SandboxPolicyClasses" {
			continue
		}
		if p := parsePolicy(obj); p.err == nil && (p.spec.Privilege != nil || p.spec.Network != nil || p.spec.File != nil) && p.spec.Mode != api.ModeOff {
			policies = append(policies, p)
		}
	}
	// A stable order: a backend that cannot fit every slot keeps the first.
	sort.Slice(policies, func(i, j int) bool { return policies[i].identity.UID < policies[j].identity.UID })
	return policies
}

func (c *Controller) LastError() error { c.mu.Lock(); defer c.mu.Unlock(); return c.lastError }

func bindingKey(b Binding) string {
	// Match backend ownership, with PodUID fencing Kubernetes object replacement.
	// Quote strings so embedded separators cannot alias another identity.
	return fmt.Sprintf("%q/%q/%q/%d/%d/%d/%q", b.Runtime, b.ContainerID, b.CgroupPath, b.CgroupID, b.MountNamespace, b.PID, b.PodUID)
}
func objectKey(u *unstructured.Unstructured) string {
	return u.GetKind() + "/" + u.GetNamespace() + "/" + u.GetName()
}
func cloneLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

type desiredPolicy struct {
	identity          PolicyIdentity
	spec              api.PolicySpec
	podSelector       labels.Selector
	namespaceSelector labels.Selector
	// identity is what the identity section cannot express
	// (expandIdentity); the section itself is moved into file and network.
	identityStatus identityReport
	err            error
}

// writeStatus writes p's report unless StopReporting ran (the agent is
// stopping: its AgentStopping report is the last one).
func (c *Controller) writeStatus(ctx context.Context, p desiredPolicy, report *api.SandboxPolicyNodeStatus) error {
	if c.stopped.Load() {
		return nil
	}
	return c.writer.WriteStatus(WithPolicyExec(ctx, p.hasExec()), report)
}

// AgentStoppingReason is the Ready reason of every exec policy's last report
// before a graceful agent stop withdraws enforcement.
const AgentStoppingReason = "AgentStopping"

// AgentStoppingTimeout bounds the AgentStopping writes once they start.
const AgentStoppingTimeout = 2500 * time.Millisecond

// StopReporting ends status reporting before a graceful stop withdraws
// enforcement: it writes Ready False (AgentStopping) for every exec policy
// this node reports, and no status afterwards. Policies without exec rules
// are not written. It returns when ctx ends, whatever a writer does. The
// AgentStopping writes wait for an in-flight reconciliation (the controller
// lock) and then run on their own context, bounded by AgentStoppingTimeout
// and not cancelled with ctx: when the caller stopped waiting for a slow
// reconciliation, AgentStopping still lands after its last write.
func (c *Controller) StopReporting(ctx context.Context) error {
	c.stopped.Store(true)
	done := make(chan error, 1)
	go func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), AgentStoppingTimeout)
		defer cancel()
		done <- c.reportStopping(writeCtx)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("agent stopping status: %w", ctx.Err())
	}
}

func (c *Controller) reportStopping(ctx context.Context) error {
	if c.writer == nil {
		return nil
	}
	var errs []error
	for _, obj := range c.objects {
		if obj.GetKind() == "SandboxPolicyClasses" {
			continue
		}
		p := parsePolicy(obj)
		if p.identity.UID == "" || !p.hasExec() {
			continue
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		report := c.report(p, nil)
		report.Status.Conditions[0].Status = metav1.ConditionFalse
		report.Status.Conditions[0].Reason = AgentStoppingReason
		report.Status.Conditions[0].Message = "node-agent is stopping; enforcement is withdrawn until it restarts"
		// Nothing is enforced once the agent is gone.
		report.Status.AppliedGeneration = 0
		if err := c.writer.WriteStatus(WithPolicyExec(ctx, true), report); err != nil {
			errs = append(errs, fmt.Errorf("write node status %s: %w", report.Name, err))
		}
	}
	return errors.Join(errs...)
}

// hasExec reports whether the policy carries active exec rules: it is not
// Off and has an exec section or ContainerProfile sources (they import
// execs). A policy that failed to decode or validate counts as one
// (fail-closed).
func (p desiredPolicy) hasExec() bool {
	return p.err != nil || (p.spec.Mode != api.ModeOff && (p.spec.Exec != nil || len(p.spec.Sources) != 0))
}

func decodeSpec(u *unstructured.Unstructured, target any) error {
	data, err := json.Marshal(u.Object["spec"])
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}
func parsePolicy(u *unstructured.Unstructured) desiredPolicy {
	p := desiredPolicy{identity: PolicyIdentity{Kind: u.GetKind(), Namespace: u.GetNamespace(), Name: u.GetName(), UID: u.GetUID(), Generation: u.GetGeneration()}}
	var pod metav1.LabelSelector
	if u.GetKind() == "SandboxPolicy" {
		var spec api.SandboxPolicySpec
		p.err = decodeSpec(u, &spec)
		p.spec = spec.PolicySpec
		pod = spec.Selector.PodSelector
		if p.err == nil {
			p.err = api.ValidateSandboxPolicySpec(spec)
		}
	} else {
		var spec api.ClusterSandboxPolicySpec
		p.err = decodeSpec(u, &spec)
		p.spec = spec.PolicySpec
		pod = spec.Selector.PodSelector
		if p.err == nil {
			p.err = api.ValidateClusterSandboxPolicySpec(spec)
		}
		if spec.Selector.NamespaceSelector != nil {
			selector, err := metav1.LabelSelectorAsSelector(spec.Selector.NamespaceSelector)
			p.namespaceSelector = selector
			p.err = errors.Join(p.err, err)
		}
	}
	selector, err := metav1.LabelSelectorAsSelector(&pod)
	p.podSelector = selector
	p.err = errors.Join(p.err, err)
	if err := validateShape(p.spec); err != nil {
		p.err = errors.Join(p.err, err)
	}
	if p.spec.Mode != api.ModeOff {
		spec, report, err := expandIdentity(p.spec)
		if err != nil {
			p.err = errors.Join(p.err, fmt.Errorf("identity: %w", err))
		}
		p.spec, p.identityStatus = spec, report
	}
	if p.spec.Network != nil && p.spec.Mode != api.ModeOff {
		if err := validateNetwork(*p.spec.Network); err != nil {
			p.err = errors.Join(p.err, fmt.Errorf("network: %w", err))
		}
	}
	if p.spec.File != nil && p.spec.Mode != api.ModeOff {
		if err := validateFile(*p.spec.File); err != nil {
			p.err = errors.Join(p.err, fmt.Errorf("file: %w", err))
		}
	}
	if p.identity.UID == "" {
		p.err = errors.Join(p.err, fmt.Errorf("policy UID is missing"))
	}
	return p
}

func (p desiredPolicy) matches(b Binding) bool {
	if p.identity.Kind == "SandboxPolicy" && p.identity.Namespace != b.Namespace {
		return false
	}
	if p.podSelector == nil || !p.podSelector.Matches(labels.Set(b.PodLabels)) {
		return false
	}
	if p.namespaceSelector != nil && !p.namespaceSelector.Matches(labels.Set(b.NamespaceLabels)) {
		return false
	}
	for _, name := range p.spec.Containers {
		if name == b.ContainerName || name == "*" && b.Kind == "regular" {
			return true
		}
	}
	return false
}

func (c *Controller) reconcile(ctx context.Context) error {
	if c.configError != nil {
		return c.reportConfigFailure(ctx)
	}
	if c.bindingError != nil {
		return c.reportBindingFailure(ctx, errors.Join(c.bindingError, c.withdrawDisabled(ctx)))
	}
	var failures []error
	policies := make([]desiredPolicy, 0)
	classes := api.PolicyClasses{PathClasses: make(map[string][]string)}
	dest := DestClasses{Shared: map[string][]string{}, Ambiguous: map[string]bool{}, Cluster: c.clusterCIDRs}
	destOwners := make(map[string]string)
	classErrors := make(map[string]error)
	// Reject an ambiguous multi-object class namespace rather than choose
	// one definition nondeterministically. Local policy additions are merged.
	classNames := make(map[string]string)
	keys := make([]string, 0, len(c.objects))
	for key := range c.objects {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		obj := c.objects[key]
		if obj.GetKind() != "SandboxPolicyClasses" {
			policies = append(policies, parsePolicy(obj))
			continue
		}
		var spec api.PolicyClasses
		if err := decodeSpec(obj, &spec); err != nil {
			failures = append(failures, fmt.Errorf("classes %s: %w", obj.GetName(), err))
			for name := range spec.PathClasses {
				classErrors[name] = errors.Join(classErrors[name], err)
			}
			continue
		}
		classValidationErr := api.ValidatePolicyClasses(spec)
		if err := classValidationErr; err != nil {
			failures = append(failures, fmt.Errorf("classes %s: %w", obj.GetName(), err))
			// The pinned API validator attributes this exact error only to an
			// empty name. Any other/unknown object-level failure remains atomic.
			if err.Error() == "class names must not be empty" {
				_, badPath := spec.PathClasses[""]
				_, badDest := spec.DestClasses[""]
				if badPath || badDest {
					classErrors[""] = errors.Join(classErrors[""], err)
					delete(spec.PathClasses, "")
					delete(spec.DestClasses, "")
					classValidationErr = api.ValidatePolicyClasses(spec)
				}
			}
			if classValidationErr != nil {
				for name := range spec.PathClasses {
					classErrors[name] = errors.Join(classErrors[name], err)
				}
				continue
			}
		}
		for name, paths := range spec.PathClasses {
			if owner, exists := classNames[name]; exists {
				classErrors[name] = errors.Join(classErrors[name], fmt.Errorf("path class %q occurs in %s and %s", name, owner, obj.GetName()))
				delete(classes.PathClasses, name)
				continue
			}
			classNames[name] = obj.GetName()
			classes.PathClasses[name] = paths
		}
		for name, entries := range spec.DestClasses {
			if _, exists := destOwners[name]; exists {
				dest.Ambiguous[name] = true
			}
			destOwners[name] = obj.GetName()
			dest.Shared[name] = entries
		}
	}
	c.classes, c.classErrors = classes, classErrors
	policyErrors := make(map[string]error)
	failedBindings := make(map[string]int)
	networkPlans := make(map[types.UID]*NetworkPlan)
	filePlans := make(map[types.UID]*FilePlan)
	for i := range policies {
		p := &policies[i]
		if p.err == nil && p.spec.Network != nil && p.spec.Mode != api.ModeOff {
			networkPlans[p.identity.UID], p.err = TranslateNetwork(p.spec, dest)
		}
		if p.err == nil && p.spec.File != nil && p.spec.Mode != api.ModeOff {
			filePlans[p.identity.UID], p.err = TranslateFile(p.spec, classes.PathClasses, c.options.File,
				IdentityFileRules{OtherProcess: p.identityStatus.OtherProcess, Provisioned: p.identityStatus.Provisioned})
		}
		if p.err != nil {
			policyErrors[string(p.identity.UID)] = p.err
			failures = append(failures, p.err)
		}
	}
	c.networkPlans, c.filePlans = networkPlans, filePlans

	// Finish committed removals before admitting a new plan for the same identity.
	// Tombstones are cleanup ownership only, never evidence of active protection.
	for _, old := range c.withdrawals {
		if err := c.withdraw(ctx, old); err != nil {
			failures = append(failures, err)
			for _, p := range old.plan.Policies {
				policyErrors[string(p.Identity.UID)] = errors.Join(policyErrors[string(p.Identity.UID)], err)
			}
		}
	}
	for key, old := range c.active {
		if _, ok := c.bindings[key]; !ok {
			if err := c.withdraw(ctx, old); err != nil {
				failures = append(failures, err)
				for _, p := range old.plan.Policies {
					policyErrors[string(p.Identity.UID)] = err
				}
			} else {
				delete(c.active, key)
			}
		}
	}
	for key, binding := range c.bindings {
		if c.bindingRetiring(key, binding) {
			for _, p := range policies {
				if p.err == nil && p.spec.Mode != api.ModeOff && p.matches(binding) {
					policyErrors[string(p.identity.UID)] = errors.Join(policyErrors[string(p.identity.UID)], &withdrawalCleanupError{fmt.Errorf("previous binding ownership must retire before installing policy")})
					failedBindings[string(p.identity.UID)]++
				}
			}
			continue
		}
		selected := make([]desiredPolicy, 0)
		for _, p := range policies {
			// Invalid revisions retain previous enforcement even when malformed selectors
			// cannot be evaluated. Only a valid off/delete/nonmatch authorizes withdrawal.
			if p.err != nil {
				if p.identity.Kind == "SandboxPolicy" && p.identity.Namespace != binding.Namespace {
					continue
				}
				selected = append(selected, p)
				continue
			}
			if p.spec.Mode != api.ModeOff && p.matches(binding) {
				selected = append(selected, p)
			}
		}
		old, hasOld := c.active[key]
		oldPolicies := make(map[string]CompiledPolicy)
		if hasOld {
			for _, compiled := range old.plan.Policies {
				oldPolicies[string(compiled.Identity.UID)] = compiled
			}
		}
		plan := Plan{}
		var candidateErr error
		failedHere := make(map[string]bool)
		if len(selected) > MaxPoliciesPerBinding {
			candidateErr = fmt.Errorf("binding exceeds %d policies", MaxPoliciesPerBinding)
		}
		for _, p := range selected {
			uid := string(p.identity.UID)
			err := p.err
			if err == nil {
				if p.spec.Exec != nil {
					for _, rule := range p.spec.Exec.Rules {
						for _, name := range rule.Target.PathClass {
							if p.spec.Classes != nil {
								if _, local := p.spec.Classes.PathClasses[name]; local {
									continue
								}
							}
							err = errors.Join(err, classErrors[name])
						}
					}
				}
			}
			if err == nil {
				compiled, compileErr := Compile(ctx, p.identity, p.spec, classes, binding, c.resolver)
				err = compileErr
				np, fp := networkPlans[p.identity.UID], filePlans[p.identity.UID]
				if err == nil && (np != nil || fp != nil) {
					compiled.Network, compiled.File, compiled.Revision = np, fp, ""
					compiled.Revision = digest(compiled)
				}
				if err == nil {
					plan.Policies = append(plan.Policies, compiled)
				}
			}
			if err != nil {
				policyErrors[uid] = errors.Join(policyErrors[uid], err)
				candidateErr = errors.Join(candidateErr, err)
				failedHere[uid] = true
				if previous, ok := oldPolicies[uid]; ok {
					plan.Policies = append(plan.Policies, previous)
				}
			}
		}
		if candidateErr != nil {
			failures = append(failures, candidateErr)
		}
		plan.Revision = digest(plan.Policies)
		var backendErr error
		if len(selected) > MaxPoliciesPerBinding {
			backendErr = candidateErr
			if hasOld {
				backendErr = errors.Join(backendErr, c.attest(ctx, old))
			}
		} else if len(plan.Policies) > 0 {
			// Same-plan Replace is an attestation/cleanup retry, not a gadget restart.
			// Never infer current protection merely from a prior successful revision.
			backendErr = c.replace(ctx, binding, plan)
		} else if hasOld {
			backendErr = c.withdraw(ctx, old)
		}
		if backendErr != nil {
			failures = append(failures, backendErr)
			for _, p := range selected {
				uid := string(p.identity.UID)
				policyErrors[uid] = errors.Join(policyErrors[uid], backendErr)
				failedHere[uid] = true
			}
			for _, p := range old.plan.Policies {
				uid := string(p.Identity.UID)
				policyErrors[uid] = errors.Join(policyErrors[uid], backendErr)
			}
		}
		for uid := range failedHere {
			failedBindings[uid]++
		}
	}
	c.failedBindings = failedBindings
	if c.writer != nil {
		for _, p := range policies {
			if p.identity.UID == "" {
				continue
			}
			failure := policyErrors[string(p.identity.UID)]
			if failure == nil {
				// Unjoined, so report can tell pending-only from other failures.
				failure = c.bindingPending
			} else if c.bindingPending != nil {
				failure = errors.Join(failure, c.bindingPending)
			}
			report := c.report(p, failure)
			if err := c.writeStatus(ctx, p, report); err != nil {
				failures = append(failures, fmt.Errorf("write node status %s: %w", report.Name, err))
			}
		}
	}
	return errors.Join(append(failures, c.bindingPending)...)
}

// A transient incomplete runtime snapshot is not authorization to remove working
// bindings. Retain the complete previous snapshot and publish the failed barrier.
func (c *Controller) rejectBindings(ctx context.Context, failure error) error {
	c.bindingError = failure
	c.lastError = c.reconcile(ctx)
	return c.lastError
}

func (c *Controller) reportBindingFailure(ctx context.Context, failure error) error {
	// No binding was applied from this snapshot: there is no count to report.
	c.failedBindings = nil
	var statusErrors []error
	for _, obj := range c.objects {
		if obj.GetKind() == "SandboxPolicyClasses" {
			continue
		}
		p := parsePolicy(obj)
		if c.writer != nil && p.identity.UID != "" {
			statusErrors = append(statusErrors, c.writeStatus(ctx, p, c.report(p, failure)))
		}
	}
	return errors.Join(append([]error{failure}, statusErrors...)...)
}

// A changed physical identity must not acquire a cgroup until its previous
// owner (including committed-removal cleanup) has completely retired.
func (c *Controller) bindingRetiring(key string, binding Binding) bool {
	for oldKey, old := range c.active {
		if oldKey != key && old.binding.CgroupID == binding.CgroupID {
			return true
		}
	}
	for _, old := range c.withdrawals {
		if old.binding.CgroupID == binding.CgroupID {
			return true
		}
	}
	return false
}

// Snapshot failures permit health observation, never implicit pending publication.
func (c *Controller) attest(ctx context.Context, old installed) error {
	var err error
	if backend, ok := c.backend.(ProtectionAttester); ok {
		err = backend.Attest(ctx, old.binding, old.plan.Revision)
	} else {
		err = fmt.Errorf("backend does not support read-only protection attestation")
	}
	old.protectionUnconfirmed = err != nil
	c.active[bindingKey(old.binding)] = old
	if err != nil {
		return &protectionError{err}
	}
	return nil
}

func (c *Controller) replace(ctx context.Context, binding Binding, plan Plan) error {
	result, err := c.backend.Replace(ctx, binding, plan)
	if result.ProtectionUnconfirmed {
		err = &protectionError{errors.Join(err, errProtectionUnconfirmed)}
	}
	key := bindingKey(binding)
	if result.Committed {
		if result.ActiveRevision != plan.Revision {
			return errors.Join(err, fmt.Errorf("backend committed an unexpected revision %q", result.ActiveRevision))
		}
		c.active[key] = installed{binding: binding, plan: plan, cleanupPending: err != nil && !result.ProtectionUnconfirmed, protectionUnconfirmed: result.ProtectionUnconfirmed}
		if err != nil && !result.ProtectionUnconfirmed {
			return &cleanupError{err}
		}
	} else {
		if old, ok := c.active[key]; ok {
			old.protectionUnconfirmed = result.ProtectionUnconfirmed
			c.active[key] = old
		}
		if err == nil {
			return fmt.Errorf("backend returned success without committing revision %s", plan.Revision)
		}
	}
	return err
}

type protectionError struct{ error }

// errProtectionUnconfirmed notes that owned enforcement cannot be confirmed;
// the cause, when known, is joined next to it.
var errProtectionUnconfirmed = errors.New("owned enforcement protection cannot be confirmed")

// ErrWitnessUnknown marks a health check that could not read a witness
// counter (slot faults, the node witness): the protection is unknown, not
// lost. Status reports Ready=Unknown (WitnessUnknown) when it is the only
// cause.
var ErrWitnessUnknown = errors.New("witness counter cannot be read")

// witnessOnly reports whether every cause in err is an unreadable witness
// counter: each leaf of the error tree is ErrWitnessUnknown or the
// unconfirmed note. The note with no cause beside it (an unconfirmed result
// with no error, for example a partial commit) is a known loss.
func witnessOnly(err error) bool {
	if err == nil {
		return false
	}
	found := false
	var walk func(error) bool
	walk = func(e error) bool {
		switch {
		case e == ErrWitnessUnknown:
			found = true
			return true
		case e == errProtectionUnconfirmed:
			return true
		}
		switch u := e.(type) {
		case interface{ Unwrap() []error }:
			markerOnly := true
			for _, inner := range u.Unwrap() {
				if inner != nil && inner != errProtectionUnconfirmed {
					markerOnly = false
				}
			}
			if markerOnly {
				return false
			}
			for _, inner := range u.Unwrap() {
				if inner != nil && !walk(inner) {
					return false
				}
			}
			return true
		case interface{ Unwrap() error }:
			if inner := u.Unwrap(); inner != nil && inner != errProtectionUnconfirmed {
				return walk(inner)
			}
		}
		return false
	}
	return walk(err) && found
}

func (e *protectionError) Unwrap() error { return e.error }

type cleanupError struct{ error }

func (e *cleanupError) Unwrap() error { return e.error }

// withdraw distinguishes removal from cleanup: committed failures cannot remain
// in active, or status would falsely claim last-good protection still exists.
func (c *Controller) withdraw(ctx context.Context, old installed) error {
	key := bindingKey(old.binding)
	result, err := c.backend.Withdraw(ctx, old.binding)
	if result.Committed {
		delete(c.active, key)
		if err != nil {
			c.withdrawals[key] = old
			return &withdrawalCleanupError{err}
		}
		delete(c.withdrawals, key)
	} else {
		if result.ProtectionUnconfirmed {
			if retained, ok := c.active[key]; ok {
				retained.protectionUnconfirmed = true
				c.active[key] = retained
			}
		}
		if err == nil {
			err = fmt.Errorf("backend returned withdrawal success without committing removal")
		}

	}
	// A retry failure cannot undo a previously confirmed removal.
	if _, pending := c.withdrawals[key]; pending && err != nil {
		return &withdrawalCleanupError{err}
	}
	return err
}

type withdrawalCleanupError struct{ error }

func (e *withdrawalCleanupError) Unwrap() error { return e.error }

// A failed LIST freezes both installation and withdrawal until all three inputs
// can be listed again. Runtime snapshots are still recorded by SetBindings, so a
// successful recovery withdraws disappeared identities and applies the newest
// authoritative selection. This deliberately retains stale/deleted runtime
// bindings during API loss rather than use an incomplete config snapshot to
// authorize state transitions. Backend.Close remains the shutdown cleanup path.
func (c *Controller) reportConfigFailure(ctx context.Context) error {
	// No backend call is safe here: Replace may resume a pending publication.
	// Retain ownership without claiming protection until a fresh attestation.
	for key, old := range c.active {
		old.protectionUnconfirmed = true
		c.active[key] = old
	}
	failure := errors.Join(c.configError, c.bindingError)
	if c.writer == nil {
		return failure
	}
	var statusErrors []error
	for _, obj := range c.objects {
		if obj.GetKind() == "SandboxPolicyClasses" {
			continue
		}
		p := parsePolicy(obj)
		if p.identity.UID == "" {
			continue
		}
		report := c.report(p, failure)
		report.Status.Stale = true
		report.Status.Conditions[0].Reason = "ConfigurationUnavailable"
		report.Status.Conditions[0].Message = "Configuration snapshot unavailable; existing ownership retained but protection unconfirmed; new or changed bindings not installed"
		if err := c.writeStatus(ctx, p, report); err != nil {
			statusErrors = append(statusErrors, fmt.Errorf("write node status %s: %w", report.Name, err))
		}
	}
	return errors.Join(append([]error{failure}, statusErrors...)...)
}

// BindingSelector snapshots the last coherently loaded policy selectors. It
// performs no I/O and holds no controller lock when invoked. Discovery uses it
// only to determine which authoritative pod/container metadata REQUIRE runtime
// identity: it is not permission to guess an identity or exempt observer-ignored
// workloads. Invalid policies conservatively require every container in their
// owning namespace (or every namespace for cluster policies), retaining last-good
// selection until the invalid revision is repaired or intentionally deleted.
func (c *Controller) BindingSelector() func(Binding) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return selectorFor(c.objects)
}

func selectorFor(objects map[string]*unstructured.Unstructured) func(Binding) bool {
	policies := make([]desiredPolicy, 0, len(objects))
	for _, obj := range objects {
		if obj.GetKind() == "SandboxPolicy" || obj.GetKind() == "ClusterSandboxPolicy" {
			policies = append(policies, parsePolicy(obj))
		}
	}
	return func(binding Binding) bool {
		for _, policy := range policies {
			if policy.identity.Kind == "SandboxPolicy" && policy.identity.Namespace != binding.Namespace {
				continue
			}
			if policy.err != nil {
				return true
			}
			if policy.spec.Mode != api.ModeOff && policy.matches(binding) {
				return true
			}
		}
		return false
	}
}

func validatedBindings(bindings []Binding) (map[string]Binding, error) {
	next := make(map[string]Binding, len(bindings))
	for _, binding := range bindings {
		if binding.ContainerID == "" || binding.CgroupID == 0 || binding.PodUID == "" || binding.Namespace == "" || binding.PodName == "" || binding.ContainerName == "" {
			return nil, fmt.Errorf("incomplete container binding")
		}
		if binding.Kind != "regular" && binding.Kind != "init" && binding.Kind != "ephemeral" {
			return nil, fmt.Errorf("invalid container kind %q", binding.Kind)
		}
		key := bindingKey(binding)
		if _, ok := next[key]; ok {
			return nil, fmt.Errorf("duplicate container binding %s", key)
		}
		binding.PodLabels = cloneLabels(binding.PodLabels)
		binding.NamespaceLabels = cloneLabels(binding.NamespaceLabels)
		next[key] = binding
	}
	return next, nil
}

func (c *Controller) loadConfiguration(ctx context.Context) (map[string]*unstructured.Unstructured, error) {
	snapshot := make(map[string]*unstructured.Unstructured)
	for _, resource := range []schema.GroupVersionResource{PolicyGVR, ClusterPolicyGVR, ClassesGVR} {
		list, err := c.client.Resource(resource).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("configuration snapshot %s unavailable: %w", resource.Resource, err)
		}
		for i := range list.Items {
			obj := list.Items[i].DeepCopy()
			snapshot[objectKey(obj)] = obj
		}
	}
	return snapshot, nil
}

// HasConfigurationVersion reports whether Refresh has already listed this exact
// object revision. Both identity fields must come from the API server.
func (c *Controller) HasConfigurationVersion(uid types.UID, resourceVersion string) bool {
	versions := c.configurationVersions.Load()
	return versions != nil && uid != "" && resourceVersion != "" && (*versions)[uid] == resourceVersion
}

// Refresh is the integrated configuration/selection readiness barrier. It reads
// all policy inputs, selects from that candidate configuration, then obtains the
// matching authoritative runtime snapshot BEFORE any installation or Ready report.
// The callback executes under the reconciliation lock and must not call Controller
// methods other than the lock-free HasConfigurationVersion. It must reject incomplete discovery and concurrent churn, not return an
// inferred empty snapshot. The caller remains responsible for subscribe/replay.
// On snapshot failure the fetched config is retained for truthful new-policy
// NotReady reports, while last-good binding state is preserved. Valid explicit
// off/deletion may withdraw previously owned policies; no new plan is installed.
func (c *Controller) Refresh(ctx context.Context, snapshot func(context.Context, func(Binding) bool) ([]Binding, error)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	configuration, err := c.loadConfiguration(ctx)
	if err != nil {
		c.configurationVersions.Store(nil)
		c.configError = err
		c.lastError = c.reconcile(ctx)
		return c.lastError
	}
	// Publish before bindings and reconciliation so a watch replay during the
	// rest of this pass can recognize exactly what was already listed.
	versions := make(map[types.UID]string, len(configuration))
	for _, obj := range configuration {
		versions[obj.GetUID()] = obj.GetResourceVersion()
	}
	c.configurationVersions.Store(&versions)
	var bindings []Binding
	if snapshot == nil {
		err = fmt.Errorf("binding snapshot resolver is required")
	} else {
		bindings, err = snapshot(ctx, selectorFor(configuration))
	}
	// A pending-only snapshot still carries the complete correlated set. Bind it;
	// the pending containers keep status NotReady. Pending containers are never
	// correlated, so they cannot make a bound container drop out (withdraw).
	var pending error
	var pendingErr *BindingPendingError
	if errors.As(err, &pendingErr) && bindings != nil {
		pending, err = err, nil
	}
	if err == nil {
		err = ctx.Err()
	}
	var next map[string]Binding
	if err == nil {
		next, err = validatedBindings(bindings)
	}
	c.objects = configuration
	c.configError = nil
	if c.readClusterCIDRs != nil && c.usesClusterInternal() {
		if cidrs, ok := c.readClusterCIDRs(ctx); ok {
			c.clusterCIDRs = cidrs
		}
	}
	if err != nil {
		return c.rejectBindings(ctx, err)
	}
	c.bindings = next
	c.bindingError = nil
	c.bindingPending = pending
	c.lastError = c.reconcile(ctx)
	return c.lastError
}

// During binding uncertainty only an authoritative explicit off/delete permits
// changing enforcement. Selector mismatch from old pod/namespace labels does not.
// Partial withdrawal reuses immutable last-good compiled rules for retained UIDs.
func (c *Controller) withdrawDisabled(ctx context.Context) error {
	keep := make(map[string]bool)
	for _, obj := range c.objects {
		if obj.GetKind() == "SandboxPolicyClasses" {
			continue
		}
		p := parsePolicy(obj)
		if p.err != nil || p.spec.Mode != api.ModeOff {
			keep[string(p.identity.UID)] = true
		}
	}
	var failures []error
	for _, pending := range c.withdrawals {
		failures = append(failures, c.withdraw(ctx, pending))
	}
	for _, old := range c.active {
		retained := Plan{}
		for _, p := range old.plan.Policies {
			if keep[string(p.Identity.UID)] {
				retained.Policies = append(retained.Policies, p)
			}
		}
		if len(retained.Policies) == len(old.plan.Policies) {
			// Re-attest the immutable last-good plan on every heartbeat: an init
			// exit or quarantine may have invalidated previously healthy protection.
			// Replace is not read-only: it may resume an uncommitted candidate.
			failures = append(failures, c.attest(ctx, old))
			continue
		}
		if len(retained.Policies) == 0 {
			failures = append(failures, c.withdraw(ctx, old))
			continue
		}
		retained.Revision = digest(retained.Policies)
		failures = append(failures, c.replace(ctx, old.binding, retained))
	}
	return errors.Join(failures...)
}
