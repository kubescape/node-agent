package sandboxpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/kubescape/node-agent/pkg/watcher"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
	err               error
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
	var classErr error
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
			classErr = errors.Join(classErr, err)
			continue
		}
		if err := api.ValidatePolicyClasses(spec); err != nil {
			classErr = errors.Join(classErr, err)
			continue
		}
		for name, paths := range spec.PathClasses {
			if owner, exists := classNames[name]; exists {
				classErr = errors.Join(classErr, fmt.Errorf("path class %q occurs in %s and %s", name, owner, obj.GetName()))
				continue
			}
			classNames[name] = obj.GetName()
			classes.PathClasses[name] = paths
		}
	}
	policyErrors := make(map[string]error)
	for _, p := range policies {
		if p.err != nil {
			policyErrors[string(p.identity.UID)] = p.err
			failures = append(failures, p.err)
		}
	}

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
				}
			}
			continue
		}
		selected := make([]desiredPolicy, 0)
		keep := make(map[string]bool)
		for _, p := range policies {
			// Invalid revisions retain previous enforcement even when malformed selectors
			// cannot be evaluated. Only a valid off/delete/nonmatch authorizes withdrawal.
			if p.err != nil {
				if p.identity.Kind == "SandboxPolicy" && p.identity.Namespace != binding.Namespace {
					continue
				}
				keep[string(p.identity.UID)] = true
				selected = append(selected, p)
				continue
			}
			if p.spec.Mode != api.ModeOff && p.matches(binding) {
				selected = append(selected, p)
				keep[string(p.identity.UID)] = true
			}
		}
		old, hasOld := c.active[key]
		if hasOld {
			retained := Plan{}
			for _, p := range old.plan.Policies {
				if keep[string(p.Identity.UID)] {
					retained.Policies = append(retained.Policies, p)
				}
			}
			if len(retained.Policies) != len(old.plan.Policies) {
				retained.Revision = digest(retained.Policies)
				var err error
				if len(retained.Policies) == 0 {
					err = c.withdraw(ctx, old)
				} else {
					err = c.replace(ctx, binding, retained)
				}
				if err != nil {
					failures = append(failures, err)
					for _, p := range old.plan.Policies {
						policyErrors[string(p.Identity.UID)] = err
					}
					for _, p := range selected {
						policyErrors[string(p.identity.UID)] = errors.Join(policyErrors[string(p.identity.UID)], err)
					}
					continue
				}
				if len(retained.Policies) == 0 {
					delete(c.active, key)
				}
			}
		}
		plan := Plan{}
		var candidateErr error
		if len(selected) > MaxPoliciesPerBinding {
			candidateErr = fmt.Errorf("binding exceeds %d policies", MaxPoliciesPerBinding)
		}
		for _, p := range selected {
			err := p.err
			if err == nil {
				err = classErr
			}
			if err == nil {
				compiled, compileErr := Compile(ctx, p.identity, p.spec, classes, binding, c.resolver)
				err = compileErr
				if err == nil {
					plan.Policies = append(plan.Policies, compiled)
				}
			}
			candidateErr = errors.Join(candidateErr, err)
		}
		plan.Revision = digest(plan.Policies)
		if candidateErr == nil && len(plan.Policies) > 0 {
			// Same-plan Replace is an attestation/cleanup retry, not a gadget restart.
			// Never infer current protection merely from a prior successful revision.
			candidateErr = c.replace(ctx, binding, plan)
		} else if candidateErr != nil {
			if old, ok := c.active[key]; ok {
				candidateErr = errors.Join(candidateErr, c.replace(ctx, old.binding, old.plan))
			}
		}

		if candidateErr != nil {
			failures = append(failures, candidateErr)
			for _, p := range selected {
				policyErrors[string(p.identity.UID)] = errors.Join(policyErrors[string(p.identity.UID)], candidateErr)
			}
		}
	}
	if c.writer != nil {
		for _, p := range policies {
			if p.identity.UID == "" {
				continue
			}
			report := c.report(p, policyErrors[string(p.identity.UID)])
			if err := c.writer.WriteStatus(ctx, report); err != nil {
				failures = append(failures, fmt.Errorf("write node status %s: %w", report.Name, err))
			}
		}
	}
	return errors.Join(failures...)
}

// A transient incomplete runtime snapshot is not authorization to remove working
// bindings. Retain the complete previous snapshot and publish the failed barrier.
func (c *Controller) rejectBindings(ctx context.Context, failure error) error {
	c.bindingError = failure
	c.lastError = c.reconcile(ctx)
	return c.lastError
}

func (c *Controller) reportBindingFailure(ctx context.Context, failure error) error {
	var statusErrors []error
	for _, obj := range c.objects {
		if obj.GetKind() == "SandboxPolicyClasses" {
			continue
		}
		p := parsePolicy(obj)
		if c.writer != nil && p.identity.UID != "" {
			statusErrors = append(statusErrors, c.writer.WriteStatus(ctx, c.report(p, failure)))
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
		err = &protectionError{errors.Join(err, fmt.Errorf("owned enforcement protection cannot be confirmed"))}
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
		if err := c.writer.WriteStatus(ctx, report); err != nil {
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

// Refresh is the integrated configuration/selection readiness barrier. It reads
// all policy inputs, selects from that candidate configuration, then obtains the
// matching authoritative runtime snapshot BEFORE any installation or Ready report.
// The callback executes under the reconciliation lock and must not call Controller
// methods. It must reject incomplete discovery and concurrent churn, not return an
// inferred empty snapshot. The caller remains responsible for subscribe/replay.
// On snapshot failure the fetched config is retained for truthful new-policy
// NotReady reports, while last-good binding state is preserved. Valid explicit
// off/deletion may withdraw previously owned policies; no new plan is installed.
func (c *Controller) Refresh(ctx context.Context, snapshot func(context.Context, func(Binding) bool) ([]Binding, error)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	configuration, err := c.loadConfiguration(ctx)
	if err != nil {
		c.configError = err
		c.lastError = c.reconcile(ctx)
		return c.lastError
	}
	var bindings []Binding
	if snapshot == nil {
		err = fmt.Errorf("binding snapshot resolver is required")
	} else {
		bindings, err = snapshot(ctx, selectorFor(configuration))
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
	if err != nil {
		return c.rejectBindings(ctx, err)
	}
	c.bindings = next
	c.bindingError = nil
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
