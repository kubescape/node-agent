package sandboxpolicy

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

func (c *Controller) report(p desiredPolicy, failure error) *api.SandboxPolicyNodeStatus {
	now := metav1.Now()
	namespace := p.identity.Namespace
	if p.identity.Kind == "ClusterSandboxPolicy" {
		namespace = c.options.AgentNamespace
	}
	status := &api.NodeStatus{Tier: "bpf-lsm", ObservedGeneration: p.identity.Generation, LastReported: now}
	ready := metav1.ConditionTrue
	reason, message := "Reconciled", "No selected running containers"
	active, stale := 0, false
	// refused: a section of the policy is not loaded on this node.
	// kernelRuntime: the kernel runtime check of a loaded section failed.
	var refused, kernelRuntime error
	unconfirmed := false
	podFaulted := false
	var cleanup *cleanupError
	cleanupPending := errors.As(failure, &cleanup)
	revisions := make(map[string]bool)
	// scope is the binding scope: exact for a container cgroup, subtree for
	// a pod cgroup binding (its containers' cgroups below it).
	// loaderNote is the first installed exec section that denies by path but
	// keeps the loaders runnable (ExecLoaderAllowed).
	loaderNote := ""
	count := func(compiled CompiledPolicy, scope string) {
		active++
		if loaderNote == "" {
			loaderNote = execLoaderNote(compiled.Exec)
		}
		// The oldest generation still installed is the one this node can vouch for.
		if status.AppliedGeneration == 0 || compiled.Identity.Generation < status.AppliedGeneration {
			status.AppliedGeneration = compiled.Identity.Generation
		}
		entry := fmt.Sprintf("generation=%d scope=%s", compiled.Identity.Generation, scope)
		if compiled.Revision != "" { // pod plans carry no revision
			entry += " revision=" + compiled.Revision
		}
		revisions[entry] = true
		if compiled.Identity.Generation != p.identity.Generation {
			stale = true
		}
	}
	ioUringHeld := 0
	for _, installed := range c.active {
		for _, compiled := range installed.plan.Policies {
			if compiled.Identity.UID != p.identity.UID {
				continue
			}
			if installed.ioUringHeld {
				ioUringHeld++
			}
			if installed.protectionUnconfirmed {
				unconfirmed = true
				continue
			}
			count(compiled, "exact")
		}
	}
	// Pod cgroup bindings enforce too, even when no container binding does,
	// but only where the witness counters confirm it.
	if reporter, ok := c.backend.(PodPlanReporter); ok {
		confirmed, faulted := reporter.BoundPodPlans()
		for _, plan := range confirmed {
			for _, compiled := range plan.Policies {
				if compiled.Identity.UID == p.identity.UID {
					count(compiled, "subtree")
				}
			}
		}
		for _, plan := range faulted {
			for _, compiled := range plan.Policies {
				if compiled.Identity.UID == p.identity.UID {
					unconfirmed, podFaulted = true, true
				}
			}
		}
	}
	if active > 0 {
		status.Tier = "bpf-lsm"
		message = "Selected containers have active enforcement"
	}
	if p.spec.Mode == api.ModeOff {
		message = "Policy is off"
	}
	// Without BPF LSM the programs attach but never run: nothing enforces or
	// audits, so the tier is none and an enabled policy is never Ready.
	if c.options.EnforcementUnavailable != nil {
		status.Tier = "none"
		status.AppliedGeneration = 0 // installed, but no generation is enforced
		if p.spec.Mode != api.ModeOff {
			failure = errors.Join(failure, c.options.EnforcementUnavailable)
		}
	} else if p.spec.Privilege != nil && p.spec.Mode != api.ModeOff {
		if err := c.sectionUnavailable(SectionPrivilege); err != nil {
			// The section never loaded; only other sections can enforce.
			if active == 0 {
				status.Tier = "none"
			}
			refused = err
			failure = errors.Join(failure, err)
		} else {
			kernelRuntime = c.kernelRuntime(SectionPrivilege)
		}
	}
	var network *NetworkReport
	if p.spec.Network != nil && p.spec.Mode != api.ModeOff {
		if err := c.sectionUnavailable(SectionNetwork); err != nil && c.options.EnforcementUnavailable == nil {
			if active == 0 {
				status.Tier = "none"
			}
			if refused == nil {
				refused = err
			}
			failure = errors.Join(failure, err)
		} else if err == nil && c.options.EnforcementUnavailable == nil && kernelRuntime == nil {
			kernelRuntime = c.kernelRuntime(SectionNetwork)
		}
		if plan := c.networkPlans[p.identity.UID]; plan != nil {
			network = &plan.Report
		}
	}
	var file *NetworkReport
	if p.spec.File != nil && p.spec.Mode != api.ModeOff {
		if err := c.sectionUnavailable(SectionFile); err != nil && c.options.EnforcementUnavailable == nil {
			if active == 0 {
				status.Tier = "none"
			}
			if refused == nil {
				refused = err
			}
			failure = errors.Join(failure, err)
		} else if err == nil && c.options.EnforcementUnavailable == nil && kernelRuntime == nil {
			kernelRuntime = c.kernelRuntime(SectionFile)
		}
		if plan := c.filePlans[p.identity.UID]; plan != nil {
			r := NetworkReport(plan.Report)
			file = &r
		}
	}
	if kernelRuntime != nil {
		// Ftrace off or a livepatch: the BPF LSM trampolines may not run, so
		// no binding is protected (detected, not guarded).
		status.Tier = "none"
		status.AppliedGeneration = 0
		failure = errors.Join(failure, kernelRuntime)
	}
	var uncertain *protectionError
	unconfirmed = unconfirmed || errors.As(failure, &uncertain)
	// An unreadable witness counter, and nothing else, leaves the protection
	// of a container binding unknown, not lost (Ready=Unknown). A pod binding
	// reports only that it is faulted (BoundPodPlans), not why, so any fault
	// of a pod binding counts as a known loss (ProtectionUnconfirmed), also
	// when its cause is an unreadable counter: a policy with pod bindings
	// then reports ProtectionUnconfirmed, the safe direction.
	witnessUnknown := unconfirmed && !podFaulted && witnessOnly(failure)
	if unconfirmed {
		failure = errors.Join(failure, fmt.Errorf("owned enforcement protection cannot be confirmed; workload may be unprotected"))
	}
	generationStale := stale
	if failure != nil {
		ready = metav1.ConditionFalse
		reason = "NotReady"
		message = "Desired revision rejected; no last-good enforcement exists"
		if active > 0 {
			// Stale only when installed bindings lag the desired generation.
			message = "Desired revision rejected; retaining existing last-good bindings; new bindings may be unprotected"
			if !generationStale {
				if failed := c.failedBindings[string(p.identity.UID)]; failed > 0 {
					message = fmt.Sprintf("Desired revision applied in part: applied on %d binding(s), failed on %d; see error", active, failed)
				} else {
					// No binding failed to apply it: a withdrawal or the snapshot failed.
					message = fmt.Sprintf("Desired revision applied on %d binding(s); another step failed; see error", active)
				}
			}
		}
		var pending *BindingPendingError
		if errors.As(failure, &pending) {
			pendingMessage := fmt.Sprintf("%d live container(s) selected by policies on this node are not yet bound", pending.Containers)
			if _, joined := failure.(interface{ Unwrap() []error }); joined {
				// Another failure also applies: keep its reason, add the count.
				message += "; " + pendingMessage
			} else {
				reason, message, stale = "BindingPending", pendingMessage+"; other selected containers are bound", generationStale
			}
		}
		if cleanupPending {
			reason = "CleanupPending"
			message = "A desired binding committed; reconciliation or previous-instance cleanup is incomplete; see active revisions"
			stale = generationStale
		}
		var withdrawn *withdrawalCleanupError
		if errors.As(failure, &withdrawn) {
			reason = "WithdrawalCleanupPending"
			message = "Binding withdrawal committed; enforcement removed for that binding, resource cleanup pending"
			stale = generationStale
		}
		// A node-wide cause names the node, not the first section it hit.
		if r, m, ok := unavailableReason(c.options.EnforcementUnavailable); ok && p.spec.Mode != api.ModeOff {
			reason, message = r, m
		} else if r, m, ok := unavailableReason(failure); ok {
			reason, message = r, m
		}
		if unconfirmed {
			reason = "ProtectionUnconfirmed"
			message = "Owned binding protection cannot be confirmed: a Strict binding with a fault fails closed (the workload may be over-blocked), other bindings may be unprotected; ownership retained only for recovery/cleanup"
			stale = true
		}
		if witnessUnknown && refused == nil && kernelRuntime == nil {
			ready, reason = metav1.ConditionUnknown, "WitnessUnknown"
			message = "A witness counter of an owned binding cannot be read; its protection is unknown"
		}
		// A refused section names the cause: its part of each binding never
		// loaded, which is more than unconfirmed.
		if r, m, ok := unavailableReason(refused); ok {
			reason, message = r, m
		}
		// The kernel runtime check names the cause: every binding of the
		// section is unprotected, whatever else failed.
		if r, m, ok := unavailableReason(kernelRuntime); ok {
			reason, message, stale = r, m+"; bindings are unprotected", true
		}
		status.Error, status.Truncated = boundedText(failure.Error(), api.MaxStatusErrorLength)
	} else if r, m := notReady(network, file, p.identityStatus.NotReady); r != "" {
		// The policy enforces, with degraded defaults (see Degraded).
		ready, reason, message = metav1.ConditionFalse, r, m
	}
	status.Stale = stale
	// Admission rejects appliedGeneration above observedGeneration, which
	// would leave the previous (perhaps Ready) status in place; an installed
	// generation newer than the one observed cannot be stated, so omit it.
	if status.AppliedGeneration > status.ObservedGeneration {
		status.AppliedGeneration = 0
	}
	// Kernel bindings of the previous node-agent run that no container took
	// over yet still enforce its policies (restart survival): report the
	// revision they enforce, never the new one. An adopted state whose links
	// cannot be confirmed is Unknown; past the settle deadline the policy is
	// Degraded (below).
	adoption := c.adoption(p)
	if ready == metav1.ConditionTrue && adoption.linkErr != nil {
		ready, reason = metav1.ConditionUnknown, "AdoptedLinkMissing"
		message = "A pinned link of the previous node-agent run no longer runs its program: " + adoption.linkErr.Error()
	}
	// A known rate breach wins over an unreadable witness. Keep other
	// readiness reasons and report recent activity separately in Degraded.
	var degraded *metav1.Condition
	if rr, ok := c.backend.(RateReporter); ok && p.spec.Mode != api.ModeOff {
		if rep, ok := rr.PolicyRates(p.identity.UID, now.Time); ok {
			degraded = degradedCondition(rep)
			switch {
			case rep.NotReady && (ready == metav1.ConditionTrue || reason == "WitnessUnknown"):
				ready, reason, message = metav1.ConditionFalse, "FailClosedRate", "Fail-closed rate above the threshold: "+rep.Message
			case rep.Unknown != nil && ready == metav1.ConditionTrue:
				ready, reason = metav1.ConditionUnknown, "WitnessUnknown"
				message = "Enforcement counters cannot be read; protection is unknown: " + rep.Unknown.Error()
			}
		}
	}
	if adoption.degraded {
		// Past the deadline Degraded is True. Its reason is the deadline,
		// except after fail-closed checks (FailClosedRecent), which stay
		// first; the other message is kept in both cases.
		note := "The settle deadline passed: adopted bindings of the previous run are kept only where the current plan is Strict (fail closed)"
		switch {
		case degraded == nil || degraded.Status == metav1.ConditionFalse:
			degraded = &metav1.Condition{Type: "Degraded", Status: metav1.ConditionTrue, Reason: "SettleDeadlinePassed", Message: note}
		case degraded.Reason == "FailClosedRecent":
			degraded.Message += "; " + note
		default:
			degraded = &metav1.Condition{Type: "Degraded", Status: metav1.ConditionTrue, Reason: "SettleDeadlinePassed", Message: note + "; " + degraded.Message}
		}
	}
	status.Conditions = []metav1.Condition{{Type: "Ready", Status: ready, Reason: reason, Message: message, ObservedGeneration: p.identity.Generation, LastTransitionTime: now}}
	if ioUringHeld > 0 {
		// An Audit binding with io_uring rings opened before it binds (a
		// Strict one is refused, reason IoUringHeld): report it here.
		note := fmt.Sprintf("%d Audit binding(s) hold io_uring rings opened before the bind; requests queued before it may run unjudged", ioUringHeld)
		switch {
		case degraded == nil || degraded.Status == metav1.ConditionFalse:
			degraded = &metav1.Condition{Type: "Degraded", Status: metav1.ConditionTrue, Reason: "IoUringHeld", Message: note}
		case degraded.Status == metav1.ConditionUnknown:
			// A known degradation is True; what is unknown stays in the
			// message.
			degraded = &metav1.Condition{Type: "Degraded", Status: metav1.ConditionTrue, Reason: "IoUringHeld", Message: note + "; " + degraded.Message}
		default:
			degraded.Message += "; " + note
		}
	}
	if degraded != nil {
		degraded.ObservedGeneration, degraded.LastTransitionTime = p.identity.Generation, now
		status.Conditions = append(status.Conditions, *degraded)
	}
	if network != nil || file != nil || len(p.identityStatus.Degraded) > 0 {
		status.Compiled = &api.CompiledStatus{}
		degraded := append([]api.DegradedRule(nil), p.identityStatus.Degraded...)
		for _, section := range []struct {
			report    *NetworkReport
			condition string
		}{{network, "NetworkNotEnforced"}, {file, "FileNotEnforced"}} {
			r := section.report
			if r == nil {
				continue
			}
			status.Compiled.Rules += r.Rules
			status.Compiled.ClassesResolved += r.ClassesResolved
			status.Compiled.ClassesUnresolved += r.ClassesUnresolved
			degraded = append(degraded, r.Degraded...)
			if len(r.NotEnforced) > 0 {
				summary, truncated := boundedText(strings.Join(r.NotEnforced, "; "), api.MaxStatusDiagnosticLength)
				status.Truncated = status.Truncated || truncated
				status.Conditions = append(status.Conditions, metav1.Condition{Type: section.condition, Status: metav1.ConditionTrue, Reason: "UnsupportedByGadget", Message: summary, ObservedGeneration: p.identity.Generation, LastTransitionTime: now})
			}
		}
		degraded = sortedDegraded(degraded)
		status.Counts.Degraded = int64(len(degraded))
		if len(degraded) > api.MaxStatusRuleDetails {
			degraded, status.Truncated = degraded[:api.MaxStatusRuleDetails], true
		}
		status.Degraded = degraded
	}
	if len(p.identityStatus.Notes) > 0 {
		summary, truncated := boundedText(strings.Join(p.identityStatus.Notes, "; "), api.MaxStatusDiagnosticLength)
		status.Truncated = status.Truncated || truncated
		status.Conditions = append(status.Conditions, metav1.Condition{Type: "IdentityNotEnforced", Status: metav1.ConditionTrue, Reason: "NotExpressible", Message: summary, ObservedGeneration: p.identity.Generation, LastTransitionTime: now})
	}
	if loaderNote != "" && p.spec.Mode != api.ModeOff {
		summary, truncated := boundedText(loaderNote, api.MaxStatusDiagnosticLength)
		status.Truncated = status.Truncated || truncated
		status.Conditions = append(status.Conditions, metav1.Condition{Type: "ExecLoaderAllowed", Status: metav1.ConditionTrue, Reason: "LoaderAllowRule", Message: summary, ObservedGeneration: p.identity.Generation, LastTransitionTime: now})
	}
	if len(revisions) > 0 {
		ordered := make([]string, 0, len(revisions))
		for revision := range revisions {
			ordered = append(ordered, revision)
		}
		sort.Strings(ordered)
		summary, truncated := boundedText(strings.Join(ordered, "; "), api.MaxStatusDiagnosticLength)
		status.Truncated = status.Truncated || truncated
		status.Conditions = append(status.Conditions, metav1.Condition{Type: "ActiveRevision", Status: metav1.ConditionTrue, Reason: "Installed", Message: summary, ObservedGeneration: p.identity.Generation, LastTransitionTime: now})
	}
	if len(adoption.entries) > 0 {
		sort.Strings(adoption.entries)
		summary, truncated := boundedText(strings.Join(adoption.entries, "; "), api.MaxStatusDiagnosticLength)
		status.Truncated = status.Truncated || truncated
		cond := metav1.Condition{Type: "AdoptedLastGood", Status: metav1.ConditionTrue, Reason: "RestartAdopted", Message: summary, ObservedGeneration: p.identity.Generation, LastTransitionTime: now}
		switch {
		case adoption.linkErr != nil:
			cond.Status, cond.Reason = metav1.ConditionUnknown, "AdoptedLinkMissing"
		case adoption.degraded:
			cond.Reason = "SettleDeadlinePassed"
		}
		status.Conditions = append(status.Conditions, cond)
	}
	if cond, ok := c.restartCondition(p); ok {
		cond.ObservedGeneration, cond.LastTransitionTime = p.identity.Generation, now
		status.Conditions = append(status.Conditions, cond)
	}

	if reporter, ok := c.backend.(RuntimeHelperReporter); ok {
		if cond, ok := runtimeHelperCondition(reporter, p.identity.UID); ok {
			cond.ObservedGeneration, cond.LastTransitionTime = p.identity.Generation, now
			status.Conditions = append(status.Conditions, cond)
		}
	}

	var dropped bool
	status.Conditions, dropped = capConditions(status.Conditions)
	status.Truncated = status.Truncated || dropped

	return &api.SandboxPolicyNodeStatus{
		TypeMeta:   metav1.TypeMeta{APIVersion: api.SchemeGroupVersion.String(), Kind: "SandboxPolicyNodeStatus"},
		ObjectMeta: metav1.ObjectMeta{Name: api.NodeStatusName(p.identity.UID, c.options.Node.UID), Namespace: namespace, OwnerReferences: []metav1.OwnerReference{{APIVersion: api.SchemeGroupVersion.String(), Kind: p.identity.Kind, Name: p.identity.Name, UID: p.identity.UID}}},
		Spec:       api.SandboxPolicyNodeStatusSpec{PolicyRef: api.SandboxPolicyReference{Kind: p.identity.Kind, Name: p.identity.Name, UID: p.identity.UID}, NodeRef: c.options.Node}, Status: status,
	}
}

// notReady returns the Ready=False reason and message when a section rule
// cannot be resolved or enforced, else "".
func notReady(network, file *NetworkReport, identity string) (string, string) {
	var reason string
	var parts []string
	if network != nil && network.NotReady == "NotEnforceable" {
		reason = network.NotReady
		parts = append(parts, "part of an enforce network deny cannot be enforced (a class resolved in part, an unsupported proto, or the listen direction); the rest enforces")
	} else if network != nil && network.NotReady != "" {
		reason = network.NotReady
		parts = append(parts, "network rule or except entry cannot be resolved; enforcement is kept (an enforce default deny over-blocks)")
	}
	if file != nil && file.NotReady != "" {
		if reason == "" {
			reason = file.NotReady
		}
		parts = append(parts, "file rule or except entry cannot be resolved or enforced; an unresolved class keeps enforcement, an unenforceable allow runs the defaults of its access kinds in audit, an enforce deny keeps its paths without what cannot be judged (it over-blocks) and drops the globs the gadget cannot express, and an enforce execMap deny is not enforced at all (FileNotEnforced)")
	}
	if identity != "" {
		if reason == "" {
			reason = identity
		}
		parts = append(parts, "identity enforce default deny cannot be enforced (identity has no default of its own) and runs in audit")
	}
	if reason == "" {
		return "", ""
	}
	return reason, "A " + strings.Join(parts, "; a ") + "; see degraded and the NotEnforced conditions"
}

func boundedText(value string, limit int) (string, bool) {
	if utf8.RuneCountInString(value) <= limit {
		return value, false
	}
	return string([]rune(value)[:limit]), true
}

// conditionReasonItem is one item of a comma-joined condition reason list
// (the metav1.Condition reason syntax, without commas).
var conditionReasonItem = regexp.MustCompile(`^[A-Za-z]([A-Za-z0-9_:]*[A-Za-z0-9_])?$`)

// conditionReasonMore marks a reason list cut at the bound.
const conditionReasonMore = "More"

// BoundConditionReason fits a comma-joined reason list into
// api.MaxStatusConditionKeyLength. It drops empty and malformed items and,
// when the list is too long, whole trailing items (never half of one),
// appending ",More" ("More" alone if not even the first item fits beside it).
// The result always matches the condition reason syntax
// ("Unknown" if no item is usable). cut reports any change.
func BoundConditionReason(reason string) (bounded string, cut bool) {
	var items []string
	for item := range strings.SplitSeq(reason, ",") {
		if conditionReasonItem.MatchString(item) && len(item) <= api.MaxStatusConditionKeyLength {
			items = append(items, item)
		}
	}
	if len(items) == 0 {
		return "Unknown", true
	}
	if joined := strings.Join(items, ","); len(joined) <= api.MaxStatusConditionKeyLength {
		return joined, joined != reason
	}
	length := len(conditionReasonMore)
	var kept []string
	for _, item := range items {
		if length+len(item)+1 > api.MaxStatusConditionKeyLength {
			break
		}
		kept = append(kept, item)
		length += len(item) + 1
	}
	return strings.Join(append(kept, conditionReasonMore), ","), true
}

// BoundCondition fits c's reason and message into the storage schema
// (api.MaxStatusConditionKeyLength, api.MaxStatusDiagnosticLength); an
// out-of-schema status update would be rejected and leave the previous
// status (perhaps Ready True) in place. It reports whether anything was cut.
func BoundCondition(c *metav1.Condition) bool {
	reason, reasonCut := BoundConditionReason(c.Reason)
	message, messageCut := boundedText(c.Message, api.MaxStatusDiagnosticLength)
	c.Reason, c.Message = reason, message
	return reasonCut || messageCut
}

// DynamicStatusWriter only creates the UID-scoped report and writes its status
// subresource. It never edits policy parent aggregates. Conflicts are returned so
// the controller's periodic reconciliation can retry without hiding write loss.
type DynamicStatusWriter struct{ Client dynamic.Interface }

func (w DynamicStatusWriter) WriteStatus(ctx context.Context, report *api.SandboxPolicyNodeStatus) error {
	resource := w.Client.Resource(NodeStatusGVR).Namespace(report.Namespace)
	existing, err := resource.Get(ctx, report.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		initial := report.DeepCopy()
		initial.Status = nil
		raw, convertErr := runtime.DefaultUnstructuredConverter.ToUnstructured(initial)
		if convertErr != nil {
			return convertErr
		}
		existing, err = resource.Create(ctx, &unstructured.Unstructured{Object: raw}, metav1.CreateOptions{})
	}
	if err != nil {
		return err
	}
	var current api.SandboxPolicyNodeStatus
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(existing.Object, &current); err != nil {
		return err
	}
	if current.Spec != report.Spec {
		return fmt.Errorf("node report identity mismatch for %s", report.Name)
	}
	status := report.Status.DeepCopy()
	// Every condition fits the schema, whoever composed it.
	for i := range status.Conditions {
		if BoundCondition(&status.Conditions[i]) {
			status.Truncated = true
		}
	}
	// Preserve transition timestamps for stable conditions across heartbeats.
	if current.Status != nil {
		for i := range status.Conditions {
			for _, previous := range current.Status.Conditions {
				if previous.Type == status.Conditions[i].Type && previous.Status == status.Conditions[i].Status {
					status.Conditions[i].LastTransitionTime = previous.LastTransitionTime
				}
			}
		}
	}
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(status)
	if err != nil {
		return err
	}
	existing.Object["status"] = raw
	_, err = resource.UpdateStatus(ctx, existing, metav1.UpdateOptions{})
	return err
}

// runtimeHelperCondition reports a policy whose pod bindings carry the
// runtime helper exemption (the host operator enabled it): the helper-flagged
// bindings and the execs exempted on the node. An unreadable count is
// Unknown, never zero.
func runtimeHelperCondition(r RuntimeHelperReporter, uid types.UID) (metav1.Condition, bool) {
	enabled, plans, exempt, err := r.RuntimeHelperStatus()
	if !enabled {
		return metav1.Condition{}, false
	}
	pods := 0
	for _, plan := range plans {
		for _, compiled := range plan.Policies {
			if compiled.Identity.UID == uid {
				pods++
				break
			}
		}
	}
	if pods == 0 {
		return metav1.Condition{}, false
	}
	if err != nil {
		return metav1.Condition{Type: "RuntimeHelperExemption", Status: metav1.ConditionUnknown, Reason: "WitnessUnknown",
			Message: fmt.Sprintf("%d pod bindings exempt OCI runtime helpers (operator setting); exempted execs unknown: %v", pods, err)}, true
	}
	return metav1.Condition{Type: "RuntimeHelperExemption", Status: metav1.ConditionTrue, Reason: "OperatorEnabled",
		Message: fmt.Sprintf("%d pod bindings exempt OCI runtime helpers (operator setting); ExemptExecs=%d on this node", pods, exempt)}, true
}

// adoptionReport is the restart adoption of one policy (AdoptionReporter).
type adoptionReport struct {
	entries  []string
	degraded bool
	linkErr  error
}

func (c *Controller) adoption(p desiredPolicy) adoptionReport {
	var r adoptionReport
	reporter, ok := c.backend.(AdoptionReporter)
	if !ok {
		return r
	}
	uses := map[string]bool{SectionPrivilege: p.spec.Privilege != nil, SectionNetwork: p.spec.Network != nil, SectionFile: p.spec.File != nil}
	for _, a := range reporter.Adopted() {
		if a.Unreadable {
			if !uses[a.Section] {
				continue
			}
			// A pinned set that could not be read (its policies are not
			// known) is kept: every policy of its section reports it.
			r.entries = append(r.entries, fmt.Sprintf("%s: kept state of the previous run whose policies are not known", a.Section))
			r.degraded = r.degraded || a.Degraded
			if r.linkErr == nil {
				r.linkErr = a.LinkError
				if r.linkErr == nil {
					r.linkErr = fmt.Errorf("%s: kept state of the previous run whose policies are not known", a.Section)
				}
			}
			continue
		}
		for _, policy := range a.Policies {
			if policy.Policy.UID == p.identity.UID {
				r.entries = append(r.entries, fmt.Sprintf("%s slot %d: revision=%s generation=%d digest=%s bindings=%d", a.Section, a.Slot, policy.Revision, a.Generation, a.Digest, a.Bindings))
				r.degraded = r.degraded || a.Degraded
				if a.LinkError != nil && r.linkErr == nil {
					r.linkErr = a.LinkError
				}
			}
		}
	}
	return r
}

// RestartSurvivor optionally reports, per section, whether enforcement
// survives a node-agent restart (SectionBackend.RestartSurvival).
type RestartSurvivor interface {
	RestartSurvival() []SectionRestart
}

// restartCondition reports whether the sections the policy uses keep
// enforcing through a node-agent restart: True (Pinned) only when every one of
// them survives; Unknown (PinPending) while a slot section is not pinned yet;
// False when a pin failed (PinFailed), when nothing survives (NotPinned), or
// when some sections do not survive (PartlyPinned: exec is never pinned).
func (c *Controller) restartCondition(p desiredPolicy) (metav1.Condition, bool) {
	survivor, ok := c.backend.(RestartSurvivor)
	if !ok {
		return metav1.Condition{}, false
	}
	uses := map[string]bool{SectionPrivilege: p.spec.Privilege != nil, SectionNetwork: p.spec.Network != nil, SectionFile: p.spec.File != nil, "exec": p.spec.Exec != nil}
	var survive, lost, failed, pending []string
	for _, s := range survivor.RestartSurvival() {
		if !uses[s.Section] {
			continue
		}
		switch {
		case s.Section == "exec":
			lost = append(lost, "exec: "+s.Err.Error())
		case s.Err != nil:
			failed = append(failed, s.Section+": "+s.Err.Error())
		case s.Pinned:
			survive = append(survive, s.Section)
		default:
			pending = append(pending, s.Section+": not pinned yet")
		}
	}
	if len(survive)+len(lost)+len(failed)+len(pending) == 0 {
		return metav1.Condition{}, false
	}
	parts := []string{}
	if len(survive) > 0 {
		parts = append(parts, "survive a node-agent restart: "+strings.Join(survive, ", "))
	}
	parts = append(append(append(parts, failed...), pending...), lost...)
	msg, _ := boundedText(strings.Join(parts, "; "), api.MaxStatusDiagnosticLength)
	cond := func(status metav1.ConditionStatus, reason string) (metav1.Condition, bool) {
		return metav1.Condition{Type: "RestartSurvival", Status: status, Reason: reason, Message: msg}, true
	}
	switch {
	case len(failed) > 0:
		return cond(metav1.ConditionFalse, "PinFailed")
	case len(pending) > 0:
		return cond(metav1.ConditionUnknown, "PinPending")
	case len(survive) == 0:
		return cond(metav1.ConditionFalse, "NotPinned")
	case len(lost) > 0:
		return cond(metav1.ConditionFalse, "PartlyPinned")
	}
	return cond(metav1.ConditionTrue, "Pinned")
}

// degradedCondition is the Degraded condition of the reporting rule: True on
// any fail-closed refusal or unevaluated judgement in the last 60 s, Unknown
// when a counter is unreadable or moved backwards, else False.
func degradedCondition(rep RateReport) *metav1.Condition {
	var suppressed string
	if rep.Suppressed > 0 {
		suppressed = fmt.Sprintf("%d denies in the last minute have no verdict (kernel report rate limit, full ring buffer, or the kept links of a previous node-agent run; enforcement unchanged); the count is node-wide per section, not per policy: %s", rep.Suppressed, rep.SuppressedNote)
	}
	if rep.SuppressedUnknown != "" {
		lossUnknown := fmt.Sprintf("lost verdicts cannot be counted (a verdict counter is unreadable, or was unreadable or reset in the last minute): %s", rep.SuppressedUnknown)
		if suppressed == "" {
			suppressed = lossUnknown
		} else {
			suppressed += "; " + lossUnknown
		}
	}
	withSuppressed := func(message string) string {
		if suppressed == "" {
			return message
		}
		return message + "; " + suppressed
	}
	switch {
	case rep.Unknown != nil:
		return &metav1.Condition{Type: "Degraded", Status: metav1.ConditionUnknown, Reason: "WitnessUnknown", Message: withSuppressed(rep.Unknown.Error())}
	case rep.Degraded:
		return &metav1.Condition{Type: "Degraded", Status: metav1.ConditionTrue, Reason: "FailClosedRecent", Message: withSuppressed("Fail-closed or unevaluated checks in the last minute: " + rep.Message)}
	case rep.Suppressed > 0:
		// Lost evidence, not lost enforcement: Ready keeps its state.
		return &metav1.Condition{Type: "Degraded", Status: metav1.ConditionTrue, Reason: "VerdictsSuppressed", Message: suppressed}
	case suppressed != "":
		// The loss is unknown, never zero.
		return &metav1.Condition{Type: "Degraded", Status: metav1.ConditionUnknown, Reason: "VerdictLossUnknown", Message: suppressed}
	default:
		return &metav1.Condition{Type: "Degraded", Status: metav1.ConditionFalse, Reason: "NoRecentFailures", Message: rep.Message}
	}
}

// conditionPriority orders the condition types kept when a report has more
// than api.MaxStatusConditions (the CRD's limit): enforcement state first,
// then what is not enforced, then details. Unlisted types go last.
var conditionPriority = []string{"Ready", "Degraded", "AdoptedLastGood", "RestartSurvival",
	"NetworkNotEnforced", "FileNotEnforced", "IdentityNotEnforced", "ExecLoaderAllowed", "RuntimeHelperExemption", "ActiveRevision"}

// capConditions keeps at most api.MaxStatusConditions conditions, by
// conditionPriority, in their original order; dropped reports a cut.
func capConditions(conds []metav1.Condition) ([]metav1.Condition, bool) {
	if len(conds) <= api.MaxStatusConditions {
		return conds, false
	}
	rank := func(t string) int {
		for i, p := range conditionPriority {
			if p == t {
				return i
			}
		}
		return len(conditionPriority)
	}
	order := make([]int, len(conds))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return rank(conds[order[a]].Type) < rank(conds[order[b]].Type) })
	keep := map[int]bool{}
	for _, i := range order[:api.MaxStatusConditions] {
		keep[i] = true
	}
	out := make([]metav1.Condition, 0, api.MaxStatusConditions)
	for i, c := range conds {
		if keep[i] {
			out = append(out, c)
		}
	}
	return out, true
}

// execLoaderNote reports a compiled exec section that denies by path but
// keeps the dynamic loaders runnable, because an allow rule names one
// (authored, from a path class, or from a ContainerProfile): the full compiler
// then adds no loader deny, so "ld.so <program>" can run a program that a
// path deny names.
func execLoaderNote(exec api.ExecSection) string {
	if !ExecDeniesByPath(exec) {
		return ""
	}
	rule, path, ok := LoaderAllowRule(exec)
	if !ok {
		return ""
	}
	from := ""
	if rule.Origin != nil && *rule.Origin != "" {
		from = " (origin " + *rule.Origin + ")"
	}
	return fmt.Sprintf("exec rule %s%s allows the loader path %s, so no loader deny is added: \"ld.so <program>\" can run a program that an exec path deny names", rule.Name, from, path)
}
