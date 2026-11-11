package sandboxpolicy

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
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
	unconfirmed := false
	var cleanup *cleanupError
	cleanupPending := errors.As(failure, &cleanup)
	revisions := make(map[string]bool)
	count := func(compiled CompiledPolicy) {
		active++
		// The oldest generation still installed is the one this node can vouch for.
		if status.AppliedGeneration == 0 || compiled.Identity.Generation < status.AppliedGeneration {
			status.AppliedGeneration = compiled.Identity.Generation
		}
		entry := fmt.Sprintf("generation=%d", compiled.Identity.Generation)
		if compiled.Revision != "" { // pod plans carry no revision
			entry += " revision=" + compiled.Revision
		}
		revisions[entry] = true
		if compiled.Identity.Generation != p.identity.Generation {
			stale = true
		}
	}
	for _, installed := range c.active {
		for _, compiled := range installed.plan.Policies {
			if compiled.Identity.UID != p.identity.UID {
				continue
			}
			if installed.protectionUnconfirmed {
				unconfirmed = true
				continue
			}
			count(compiled)
		}
	}
	// Pod cgroup bindings enforce too, even when no container binding does,
	// but only where the witness counters confirm it.
	if reporter, ok := c.backend.(PodPlanReporter); ok {
		confirmed, faulted := reporter.BoundPodPlans()
		for _, plan := range confirmed {
			for _, compiled := range plan.Policies {
				if compiled.Identity.UID == p.identity.UID {
					count(compiled)
				}
			}
		}
		for _, plan := range faulted {
			for _, compiled := range plan.Policies {
				if compiled.Identity.UID == p.identity.UID {
					unconfirmed = true
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
			// Last-good bindings still enforce through BPF LSM.
			if active == 0 {
				status.Tier = "none"
			}
			failure = errors.Join(failure, err)
		}
	}
	var network *NetworkReport
	if p.spec.Network != nil && p.spec.Mode != api.ModeOff {
		if err := c.sectionUnavailable(SectionNetwork); err != nil && c.options.EnforcementUnavailable == nil {
			if active == 0 {
				status.Tier = "none"
			}
			failure = errors.Join(failure, err)
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
			failure = errors.Join(failure, err)
		}
		if plan := c.filePlans[p.identity.UID]; plan != nil {
			r := NetworkReport(plan.Report)
			file = &r
		}
	}
	var uncertain *protectionError
	unconfirmed = unconfirmed || errors.As(failure, &uncertain)
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
				message = "Desired revision applied in part; installed bindings enforce it, but some bindings failed; see error"
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
			message = "Owned binding protection cannot be confirmed; workload may be unprotected; ownership retained only for recovery/cleanup"
			stale = true
		}
		status.Error, status.Truncated = boundedText(failure.Error(), api.MaxStatusErrorLength)
	} else if r, m := notReady(network, file); r != "" {
		// The policy enforces, with degraded defaults (see Degraded).
		ready, reason, message = metav1.ConditionFalse, r, m
	}
	status.Stale = stale
	status.Conditions = []metav1.Condition{{Type: "Ready", Status: ready, Reason: reason, Message: message, ObservedGeneration: p.identity.Generation, LastTransitionTime: now}}
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
	// Kernel bindings of the previous node-agent run that no container took
	// over yet still enforce its policies (restart survival): report the
	// revision they enforce, never the new one.
	if reporter, ok := c.backend.(AdoptionReporter); ok {
		var adopted []string
		for _, a := range reporter.Adopted() {
			for _, policy := range a.Policies {
				if policy.Policy.UID == p.identity.UID {
					adopted = append(adopted, fmt.Sprintf("%s slot %d: revision=%s generation=%d digest=%s bindings=%d", a.Section, a.Slot, policy.Revision, a.Generation, a.Digest, a.Bindings))
				}
			}
		}
		if len(adopted) > 0 {
			sort.Strings(adopted)
			summary, truncated := boundedText(strings.Join(adopted, "; "), api.MaxStatusDiagnosticLength)
			status.Truncated = status.Truncated || truncated
			status.Conditions = append(status.Conditions, metav1.Condition{Type: "AdoptedLastGood", Status: metav1.ConditionTrue, Reason: "RestartAdopted", Message: summary, ObservedGeneration: p.identity.Generation, LastTransitionTime: now})
		}
	}

	return &api.SandboxPolicyNodeStatus{
		TypeMeta:   metav1.TypeMeta{APIVersion: api.SchemeGroupVersion.String(), Kind: "SandboxPolicyNodeStatus"},
		ObjectMeta: metav1.ObjectMeta{Name: api.NodeStatusName(p.identity.UID, c.options.Node.UID), Namespace: namespace, OwnerReferences: []metav1.OwnerReference{{APIVersion: api.SchemeGroupVersion.String(), Kind: p.identity.Kind, Name: p.identity.Name, UID: p.identity.UID}}},
		Spec:       api.SandboxPolicyNodeStatusSpec{PolicyRef: api.SandboxPolicyReference{Kind: p.identity.Kind, Name: p.identity.Name, UID: p.identity.UID}, NodeRef: c.options.Node}, Status: status,
	}
}

// notReady returns the Ready=False reason and message when a section rule
// cannot be resolved or enforced, else "".
func notReady(network, file *NetworkReport) (string, string) {
	var reason string
	var parts []string
	if network != nil && network.NotReady != "" {
		reason = network.NotReady
		parts = append(parts, "network rule or except entry cannot be resolved; enforcement is kept (an enforce default deny over-blocks)")
	}
	if file != nil && file.NotReady != "" {
		if reason == "" {
			reason = file.NotReady
		}
		parts = append(parts, "file rule or except entry cannot be resolved or enforced; an unresolved class keeps enforcement, an unenforceable allow runs the defaults of its access kinds in audit")
	}
	if reason == "" {
		return "", ""
	}
	return reason, "A " + strings.Join(parts, "; a ") + "; see degraded"
}

func boundedText(value string, limit int) (string, bool) {
	if utf8.RuneCountInString(value) <= limit {
		return value, false
	}
	return string([]rune(value)[:limit]), true
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
