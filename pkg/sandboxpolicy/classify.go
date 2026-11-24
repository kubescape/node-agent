package sandboxpolicy

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
)

// classifySnap is an immutable view of the configuration, for the readers
// that must not take c.mu (ClassifyPod, PodPlans): Refresh holds c.mu across
// the API listings, so a reader under c.mu would wait on the API server.
// reconcile publishes one on every path (publishClassifySnap). Nothing in it
// is modified after publication.
type classifySnap struct {
	// configSeq is the controller's configSeq when the snapshot was built.
	configSeq   uint64
	configError error
	// policies are sorted by object key. A network or file section that did
	// not translate is an error of its policy.
	policies     []desiredPolicy
	classes      api.PolicyClasses
	classErrors  map[string]error
	networkPlans map[types.UID]*NetworkPlan
	filePlans    map[types.UID]*FilePlan
	clusterCIDRs ClusterCIDRs
}

// publishClassifySnap builds and swaps in the classification snapshot from
// c.objects, c.clusterCIDRs and c.configError. Called with c.mu held, from
// the defer at the top of reconcile. built is the configuration reconcile
// derived, or nil when it returned early; then the snapshot is built here,
// unless the published one is already at this configSeq.
func (c *Controller) publishClassifySnap(built *configBuild) {
	if built == nil {
		if prev := c.classify.Load(); prev != nil && prev.configSeq == c.configSeq {
			return
		}
	}
	snap := &classifySnap{configSeq: c.configSeq, configError: c.configError, clusterCIDRs: c.clusterCIDRs}
	if c.configError == nil {
		if built == nil {
			b := buildConfig(c.objects, c.clusterCIDRs, c.options.File)
			built = &b
		}
		snap.policies = make([]desiredPolicy, len(built.policies))
		for i, p := range built.policies {
			// A network or file section that did not translate fails the
			// container binding too (see reconcile).
			if p.err == nil && p.spec.Network != nil && p.spec.Mode != api.ModeOff && built.networkPlans[p.identity.UID] == nil {
				p.err = fmt.Errorf("network section is not translated")
			}
			if p.err == nil && p.spec.File != nil && p.spec.Mode != api.ModeOff && built.filePlans[p.identity.UID] == nil {
				p.err = fmt.Errorf("file section is not translated")
			}
			snap.policies[i] = p
		}
		snap.classes, snap.classErrors = built.classes, built.classErrors
		snap.networkPlans, snap.filePlans = built.networkPlans, built.filePlans
	}
	c.classify.Store(snap)
}

// PodClass is the start-gate class of a pod. The zero value is PodUnknown.
type PodClass int

const (
	// PodUnknown: the pod cannot be classified (Reason says why).
	PodUnknown PodClass = iota
	// PodUnselected: authoritatively, no active policy selects the pod, or
	// the pod is exempt.
	PodUnselected
	// PodSelected: at least one active policy selects a container of the pod.
	PodSelected
)

func (k PodClass) String() string {
	switch k {
	case PodUnselected:
		return "Unselected"
	case PodSelected:
		return "Selected"
	}
	return "Unknown"
}

// PodShape flags the shapes of a selected pod that a pod binding cannot
// express.
type PodShape uint8

const (
	// ShapeSources: a selecting policy has ContainerProfile sources, which
	// only a container binding resolves.
	ShapeSources PodShape = 1 << iota
	// ShapeDifferentSets: the containers of the pod (init containers
	// included) get different sets of a section's policies.
	ShapeDifferentSets
	// ShapeContainerInPodCgroup: the container runs in the pod cgroup itself
	// (detected at CreateContainer by the caller).
	ShapeContainerInPodCgroup
)

// SectionPlan is the pod plan of one section (privilege, network or file):
// the policies every container of the pod gets in that section, holding only
// that section. Digest is SectionDigest(Plan, section), a memo key only:
// it lets a caller tell whether two classifications of a pod gave the same
// section plan. The backend never sees it: ConfirmPod and MarkPod take the
// Plan and compare the backend's own combination keys, so Digest must never
// be compared with a backend string.
type SectionPlan struct {
	Plan   Plan
	Digest string
	// Strict: a policy of the section is in enforce mode.
	Strict bool
}

// PodClassification is the result of ClassifyPod.
type PodClassification struct {
	Class PodClass
	// Reason says why the pod is Unknown, or Unselected ("exempt").
	Reason string
	// Exempt: the exemption annotation exempts the pod (Unselected).
	//
	// A container form (<key>/container.<name>) exempts only that container
	// at CreateContainer, while RunPodSandbox may have put a pending mark on
	// the pod cgroup, which then judges the exempt container too (Strict:
	// EPERM, fail-closed). S5 must decide this case.
	Exempt bool
	// ExemptButSelected: the pod is exempt and an active policy selects it
	// (Reason names the policy). The class stays Unselected (exempt); the
	// flag is for logs, counters and alerts. Admission (N1 §3) remains the
	// place that refuses the conflict. It is evaluated only from the
	// snapshot and a cache Lookup, never a Fetch, so it is false when either
	// is unavailable.
	ExemptButSelected bool
	// The rest is set for a Selected pod only.
	// Sections holds the plan of each section whose policies are the same
	// nonempty set in every container. It is empty when Shape has
	// ShapeSources.
	Sections map[string]SectionPlan
	// Exec: a selecting policy has exec rules (an exec section or sources).
	Exec bool
	// Strict: a selecting policy is in enforce mode.
	Strict bool
	Shape  PodShape
	// Policies are the identities of the policies that select a container
	// of the pod, sorted by UID (Selected only). The start gate's status
	// attributes a pod's state to them.
	Policies []PolicyIdentity
	// Seq is the sequence of the inputs the classification read: the
	// snapshot's configSeq and the input epoch.
	Seq Seq
}

// NRIPod is what the NRI payload says about a pod sandbox.
type NRIPod struct {
	UID         types.UID
	Namespace   string
	Name        string
	Annotations map[string]string
}

// PodContainer is a container declared in the pod spec. Kind is regular,
// init or ephemeral.
type PodContainer struct {
	Name string
	Kind string
}

// PodFacts is the API view of a pod and its namespace.
type PodFacts struct {
	UID             types.UID
	Labels          map[string]string
	Annotations     map[string]string
	Containers      []PodContainer
	NamespaceLabels map[string]string
}

// PodSource gives ClassifyPod its inputs besides the snapshot.
type PodSource struct {
	// ExemptionKey is the configured exemption annotation key; empty: no
	// exemption. Its effective forms are those of the NRI validator:
	// <key>/container.<name>, <key>/pod and <key>, in that order.
	ExemptionKey string
	// InputEpoch reads the input epoch of the informer data. Required.
	InputEpoch func() uint64
	// Lookup reads the pod and its namespace from the informer caches; ok
	// is false when either is not cached. It must not block. Required.
	Lookup func(namespace, name string) (PodFacts, bool)
	// Fetch, when set, reads a pod the informer misses (and its namespace)
	// from the API server, bounded by ctx (the caller's deadline). S5 sets
	// it; without it a miss is Unknown.
	Fetch func(ctx context.Context, namespace, name string) (PodFacts, bool)
}

// ClassifyRequest is one classification.
type ClassifyRequest struct {
	Pod NRIPod
	// Container is the container being created (CreateContainer); empty at
	// RunPodSandbox and Synchronize.
	Container string
	// ContainerInPodCgroup: the container runs in the pod cgroup itself.
	// Set at CreateContainer only.
	ContainerInPodCgroup bool
}

const (
	configSourceAnnotation = "kubernetes.io/config.source"
	configMirrorAnnotation = "kubernetes.io/config.mirror"
)

// ClassifyPod classifies a pod for the start gate. It reads only the
// classification snapshot and the PodSource, never c.mu, so it does not wait
// on a reconcile or the API server (except through src.Fetch, bounded by
// ctx). Callers must not hold the backend lock (b.mu) while classifying.
// The rules, in order:
//  1. the exemption annotation, from the NRI payload: Unselected (Exempt),
//     flagged ExemptButSelected when a policy selects the pod;
//  2. a static pod is classified from its mirror pod (the mirror annotation
//     names the static pod's UID), otherwise Unknown;
//  3. a pod the informer misses (or whose UID differs): src.Fetch, otherwise
//     Unknown;
//  4. no snapshot, or a configuration error: Unknown; a policy in scope for
//     the pod with an error (a SandboxPolicy of its namespace, any
//     ClusterSandboxPolicy) is Unknown, as selectorFor; a selecting policy
//     with a class or compile error: Unknown; more than
//     MaxPoliciesPerBinding policies selecting one container: Unknown;
//  5. otherwise Selected, with the shapes a pod binding cannot express, or
//     Unselected when no active policy selects a container of the pod.
func (c *Controller) ClassifyPod(ctx context.Context, req ClassifyRequest, src PodSource) PodClassification {
	snap := c.classify.Load()
	var configSeq uint64
	if snap != nil {
		configSeq = snap.configSeq
	}
	unknown := func(seq Seq, format string, args ...any) PodClassification {
		return PodClassification{Class: PodUnknown, Reason: fmt.Sprintf(format, args...), Seq: seq}
	}
	if src.InputEpoch == nil || src.Lookup == nil {
		return unknown(Seq{Config: configSeq}, "no pod source")
	}
	// 1. The exemption needs no other input: an exempt pod starts while the
	// API or the policies are unavailable.
	exempt, containerScoped, err := exempted(req.Pod.Annotations, src.ExemptionKey, req.Container)
	if err != nil {
		return unknown(Seq{Config: configSeq, Input: src.InputEpoch()}, "%v", err)
	}
	static := req.Pod.Annotations[configSourceAnnotation] != "" && req.Pod.Annotations[configSourceAnnotation] != "api"
	matches := func(f PodFacts) bool {
		if static {
			return f.Annotations[configMirrorAnnotation] == string(req.Pod.UID) && req.Pod.UID != ""
		}
		return f.UID == req.Pod.UID && req.Pod.UID != ""
	}
	if exempt {
		out := PodClassification{Class: PodUnselected, Reason: "exempt", Exempt: true, Seq: Seq{Config: configSeq, Input: src.InputEpoch()}}
		if snap != nil && snap.configError == nil {
			if f, ok := src.Lookup(req.Pod.Namespace, req.Pod.Name); ok && matches(f) {
				// A container-form exemption exempts that container only:
				// only its selection matters.
				only := ""
				if containerScoped {
					only = req.Container
				}
				if name := selectedBy(snap, req.Pod, f, only); name != "" {
					out.ExemptButSelected = true
					out.Reason = "exempt, but selected by " + name
				}
			}
		}
		return out
	}
	// 4, first part, before any lookup: it needs no pod input, and an
	// Unknown here must not wait for a GET.
	if snap == nil {
		return unknown(Seq{Input: src.InputEpoch()}, "no classification snapshot yet")
	}
	if snap.configError != nil {
		return unknown(Seq{Config: configSeq, Input: src.InputEpoch()}, "configuration unavailable: %v", snap.configError)
	}
	// 2 and 3.
	type found struct {
		facts PodFacts
		ok    bool
	}
	got, epoch := CaptureInputs(src.InputEpoch, func() found {
		f, ok := src.Lookup(req.Pod.Namespace, req.Pod.Name)
		return found{f, ok && matches(f)}
	})
	seq := Seq{Config: configSeq, Input: epoch}
	if !got.ok && src.Fetch != nil {
		// Data read after epoch is at least as new as epoch.
		f, ok := src.Fetch(ctx, req.Pod.Namespace, req.Pod.Name)
		got = found{f, ok && matches(f)}
	}
	if !got.ok {
		if static {
			return unknown(seq, "static pod %s/%s has no mirror pod with its UID", req.Pod.Namespace, req.Pod.Name)
		}
		return unknown(seq, "pod %s/%s (%s) is not known", req.Pod.Namespace, req.Pod.Name, req.Pod.UID)
	}
	return classify(snap, req, got.facts, seq)
}

// exempted reports whether the effective exemption annotation is true, and
// whether that annotation is the container form. As the NRI default
// validator, the container form is read first, then the pod forms; a value
// that is not a boolean is an error.
func exempted(annotations map[string]string, key, container string) (exempt, containerScoped bool, err error) {
	if key == "" {
		return false, false, nil
	}
	keys := []string{key + "/pod", key}
	if container != "" {
		keys = append([]string{key + "/container." + container}, keys...)
	}
	for i, k := range keys {
		if v, ok := annotations[k]; ok {
			exempt, err := strconv.ParseBool(v)
			if err != nil {
				return false, false, fmt.Errorf("invalid exemption annotation %s=%q: %w", k, v, err)
			}
			return exempt, container != "" && i == 0, nil
		}
	}
	return false, false, nil
}

// selectedBy returns "Kind namespace/name" of the first valid active policy
// that selects a container of the pod (only the container named only, when
// set), or "".
func selectedBy(snap *classifySnap, pod NRIPod, facts PodFacts, only string) string {
	for _, pc := range facts.Containers {
		if only != "" && pc.Name != only {
			continue
		}
		b := Binding{PodUID: pod.UID, Namespace: pod.Namespace, PodName: pod.Name, ContainerName: pc.Name, Kind: pc.Kind, PodLabels: facts.Labels, NamespaceLabels: facts.NamespaceLabels}
		for _, p := range snap.policies {
			if p.err == nil && p.spec.Mode != api.ModeOff && p.matches(b) {
				return p.identity.Kind + " " + p.identity.Namespace + "/" + p.identity.Name
			}
		}
	}
	return ""
}

// SectionDigest is the digest of one section (privilege, network or file)
// of a plan: the section revision of SectionBackend.split (sectionRevision).
// "" for a plan with no policy of the section, or an unknown section.
func SectionDigest(plan Plan, section string) string {
	for _, sec := range sectionParts {
		if sec.name == section {
			return sectionRevision(plan.Policies, sec.part)
		}
	}
	return ""
}

// classify applies rules 4 and 5 to a pod the informer knows.
func classify(snap *classifySnap, req ClassifyRequest, facts PodFacts, seq Seq) PodClassification {
	unknown := func(format string, args ...any) PodClassification {
		return PodClassification{Class: PodUnknown, Reason: fmt.Sprintf(format, args...), Seq: seq}
	}
	// A policy in scope with an error may select the pod: its selector or
	// sections cannot be trusted (selectorFor).
	for _, p := range snap.policies {
		if p.identity.Kind == "SandboxPolicy" && p.identity.Namespace != req.Pod.Namespace {
			continue
		}
		if p.err != nil {
			return unknown("%s %s/%s is in scope and has an error: %v", p.identity.Kind, p.identity.Namespace, p.identity.Name, p.err)
		}
	}
	if len(facts.Containers) == 0 {
		return unknown("pod %s/%s declares no container", req.Pod.Namespace, req.Pod.Name)
	}
	for _, pc := range facts.Containers {
		// "*" matches the kind "regular" only: another spelling would drop
		// the container from wildcard policies.
		if pc.Kind != "regular" && pc.Kind != "init" && pc.Kind != "ephemeral" {
			return unknown("container %s has an invalid kind %q", pc.Name, pc.Kind)
		}
	}
	if req.Container != "" && !slices.ContainsFunc(facts.Containers, func(pc PodContainer) bool { return pc.Name == req.Container }) {
		return unknown("container %s is not in the pod spec", req.Container)
	}
	out := PodClassification{Class: PodSelected, Seq: seq}
	selecting := map[types.UID]PolicyIdentity{}
	// most is the largest number of policies selecting one container: the
	// cap is per container, as for a container binding.
	most := 0
	// perContainer holds, per container, the compiled policies that have a
	// privilege, network or file section.
	perContainer := make([][]CompiledPolicy, 0, len(facts.Containers))
	for _, pc := range facts.Containers {
		b := Binding{PodUID: req.Pod.UID, Namespace: req.Pod.Namespace, PodName: req.Pod.Name, ContainerName: pc.Name, Kind: pc.Kind, PodLabels: facts.Labels, NamespaceLabels: facts.NamespaceLabels}
		var compiled []CompiledPolicy
		count := 0
		for _, p := range snap.policies {
			if p.spec.Mode == api.ModeOff || !p.matches(b) {
				continue
			}
			count++
			selecting[p.identity.UID] = p.identity
			out.Strict = out.Strict || p.spec.Mode == api.ModeEnforce
			out.Exec = out.Exec || p.hasExec()
			if len(p.spec.Sources) > 0 {
				// Needs the ContainerProfile, which only the container
				// binding resolves.
				out.Shape |= ShapeSources
				continue
			}
			if err := policyClassError(p, snap.classErrors); err != nil {
				return unknown("policy %s/%s: class error: %v", p.identity.Namespace, p.identity.Name, err)
			}
			if _, err := Compile(context.Background(), p.identity, p.spec, snap.classes, b, nil); err != nil {
				return unknown("policy %s/%s does not compile: %v", p.identity.Namespace, p.identity.Name, err)
			}
			cp := CompiledPolicy{Identity: p.identity, Mode: p.spec.Mode, Privilege: p.spec.Privilege.DeepCopy(), Network: snap.networkPlans[p.identity.UID], File: snap.filePlans[p.identity.UID]}
			if cp.Privilege != nil || cp.Network != nil || cp.File != nil {
				compiled = append(compiled, cp)
			}
		}
		most = max(most, count)
		perContainer = append(perContainer, compiled)
	}
	if most > MaxPoliciesPerBinding {
		return unknown("%d policies select one container of the pod (at most %d)", most, MaxPoliciesPerBinding)
	}
	if len(selecting) == 0 {
		return PodClassification{Class: PodUnselected, Reason: "unselected", Seq: seq}
	}
	for _, id := range selecting {
		out.Policies = append(out.Policies, id)
	}
	slices.SortFunc(out.Policies, func(a, b PolicyIdentity) int { return cmp.Compare(a.UID, b.UID) })
	if req.ContainerInPodCgroup {
		out.Shape |= ShapeContainerInPodCgroup
	}
	if out.Shape&ShapeSources != 0 {
		return out
	}
	out.Sections = map[string]SectionPlan{}
	for _, sec := range sectionParts {
		// The section's policies of each container, sorted by UID.
		sets := make([][]CompiledPolicy, len(perContainer))
		for i, compiled := range perContainer {
			for _, p := range compiled {
				if sec.part(p) == nil {
					continue
				}
				only := p
				for _, other := range sectionParts {
					if other.name != sec.name {
						other.strip(&only)
					}
				}
				sets[i] = append(sets[i], only)
			}
			slices.SortFunc(sets[i], func(a, b CompiledPolicy) int {
				return cmp.Compare(a.Identity.UID, b.Identity.UID)
			})
		}
		same := true
		for _, set := range sets[1:] {
			same = same && samePolicies(Plan{Policies: sets[0]}, Plan{Policies: set})
		}
		if !same {
			out.Shape |= ShapeDifferentSets
			continue
		}
		if len(sets[0]) == 0 {
			continue
		}
		plan := Plan{Policies: sets[0]}
		plan.Revision = digest(plan.Policies)
		strict := slices.ContainsFunc(plan.Policies, func(p CompiledPolicy) bool { return p.Mode == api.ModeEnforce })
		out.Sections[sec.name] = SectionPlan{Plan: plan, Digest: SectionDigest(plan, sec.name), Strict: strict}
	}
	return out
}
