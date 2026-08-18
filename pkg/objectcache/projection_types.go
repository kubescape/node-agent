package objectcache

import (
	"github.com/kubescape/node-agent/pkg/objectcache/callstackcache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PeerSelector carries a single network-neighbor entry's identity selectors
// (podSelector + namespaceSelector) through the projection so the
// cp.was_selector_in_{ingress,egress} CEL helpers can resolve a runtime peer
// IP to a pod and match it by LABEL rather than by (volatile) IP. The address
// surfaces (Ingress/EgressAddresses) still carry the ipAddress/CIDR form for
// the was_address_in_* helpers; these are complementary.
type PeerSelector struct {
	PodSelector       *metav1.LabelSelector
	NamespaceSelector *metav1.LabelSelector
}

// PathMatcher is implemented by the trie-based matchers in containerprofilecache.
type PathMatcher interface {
	HasMatch(s string) bool
}

// RuleProjectionSpec is the compiled, immutable, hash-tagged union of all
// loaded rules' ProfileDataRequired declarations.
type RuleProjectionSpec struct {
	Opens            FieldSpec
	Execs            FieldSpec
	Capabilities     FieldSpec
	Syscalls         FieldSpec
	Endpoints        FieldSpec
	EgressDomains    FieldSpec
	EgressAddresses  FieldSpec
	IngressDomains   FieldSpec
	IngressAddresses FieldSpec

	Hash string // canonical FNV-64a content hash; populated by CompileSpec
}

// FieldSpec is the per-data-surface compiled declaration.
type FieldSpec struct {
	InUse    bool
	All      bool
	Exact    map[string]struct{}
	Prefixes []string
	Suffixes []string
	Contains []string

	// PrefixMatcher and SuffixMatcher are compiled by containerprofilecache.CompileSpec.
	// They are exported interfaces so CompileSpec (in a different package) can assign them.
	PrefixMatcher PathMatcher
	SuffixMatcher PathMatcher
}

// ProjectedContainerProfile is the cache-resident compact form. Pure node-agent
// internal type; never serialized. Replaces *v1beta1.ContainerProfile in the cache.
type ProjectedContainerProfile struct {
	// Namespace is the profiled workload's own namespace; a peer entry whose
	// NamespaceSelector is nil matches only peers in this namespace (the learned
	// encoding and the NetworkPolicyPeer semantic for an absent namespaceSelector).
	Namespace string

	Opens            ProjectedField
	Execs            ProjectedField
	Endpoints        ProjectedField
	Capabilities     ProjectedField
	Syscalls         ProjectedField
	EgressDomains    ProjectedField
	EgressAddresses  ProjectedField
	IngressDomains   ProjectedField
	IngressAddresses ProjectedField

	// IngressPeers / EgressPeers carry the podSelector+namespaceSelector of each
	// network-neighbor entry (dropped by the address/domain projection) so the
	// cp.was_selector_in_{ingress,egress} helpers can match a runtime peer by
	// label. Always projected in full (not gated by a rule surface) since they
	// are small and only populated when the profile actually declares selectors.
	IngressPeers []PeerSelector
	EgressPeers  []PeerSelector

	// ExecsByPath carries the per-Path Args slices from cp.Spec.Execs so
	// downstream consumers (e.g. dynamicpathdetector.CompareExecArgs used
	// by R0040 in node-agent#807) can run wildcard-aware argv matching
	// against the projected profile. Keyed by Exec.Path (same key used
	// in Execs.Values / Execs.Patterns); the value is a LIST of argv
	// vectors because a merged profile can contain multiple ExecCalls
	// entries with the same Path and different argv shapes — overlay
	// merge appends rather than replaces (mergeApplicationProfile in
	// storage). A consumer matches if ANY argv vector in the list
	// matches the runtime args. Empty/absent value means "no argv
	// constraint" (back-compat for pre-projection profiles).
	ExecsByPath map[string][][]string

	SpecHash       string
	SyncChecksum   string
	PolicyByRuleId map[string]v1beta1.RulePolicy
	CallStackTree  *callstackcache.CallStackSearchTree
}

// ProjectedField is the per-surface compact form read by CEL helpers.
// Composite-key carriers (flags, args, methods, ports) are out of scope for v1.
type ProjectedField struct {
	All        bool
	Values     map[string]struct{}
	Patterns   []string
	PrefixHits map[string]bool
	SuffixHits map[string]bool
}
