package objectcache

import (
	"github.com/kubescape/node-agent/pkg/objectcache/callstackcache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

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
	Opens            ProjectedField
	Execs            ProjectedField
	Endpoints        ProjectedField
	Capabilities     ProjectedField
	Syscalls         ProjectedField
	EgressDomains    ProjectedField
	EgressAddresses  ProjectedField
	IngressDomains   ProjectedField
	IngressAddresses ProjectedField

	// ExecsByPath carries the per-Path Args slices from cp.Spec.Execs so
	// downstream consumers (ap.was_executed_with_args + R0040) can run
	// argv-vector matching against the projected profile. Keyed by
	// Exec.Path (same key used in Execs.Values / Execs.Patterns); the
	// value is a LIST of argv vectors because a merged profile can carry
	// multiple ExecCalls entries with the same Path and different argv
	// shapes — overlay merge appends rather than replaces, and the
	// consumer matches if ANY vector matches the runtime args.
	// Empty/absent key means "no argv constraint" (back-compat for
	// pre-projection profiles).
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
