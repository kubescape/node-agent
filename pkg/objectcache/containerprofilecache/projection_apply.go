package containerprofilecache

import (
	"maps"
	"slices"
	"strings"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/objectcache/callstackcache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
)

// Apply transforms a raw ContainerProfile into a ProjectedContainerProfile
// under the given spec. Pure function: no I/O, no mutation of inputs.
// If spec is nil, a zero-spec is used — InUse=false on every field triggers
// pass-through, retaining all raw data.
// callStackTree is built by the caller and passed in so Apply stays a pure
// data transform.
func Apply(spec *objectcache.RuleProjectionSpec, cp *v1beta1.ContainerProfile, callStackTree *callstackcache.CallStackSearchTree) *objectcache.ProjectedContainerProfile {
	var s objectcache.RuleProjectionSpec
	if spec != nil {
		s = *spec
	}

	pcp := &objectcache.ProjectedContainerProfile{
		SpecHash:      s.Hash,
		CallStackTree: callStackTree,
	}

	if cp == nil {
		return pcp
	}

	if cp.Annotations != nil {
		pcp.SyncChecksum = cp.Annotations[helpersv1.SyncChecksumMetadataKey]
	}

	// Shallow copy PolicyByRuleId — values are value-typed structs.
	if len(cp.Spec.PolicyByRuleId) > 0 {
		pcp.PolicyByRuleId = make(map[string]v1beta1.RulePolicy, len(cp.Spec.PolicyByRuleId))
		maps.Copy(pcp.PolicyByRuleId, cp.Spec.PolicyByRuleId)
	}

	// Project each data surface.
	// The third arg classifies an entry as "dynamic" — routes it to Patterns
	// rather than Values. Path surfaces use the ⋯ DynamicIdentifier marker;
	// network surfaces accept CIDRs, '*' sentinels, and DNS wildcard tokens
	// per the v0.0.2 spec (matched at runtime by storage's networkmatch).
	opensPaths := extractOpensPaths(cp)
	pcp.Opens = projectField(s.Opens, opensPaths, containsDynamicSegment)

	execsPaths := extractExecsPaths(cp)
	pcp.Execs = projectField(s.Execs, execsPaths, containsDynamicSegment)
	pcp.ExecsByPath = extractExecsByPath(cp)

	endpointPaths := extractEndpointPaths(cp)
	pcp.Endpoints = projectField(s.Endpoints, endpointPaths, containsDynamicSegment)

	pcp.Capabilities = projectField(s.Capabilities, cp.Spec.Capabilities, nil)
	pcp.Syscalls = projectField(s.Syscalls, cp.Spec.Syscalls, nil)

	pcp.EgressDomains = projectField(s.EgressDomains, extractEgressDomains(cp), isNetworkDNSWildcard)
	pcp.EgressAddresses = projectField(s.EgressAddresses, extractEgressAddresses(cp), isNetworkIPWildcard)

	pcp.IngressDomains = projectField(s.IngressDomains, extractIngressDomains(cp), isNetworkDNSWildcard)
	pcp.IngressAddresses = projectField(s.IngressAddresses, extractIngressAddresses(cp), isNetworkIPWildcard)

	return pcp
}

// projectField is the per-surface transform. rawEntries are strings from the
// raw profile. isDynamic, if non-nil, is called per entry: returning true
// routes the entry to Patterns rather than Values (cache-miss path runs the
// matcher rather than a map lookup).
func projectField(spec objectcache.FieldSpec, rawEntries []string, isDynamic func(string) bool) objectcache.ProjectedField {
	if !spec.InUse {
		// No rule declared a requirement for this field — pass all raw entries
		// through so existing rules that omit profileDataRequired keep working.
		spec.All = true
	}

	pf := objectcache.ProjectedField{
		All:        spec.All,
		Values:     make(map[string]struct{}),
		PrefixHits: make(map[string]bool, len(spec.Prefixes)),
		SuffixHits: make(map[string]bool, len(spec.Suffixes)),
	}

	// Pre-populate hit maps with false for every declared prefix/suffix.
	for _, p := range spec.Prefixes {
		pf.PrefixHits[p] = false
	}
	for _, s := range spec.Suffixes {
		pf.SuffixHits[s] = false
	}

	seen := make(map[string]bool) // for Patterns dedup

	for _, e := range rawEntries {
		dynamic := isDynamic != nil && isDynamic(e)

		if dynamic {
			// Dynamic entries always go to Patterns on path surfaces (both
			// pass-through and explicit InUse modes).
			if !seen[e] {
				seen[e] = true
				pf.Patterns = append(pf.Patterns, e)
			}
		} else if spec.All {
			pf.Values[e] = struct{}{}
		} else {
			retained := false
			if _, ok := spec.Exact[e]; ok {
				retained = true
			} else if spec.PrefixMatcher != nil && spec.PrefixMatcher.HasMatch(e) {
				retained = true
			} else if spec.SuffixMatcher != nil && spec.SuffixMatcher.HasMatch(e) {
				retained = true
			} else if containsMatch(spec.Contains, e) {
				retained = true
			}
			if retained {
				pf.Values[e] = struct{}{}
			}
		}

		// Update PrefixHits / SuffixHits for every raw entry (including dynamic).
		for _, p := range spec.Prefixes {
			if strings.HasPrefix(e, p) {
				pf.PrefixHits[p] = true
			}
		}
		for _, s := range spec.Suffixes {
			if strings.HasSuffix(e, s) {
				pf.SuffixHits[s] = true
			}
		}
	}

	// Deduplicate and sort Patterns for idempotency.
	slices.Sort(pf.Patterns)

	if len(pf.Values) == 0 {
		pf.Values = nil
	}

	return pf
}

// containsDynamicSegment reports whether e contains the dynamic-path marker.
// Always references the constant from the storage package; never hardcodes the glyph.
func containsDynamicSegment(e string) bool {
	return strings.Contains(e, dynamicpathdetector.DynamicIdentifier)
}

// isNetworkIPWildcard reports whether an IP-surface entry is a v0.0.2
// pattern (CIDR membership, '*' any-IP sentinel, or DynamicIdentifier).
// Literal IPv4/IPv6 addresses are NOT patterns; they go to Values for
// the cheap map lookup path. Spec §5.7.
func isNetworkIPWildcard(e string) bool {
	if e == "" {
		return false
	}
	if e == "*" {
		return true
	}
	if strings.Contains(e, "/") {
		return true
	}
	if strings.Contains(e, dynamicpathdetector.DynamicIdentifier) {
		return true
	}
	return false
}

// isNetworkDNSWildcard reports whether a DNS-surface entry uses any of
// the v0.0.2 wildcard tokens — leading '*' (RFC 4592), mid '⋯', trailing
// '*'. Literal FQDNs go to Values. Spec §5.8.
func isNetworkDNSWildcard(e string) bool {
	if e == "" {
		return false
	}
	if strings.Contains(e, "*") {
		return true
	}
	if strings.Contains(e, dynamicpathdetector.DynamicIdentifier) {
		return true
	}
	return false
}

// --- Field extractors ---

func extractOpensPaths(cp *v1beta1.ContainerProfile) []string {
	paths := make([]string, len(cp.Spec.Opens))
	for i, o := range cp.Spec.Opens {
		paths[i] = o.Path
	}
	return paths
}

func extractExecsPaths(cp *v1beta1.ContainerProfile) []string {
	paths := make([]string, len(cp.Spec.Execs))
	for i, e := range cp.Spec.Execs {
		paths[i] = e.Path
	}
	return paths
}

// extractExecsByPath builds the path → args map used by the exec-args
// wildcard matcher (CompareExecArgs). Multiple ExecCalls entries with the
// same Path collapse to the last seen; this matches the prior fork-only
// behavior. nil-Args entries are stored as empty slices, which
// CompareExecArgs treats as "no argv constraint".
//
// Args slices are CLONED rather than aliased — Apply is contract-bound to
// be a pure transform, and an alias would let consumers mutate the source
// profile by editing the projected map. (CR #43 finding on this file.)
func extractExecsByPath(cp *v1beta1.ContainerProfile) map[string][]string {
	if len(cp.Spec.Execs) == 0 {
		return nil
	}
	m := make(map[string][]string, len(cp.Spec.Execs))
	for _, e := range cp.Spec.Execs {
		if e.Args == nil {
			m[e.Path] = []string{}
			continue
		}
		cloned := make([]string, len(e.Args))
		copy(cloned, e.Args)
		m[e.Path] = cloned
	}
	return m
}

func extractEndpointPaths(cp *v1beta1.ContainerProfile) []string {
	endpoints := make([]string, len(cp.Spec.Endpoints))
	for i, e := range cp.Spec.Endpoints {
		endpoints[i] = e.Endpoint
	}
	return endpoints
}

func extractEgressDomains(cp *v1beta1.ContainerProfile) []string {
	var domains []string
	for _, n := range cp.Spec.Egress {
		if n.DNS != "" {
			domains = append(domains, n.DNS)
		}
		domains = append(domains, n.DNSNames...)
	}
	return domains
}

func extractEgressAddresses(cp *v1beta1.ContainerProfile) []string {
	var addrs []string
	for _, n := range cp.Spec.Egress {
		if n.IPAddress != "" {
			addrs = append(addrs, n.IPAddress)
		}
		// v0.0.2 IPAddresses[] — list form supporting CIDRs and '*' sentinel.
		// Same semantics as the deprecated singular IPAddress, just plural.
		addrs = append(addrs, n.IPAddresses...)
	}
	return addrs
}

func extractIngressDomains(cp *v1beta1.ContainerProfile) []string {
	var domains []string
	for _, n := range cp.Spec.Ingress {
		if n.DNS != "" {
			domains = append(domains, n.DNS)
		}
		domains = append(domains, n.DNSNames...)
	}
	return domains
}

func extractIngressAddresses(cp *v1beta1.ContainerProfile) []string {
	var addrs []string
	for _, n := range cp.Spec.Ingress {
		if n.IPAddress != "" {
			addrs = append(addrs, n.IPAddress)
		}
		addrs = append(addrs, n.IPAddresses...)
	}
	return addrs
}

