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
// If spec is nil, a zero-spec (no surfaces InUse) is used — all data dropped.
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
	opensPaths := extractOpensPaths(cp)
	pcp.Opens = projectField(s.Opens, opensPaths, true)

	execsPaths := extractExecsPaths(cp)
	pcp.Execs = projectField(s.Execs, execsPaths, true)

	endpointPaths := extractEndpointPaths(cp)
	pcp.Endpoints = projectField(s.Endpoints, endpointPaths, true)

	pcp.Capabilities = projectField(s.Capabilities, cp.Spec.Capabilities, false)
	pcp.Syscalls = projectField(s.Syscalls, cp.Spec.Syscalls, false)

	pcp.EgressDomains = projectField(s.EgressDomains, extractEgressDomains(cp), false)
	pcp.EgressAddresses = projectField(s.EgressAddresses, extractEgressAddresses(cp), false)

	pcp.IngressDomains = projectField(s.IngressDomains, extractIngressDomains(cp), false)
	pcp.IngressAddresses = projectField(s.IngressAddresses, extractIngressAddresses(cp), false)

	return pcp
}

// projectField is the per-surface transform. rawEntries are strings from the
// raw profile. isPathSurface enables retention of dynamic-segment entries.
func projectField(spec objectcache.FieldSpec, rawEntries []string, isPathSurface bool) objectcache.ProjectedField {
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
		isDynamic := isPathSurface && containsDynamicSegment(e)

		if isDynamic {
			// Dynamic entries go to Patterns regardless of spec content, as
			// long as the surface is in use (checked above).
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
	}
	return addrs
}

