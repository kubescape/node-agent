package networkneighborhood

import (
	"net"
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilehelper"
	"github.com/kubescape/storage/pkg/registry/file/networkmatch"
)

// matchIPField is the wildcard-aware adapter from the projection layer's
// ProjectedField (Values exact-set + Patterns slice) to the v0.0.2 wildcard
// semantics implemented in storage's networkmatch package.
//
// Order of checks (cheapest first):
//  1. Values map — exact byte equality
//  2. Patterns slice — CIDRs, '*' sentinels, RFC 4592 leading wildcards,
//     mid-⋯, trailing-* (via networkmatch.MatchIP)
//
// ProjectedField.All is intentionally NOT consulted as a match short-circuit:
// it's the producer-side flag set when projectField is in pass-through
// retention mode (no rule declared profileDataRequired for this surface),
// in which case projectField has already populated Values with every raw
// entry. Treating it as a "match any" sentinel here would let unknown IPs
// match when they're absent from the profile (CR #43, finding R-NET-7).
//
// Cold-path use only: the existing CEL functionCache in nn.go memoises
// (containerID, observed) for the TTL window, so per-call MatchIP/MatchDNS
// cost only fires on cache misses.
func matchIPField(field *objectcache.ProjectedField, observed string) bool {
	if observed == "" || field == nil {
		return false
	}
	// Exact-string lookup first (cheapest).
	if _, ok := field.Values[observed]; ok {
		return true
	}
	// IP canonicalisation: observed "::ffff:10.0.0.1" should hit a profile
	// entry of "10.0.0.1", and expanded IPv6 should hit compact IPv6.
	// Single net.ParseIP per call; only fires on Values miss.
	if parsed := net.ParseIP(observed); parsed != nil {
		if _, ok := field.Values[parsed.String()]; ok {
			return true
		}
	}
	if len(field.Patterns) > 0 && networkmatch.MatchIP(field.Patterns, observed) {
		return true
	}
	return false
}

func matchDNSField(field *objectcache.ProjectedField, observed string) bool {
	if observed == "" || field == nil {
		return false
	}
	// FQDN trailing-dot normalisation per spec §5.8: both profile entries
	// and observed names MAY or MAY NOT carry a trailing dot. Try both
	// canonical forms against Values; cheaper than a per-call MatchDNS.
	canon := strings.TrimSuffix(observed, ".")
	if _, ok := field.Values[canon]; ok {
		return true
	}
	if _, ok := field.Values[canon+"."]; ok {
		return true
	}
	if len(field.Patterns) > 0 && networkmatch.MatchDNS(field.Patterns, observed) {
		return true
	}
	return false
}

func (l *nnLibrary) wasAddressInEgress(containerID, address ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}
	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	addressStr, ok := address.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(address)
	}
	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}
	return types.Bool(matchIPField(&cp.EgressAddresses, addressStr))
}

func (l *nnLibrary) wasAddressInIngress(containerID, address ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}
	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	addressStr, ok := address.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(address)
	}
	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}
	return types.Bool(matchIPField(&cp.IngressAddresses, addressStr))
}

func (l *nnLibrary) isDomainInEgress(containerID, domain ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}
	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	domainStr, ok := domain.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(domain)
	}
	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}
	return types.Bool(matchDNSField(&cp.EgressDomains, domainStr))
}

func (l *nnLibrary) isDomainInIngress(containerID, domain ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}
	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	domainStr, ok := domain.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(domain)
	}
	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}
	return types.Bool(matchDNSField(&cp.IngressDomains, domainStr))
}

func (l *nnLibrary) wasAddressPortProtocolInEgress(containerID, address, port, protocol ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}
	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	addressStr, ok := address.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(address)
	}
	// port/protocol projection (AddressPortsByAddr) is out of scope for the
	// projection-v1 layer upstream landed; matchers degrade to address-only.
	// Wildcards remain enforced via matchIPField.
	portInt, ok := port.Value().(int64)
	if !ok {
		return types.MaybeNoSuchOverloadErr(port)
	}
	if portInt < 0 || portInt > 65535 {
		return types.Bool(false)
	}
	if _, ok := protocol.Value().(string); !ok {
		return types.MaybeNoSuchOverloadErr(protocol)
	}
	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}
	return types.Bool(matchIPField(&cp.EgressAddresses, addressStr))
}

func (l *nnLibrary) wasAddressPortProtocolInIngress(containerID, address, port, protocol ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}
	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	addressStr, ok := address.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(address)
	}
	portInt, ok := port.Value().(int64)
	if !ok {
		return types.MaybeNoSuchOverloadErr(port)
	}
	if portInt < 0 || portInt > 65535 {
		return types.Bool(false)
	}
	if _, ok := protocol.Value().(string); !ok {
		return types.MaybeNoSuchOverloadErr(protocol)
	}
	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}
	return types.Bool(matchIPField(&cp.IngressAddresses, addressStr))
}
