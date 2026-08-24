package containerprofilenetwork

import (
	"net"
	"reflect"
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilehelper"
	"github.com/kubescape/storage/pkg/registry/file/networkmatch"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
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
	// CIDRs, "*" sentinels and wildcards: the network projection routes ALL
	// entries to Values (it calls projectField with isPathSurface=false, so
	// nothing is ever classified into Patterns). networkmatch.MatchIP matches
	// literals, CIDRs and "*" uniformly, so run it over the full entry set.
	entries := make([]string, 0, len(field.Values)+len(field.Patterns))
	for v := range field.Values {
		entries = append(entries, v)
	}
	entries = append(entries, field.Patterns...)
	return networkmatch.MatchIP(entries, observed)
}

// matchAddrPort reports whether observed (address, protocol, port) falls within
// any single neighbor entry: its addresses match AND the entry allows the port
// (nil Ports = no ports stanza = any port; a populated map matches literal keys only).
func matchAddrPort(groups []objectcache.AddrPortGroup, address, protocol string, port int32) bool {
	if address == "" {
		return false
	}
	key := objectcache.PortKey(protocol, port)
	for i := range groups {
		g := &groups[i]
		if !networkmatch.MatchIP(g.Addrs, address) {
			continue
		}
		if g.Ports == nil {
			return true
		}
		if _, ok := g.Ports[key]; ok {
			return true
		}
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
	// Leading-*, mid-⋯ and trailing-* DNS patterns also land in Values (network
	// surfaces never populate Patterns), so run MatchDNS over the full set.
	entries := make([]string, 0, len(field.Values)+len(field.Patterns))
	for v := range field.Values {
		entries = append(entries, v)
	}
	entries = append(entries, field.Patterns...)
	return networkmatch.MatchDNS(entries, observed)
}

func (l *containerProfileNetworkLibrary) wasAddressInEgress(containerID, address ref.Val) ref.Val {
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

func (l *containerProfileNetworkLibrary) wasAddressInIngress(containerID, address ref.Val) ref.Val {
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

func (l *containerProfileNetworkLibrary) isDomainInEgress(containerID, domain ref.Val) ref.Val {
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

func (l *containerProfileNetworkLibrary) isDomainInIngress(containerID, domain ref.Val) ref.Val {
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

func (l *containerProfileNetworkLibrary) wasAddressPortProtocolInEgress(containerID, address, port, protocol ref.Val) ref.Val {
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
	protocolStr, ok := protocol.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(protocol)
	}
	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}
	return types.Bool(matchAddrPort(cp.EgressAddrPorts, addressStr, protocolStr, int32(portInt)))
}

func (l *containerProfileNetworkLibrary) wasAddressPortProtocolInIngress(containerID, address, port, protocol ref.Val) ref.Val {
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
	protocolStr, ok := protocol.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(protocol)
	}
	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}
	return types.Bool(matchAddrPort(cp.IngressAddrPorts, addressStr, protocolStr, int32(portInt)))
}

// namespaceSelectorMatches matches a namespaceSelector against the peer's
// namespace via the implicit kubernetes.io/metadata.name label every namespace
// carries (the form these profiles use). A nil selector matches only the
// profiled workload's own namespace: the learned generator omits the selector
// exactly for same-namespace peers, and NetworkPolicyPeer gives an absent
// namespaceSelector the same meaning. Selectors keyed on other namespace
// labels are not resolved here.
func namespaceSelectorMatches(sel *metav1.LabelSelector, ns, profileNs string) bool {
	if sel == nil {
		return ns == profileNs
	}
	s, err := metav1.LabelSelectorAsSelector(sel)
	if err != nil {
		return false
	}
	return s.Matches(labels.Set{"kubernetes.io/metadata.name": ns})
}

// wasSelectorInPeers reports whether the peer identified by (podLabels, ns)
// matches any peer entry's podSelector AND its namespaceSelector.
func wasSelectorInPeers(peers []objectcache.PeerSelector, podLabels labels.Set, ns, profileNs string) bool {
	for i := range peers {
		peer := &peers[i]
		if peer.PodSelector == nil {
			continue
		}
		ps, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
		if err != nil {
			continue
		}
		if ps.Matches(podLabels) && namespaceSelectorMatches(peer.NamespaceSelector, ns, profileNs) {
			return true
		}
	}
	return false
}

func (l *containerProfileNetworkLibrary) wasSelectorInIngress(containerID, namespace, podLabels ref.Val) ref.Val {
	return l.wasSelectorIn(containerID, namespace, podLabels, true)
}

func (l *containerProfileNetworkLibrary) wasSelectorInEgress(containerID, namespace, podLabels ref.Val) ref.Val {
	return l.wasSelectorIn(containerID, namespace, podLabels, false)
}

// wasSelectorIn reports whether the runtime peer — identified by the namespace
// and pod labels that Inspektor Gadget's kubeipresolver stamps onto the network
// event — matches any of the profile's ingress-or-egress peer selectors.
//
// Matching on the peer's identity (namespace + labels) rather than its IP is the
// whole point: it is stable across pod IP churn AND works across nodes, because
// kubeipresolver resolves the peer against a cluster-wide pod inventory before
// the event ever reaches CEL. There is deliberately no IP→pod lookup here — that
// would reintroduce a dependency on node-agent's node-local pod cache, which is
// exactly what breaks cross-node peers.
func (l *containerProfileNetworkLibrary) wasSelectorIn(containerID, namespace, podLabels ref.Val, ingress bool) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}
	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	nsStr, ok := namespace.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(namespace)
	}
	if nsStr == "" {
		// The peer did not resolve to a pod (external IP, or the resolver had no
		// inventory entry): it cannot satisfy any selector. A resolved pod with
		// zero labels is NOT this case - an empty podSelector may still match it.
		return types.Bool(false)
	}
	peerLabels := refValToStringMap(podLabels)
	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}
	peers := cp.EgressPeers
	if ingress {
		peers = cp.IngressPeers
	}
	if len(peers) == 0 {
		return types.Bool(false)
	}
	return types.Bool(wasSelectorInPeers(peers, labels.Set(peerLabels), nsStr, cp.Namespace))
}

// refValToStringMap converts a CEL map argument to a Go map[string]string. A nil
// or non-map value yields nil (treated as "peer has no labels").
func refValToStringMap(v ref.Val) map[string]string {
	if v == nil {
		return nil
	}
	native, err := v.ConvertToNative(reflect.TypeOf(map[string]string(nil)))
	if err != nil {
		return nil
	}
	m, _ := native.(map[string]string)
	return m
}
