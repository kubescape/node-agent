package networkpeer

import (
	"strings"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// ExpandServiceNeighbors resolves every serviceRef / serviceSelector / entity
// neighbor in the list against the cluster view and returns equivalent
// synthesized ipAddresses neighbors (one per source neighbor, carrying the
// resolved IPs and the source neighbor's own ports).
//
// The synthesized neighbors are ordinary selector-free ipAddresses entries
// (plus, for Service-backed specs, the Service's cluster FQDN as a dnsName so a
// client dialling it by name is allowlisted too), so the existing
// port-sensitive address matcher and DNS matcher handle them with no further
// change — a serviceRef/host neighbor becomes exactly the narrow, resolved
// entry it stands for. Neighbors that resolve to nothing (unknown
// Service, selector matching nothing, unknown entity) contribute nothing —
// never a match-all. Callers append the result to the same direction (egress
// or ingress) before projecting the profile.
func ExpandServiceNeighbors(neighbors []v1beta1.NetworkNeighbor, l Lister) []v1beta1.NetworkNeighbor {
	if l == nil {
		return nil
	}
	var out []v1beta1.NetworkNeighbor
	for i := range neighbors {
		n := &neighbors[i]
		spec, ok := specFromNeighbor(n)
		if !ok {
			continue
		}
		ips := ResolveIPs(spec, l)
		dnsNames := ResolveDNSNames(spec, l)
		if len(ips) == 0 && len(dnsNames) == 0 {
			continue
		}
		out = append(out, v1beta1.NetworkNeighbor{
			Identifier:  n.Identifier + "-resolved",
			Type:        n.Type,
			IPAddresses: ips,
			DNSNames:    dnsNames,
			Ports:       n.Ports,
		})
	}
	return out
}

// WithResolvedServiceNeighbors returns cp with every serviceRef/serviceSelector/
// entity neighbor expanded into equivalent selector-free ipAddresses neighbors
// (appended to the same direction), so the projection's existing address
// surface enforces them. It is a no-op — returning cp unchanged — when the
// lister is nil or nothing resolves, and it never mutates the input: a copy is
// made only when there is something to add. Call it immediately before
// projecting a ContainerProfile.
func WithResolvedServiceNeighbors(cp *v1beta1.ContainerProfile, l Lister) *v1beta1.ContainerProfile {
	if cp == nil || l == nil {
		return cp
	}
	egExtra := ExpandServiceNeighbors(cp.Spec.Egress, l)
	inExtra := ExpandServiceNeighbors(cp.Spec.Ingress, l)
	if len(egExtra) == 0 && len(inExtra) == 0 {
		return cp
	}
	out := cp.DeepCopy()
	out.Spec.Egress = append(out.Spec.Egress, egExtra...)
	out.Spec.Ingress = append(out.Spec.Ingress, inExtra...)
	return out
}

// HasServiceNeighbors reports whether any egress/ingress neighbor declares a
// serviceRef / serviceSelector / entity — i.e. whether this profile's
// projection depends on the live cluster view (Service/EndpointSlice/Node) and
// must be re-projected when that view changes. Keyed on the raw fields, not on
// whether they currently resolve, so a profile projected before the informers
// synced is still marked and re-projects once they do.
func HasServiceNeighbors(cp *v1beta1.ContainerProfile) bool {
	if cp == nil {
		return false
	}
	for i := range cp.Spec.Egress {
		if hasServiceFields(&cp.Spec.Egress[i]) {
			return true
		}
	}
	for i := range cp.Spec.Ingress {
		if hasServiceFields(&cp.Spec.Ingress[i]) {
			return true
		}
	}
	return false
}

// Must mirror specFromNeighbor's gate: ServiceRefNamespace alone is not a serviceRef.
func hasServiceFields(n *v1beta1.NetworkNeighbor) bool {
	return n.ServiceRefName != "" || n.ServiceSelector != nil || n.Entity != ""
}

// specFromNeighbor extracts a PeerSpec from a NetworkNeighbor, reporting false
// if the neighbor declares none of the service/entity selectors (a plain
// ipAddresses / dnsNames / podSelector neighbor is left untouched).
func specFromNeighbor(n *v1beta1.NetworkNeighbor) (PeerSpec, bool) {
	// Cheap-reject a plain ipAddresses/dnsNames neighbor before allocating a
	// []PortProto it would only discard (hot on every projection's non-service
	// neighbors).
	if n.Entity == "" && n.ServiceRefName == "" && n.ServiceSelector == nil {
		return PeerSpec{}, false
	}
	spec := PeerSpec{Ports: portsFromNeighbor(n.Ports)}
	switch {
	case n.Entity != "":
		spec.Entity = n.Entity
	case n.ServiceRefName != "":
		spec.ServiceRef = &ServiceRef{Namespace: n.ServiceRefNamespace, Name: n.ServiceRefName}
	case n.ServiceSelector != nil:
		// Only equality (matchLabels) is honored. A MatchExpressions clause or
		// an empty matchLabels would either be silently ignored (broadening the
		// match) or resolve to every Service — fail closed instead.
		if len(n.ServiceSelector.MatchExpressions) > 0 || len(n.ServiceSelector.MatchLabels) == 0 {
			return PeerSpec{}, false
		}
		spec.ServiceSelector = n.ServiceSelector.MatchLabels
		// A namespaceSelector is honored only as the single equality
		// kubernetes.io/metadata.name=<ns> (the only key the lister scopes on).
		// Any other form — MatchExpressions, extra keys, or a different key —
		// would be silently dropped and broaden the match cluster-wide, so fail
		// closed. A nil namespaceSelector is cluster-wide by design.
		if n.NamespaceSelector != nil {
			nsl := n.NamespaceSelector
			if len(nsl.MatchExpressions) > 0 || len(nsl.MatchLabels) != 1 ||
				nsl.MatchLabels["kubernetes.io/metadata.name"] == "" {
				return PeerSpec{}, false
			}
			spec.NamespaceLabels = nsl.MatchLabels
		}
	default:
		return PeerSpec{}, false
	}
	return spec, true
}

func portsFromNeighbor(ports []v1beta1.NetworkPort) []PortProto {
	if len(ports) == 0 {
		return nil
	}
	out := make([]PortProto, 0, len(ports))
	for i := range ports {
		p := &ports[i]
		var port int32
		if p.Port != nil {
			port = *p.Port
		}
		out = append(out, PortProto{Port: port, Protocol: strings.ToUpper(string(p.Protocol))})
	}
	return out
}
