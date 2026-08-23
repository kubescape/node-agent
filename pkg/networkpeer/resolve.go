// Package networkpeer resolves Kubernetes-native network-neighbor selectors
// (a Service reference, a Service label selector, or a reserved entity such as
// "host") into the concrete (IP, port, protocol) tuples an egress/ingress
// allowlist should match.
//
// It exists so a ContainerProfile can express cluster-infrastructure peers —
// Service ClusterIPs (alertmanager, kube-apiserver via default/kubernetes,
// kube-dns, ...) and host/kubelet traffic — portably (by name, resolved
// per-cluster) and narrowly (only the referenced Service/entity), instead of a
// broad ipAddresses CIDR over the whole service network. See
// k8sstormcenter/node-agent#92.
//
// Resolution is intentionally decoupled from live matching: callers resolve a
// PeerSpec to []AllowTuple once (e.g. at projection time) via a Lister backed
// by Service/EndpointSlice/Node informers, then match observed connections
// against the tuples with Matches. The Lister interface keeps the resolver
// unit-testable against a fake cluster view.
package networkpeer

import "strings"

// EntityHost is the reserved entity naming the local node: its InternalIP(s)
// and the CNI gateway address. It is the one peer class no Service object can
// represent (kubelet health probes, node-sourced / masqueraded traffic).
const EntityHost = "host"

// PortProto is a single allowed destination port/protocol. Protocol is
// upper-case ("TCP"/"UDP"); an empty Protocol matches any protocol.
type PortProto struct {
	Port     int32
	Protocol string
}

// ServiceRef names a single Service by namespace and name.
type ServiceRef struct {
	Namespace string
	Name      string
}

// PeerSpec is the storage-agnostic form of one serviceRef / serviceSelector /
// entity network-neighbor entry. Exactly one of ServiceRef, ServiceSelector,
// or Entity is expected to be set; Ports scopes the resolved tuples.
type PeerSpec struct {
	ServiceRef      *ServiceRef
	ServiceSelector map[string]string
	NamespaceLabels map[string]string
	Entity          string
	Ports           []PortProto
}

// ServiceInfo is the resolver's view of one Service.
type ServiceInfo struct {
	Namespace   string
	Name        string
	Labels      map[string]string
	ClusterIPs  []string
	EndpointIPs []string
}

// Lister is the read-only cluster view the resolver needs. Production wires it
// to Service/EndpointSlice/Node informer listers; tests use a fake.
type Lister interface {
	ServiceByName(namespace, name string) (*ServiceInfo, bool)
	ServicesByLabels(serviceSelector, namespaceLabels map[string]string) []*ServiceInfo
	HostIPs() []string
	// Generation increments whenever the underlying cluster view changes (any
	// Service/EndpointSlice/Node event). Callers store it alongside a projected
	// profile and re-project when it advances, so resolved IPs don't go stale on
	// endpoint churn or caches that filled after projection.
	Generation() int64
}

// AllowTuple is one concrete (IP, port, protocol) a resolved PeerSpec permits.
type AllowTuple struct {
	IP       string
	Port     int32
	Protocol string
}

// Resolve expands spec into the concrete tuples it authorises, using l for the
// current cluster view. A spec with no resolvable target (unknown Service,
// selector matching nothing, unknown entity) yields no tuples — never a
// match-all. A spec with no Ports yields one tuple per IP with Port 0 /
// Protocol "" (any-port), so callers that ignore ports still work; callers
// that enforce ports should treat Port 0 as "unspecified".
func Resolve(spec PeerSpec, l Lister) []AllowTuple {
	if l == nil {
		return nil
	}
	ips := resolveIPs(spec, l)
	if len(ips) == 0 {
		return nil
	}
	return expand(ips, spec.Ports)
}

// ResolveIPs returns just the IPs a spec resolves to, ignoring ports. Used by
// the projection-time expansion, which pairs them with the neighbor's own
// ports.
func ResolveIPs(spec PeerSpec, l Lister) []string {
	if l == nil {
		return nil
	}
	return resolveIPs(spec, l)
}

func resolveIPs(spec PeerSpec, l Lister) []string {
	switch {
	case spec.Entity != "":
		if strings.EqualFold(spec.Entity, EntityHost) {
			return dedupe(l.HostIPs())
		}
		return nil
	case spec.ServiceRef != nil:
		svc, ok := l.ServiceByName(spec.ServiceRef.Namespace, spec.ServiceRef.Name)
		if !ok || svc == nil {
			return nil
		}
		return serviceIPs(svc)
	case spec.ServiceSelector != nil:
		// An empty selector is NOT a cluster-wide match-all: fail closed.
		if len(spec.ServiceSelector) == 0 {
			return nil
		}
		var ips []string
		for _, svc := range l.ServicesByLabels(spec.ServiceSelector, spec.NamespaceLabels) {
			ips = append(ips, serviceIPs(svc)...)
		}
		return dedupe(ips)
	default:
		return nil
	}
}

func serviceIPs(svc *ServiceInfo) []string {
	out := make([]string, 0, len(svc.ClusterIPs)+len(svc.EndpointIPs))
	out = append(out, svc.ClusterIPs...)
	out = append(out, svc.EndpointIPs...)
	return dedupe(out)
}

func expand(ips []string, ports []PortProto) []AllowTuple {
	if len(ports) == 0 {
		out := make([]AllowTuple, 0, len(ips))
		for _, ip := range ips {
			out = append(out, AllowTuple{IP: ip})
		}
		return out
	}
	out := make([]AllowTuple, 0, len(ips)*len(ports))
	for _, ip := range ips {
		for _, p := range ports {
			out = append(out, AllowTuple{IP: ip, Port: p.Port, Protocol: strings.ToUpper(p.Protocol)})
		}
	}
	return out
}

// Matches reports whether the observed (ip, port, protocol) connection is
// permitted by any tuple. Matching is port-sensitive: a tuple with Port 0
// (any-port) matches any observed port; otherwise the port must be equal. An
// empty tuple Protocol matches any protocol.
func Matches(tuples []AllowTuple, ip string, port int32, protocol string) bool {
	protocol = strings.ToUpper(protocol)
	for _, t := range tuples {
		if t.IP != ip {
			continue
		}
		if t.Port != 0 && t.Port != port {
			continue
		}
		if t.Protocol != "" && t.Protocol != protocol {
			continue
		}
		return true
	}
	return false
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
