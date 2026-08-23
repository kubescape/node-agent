package networkpeer

import (
	"net"
	"sync/atomic"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
)

// InformerLister is the production Lister, backed by Service / EndpointSlice /
// Node informer listers. It resolves a serviceRef/serviceSelector to the
// Service's ClusterIP(s) ∪ its EndpointSlice addresses, and the "host" entity
// to every node's InternalIP(s) plus the CNI gateway derived from its PodCIDR.
type InformerLister struct {
	services corelisters.ServiceLister
	slices   discoverylisters.EndpointSliceLister
	nodes    corelisters.NodeLister
	// nodeName scopes the "host" entity to the local node. Empty means every
	// node (used by tests); production passes the agent's own node so kubelet
	// probes from this node's gateway match without broadening "host" to the
	// whole cluster.
	nodeName string
	// generation advances on every observed Service/EndpointSlice/Node change
	// (bumped from informer event handlers wired in cmd/main.go).
	generation atomic.Int64
}

// Generation returns the current cluster-view generation.
func (l *InformerLister) Generation() int64 { return l.generation.Load() }

// Bump advances the generation; wire it to the informer event handlers.
func (l *InformerLister) Bump() { l.generation.Add(1) }

func NewInformerLister(services corelisters.ServiceLister, slices discoverylisters.EndpointSliceLister, nodes corelisters.NodeLister, nodeName string) *InformerLister {
	return &InformerLister{services: services, slices: slices, nodes: nodes, nodeName: nodeName}
}

var _ Lister = (*InformerLister)(nil)

func (l *InformerLister) ServiceByName(namespace, name string) (*ServiceInfo, bool) {
	svc, err := l.services.Services(namespace).Get(name)
	if err != nil {
		return nil, false
	}
	return l.serviceInfo(svc), true
}

func (l *InformerLister) ServicesByLabels(serviceSelector, namespaceLabels map[string]string) []*ServiceInfo {
	// Never resolve an empty selector to labels.Everything() — that would
	// allowlist every Service in the cluster. Fail closed.
	if len(serviceSelector) == 0 {
		return nil
	}
	svcs, err := l.services.List(labels.SelectorFromSet(serviceSelector))
	if err != nil {
		return nil
	}
	wantNS := ""
	if namespaceLabels != nil {
		wantNS = namespaceLabels["kubernetes.io/metadata.name"]
	}
	var out []*ServiceInfo
	for _, svc := range svcs {
		if wantNS != "" && svc.Namespace != wantNS {
			continue
		}
		out = append(out, l.serviceInfo(svc))
	}
	return out
}

func (l *InformerLister) HostIPs() []string {
	nodes, err := l.nodes.List(labels.Everything())
	if err != nil {
		return nil
	}
	var ips []string
	for _, n := range nodes {
		if l.nodeName != "" && n.Name != l.nodeName {
			continue
		}
		for _, addr := range n.Status.Addresses {
			if addr.Type == corev1.NodeInternalIP {
				ips = append(ips, addr.Address)
			}
		}
		for _, cidr := range podCIDRs(n) {
			if gw := gatewayIP(cidr); gw != "" {
				ips = append(ips, gw)
			}
		}
	}
	return dedupe(ips)
}

func (l *InformerLister) serviceInfo(svc *corev1.Service) *ServiceInfo {
	info := &ServiceInfo{Namespace: svc.Namespace, Name: svc.Name, Labels: svc.Labels}
	for _, ip := range svc.Spec.ClusterIPs {
		if ip != "" && ip != corev1.ClusterIPNone {
			info.ClusterIPs = append(info.ClusterIPs, ip)
		}
	}
	if len(info.ClusterIPs) == 0 && svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != corev1.ClusterIPNone {
		info.ClusterIPs = append(info.ClusterIPs, svc.Spec.ClusterIP)
	}
	info.EndpointIPs = l.endpointIPs(svc.Namespace, svc.Name)
	return info
}

func (l *InformerLister) endpointIPs(namespace, service string) []string {
	sel := labels.SelectorFromSet(labels.Set{discoveryv1.LabelServiceName: service})
	slices, err := l.slices.EndpointSlices(namespace).List(sel)
	if err != nil {
		return nil
	}
	var ips []string
	for _, es := range slices {
		for i := range es.Endpoints {
			ips = append(ips, es.Endpoints[i].Addresses...)
		}
	}
	return dedupe(ips)
}

func podCIDRs(n *corev1.Node) []string {
	if len(n.Spec.PodCIDRs) > 0 {
		return n.Spec.PodCIDRs
	}
	if n.Spec.PodCIDR != "" {
		return []string{n.Spec.PodCIDR}
	}
	return nil
}

// gatewayIP returns the conventional CNI gateway for a pod CIDR: the network
// address + 1 (e.g. 10.42.0.0/24 -> 10.42.0.1). Masqueraded node-sourced
// traffic (kubelet health probes) appears from this address. IPv6 CIDRs yield
// no gateway (the .1 convention is IPv4).
func gatewayIP(cidr string) string {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	ip := ipNet.IP.To4()
	if ip == nil {
		return ""
	}
	gw := make(net.IP, len(ip))
	copy(gw, ip)
	for i := len(gw) - 1; i >= 0; i-- {
		gw[i]++
		if gw[i] != 0 {
			break
		}
	}
	// A /31 or /32 (or a network address ending in .255 that overflows) yields a
	// gateway outside the CIDR — never allowlist an IP the pod network doesn't
	// actually contain.
	if !ipNet.Contains(gw) {
		return ""
	}
	return gw.String()
}
