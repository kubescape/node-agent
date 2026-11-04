package integration

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

// ClusterCIDRReader learns the pod and service ranges of the clusterInternal
// class. Each part comes from a primary source, and from kubeadm-config only
// when the primary source answered with nothing:
//   - pods: the union of Nodes spec.podCIDRs, else kubeadm-config podSubnet;
//   - services: ServiceCIDR objects (networking.k8s.io/v1, needs list RBAC),
//     else kubeadm-config serviceSubnet.
//
// A part keeps its last good value when a read fails, so one failed read does
// not empty the class (and replace every node instance). A failed primary read
// does not fall back to kubeadm-config: that value can differ from the
// primary one, and the class would change on every failed read. A part is listed in
// Missing (the class is then partly resolved) when the sources answered with
// nothing, or when no source has answered yet. On VPC-routed CNIs (for example
// EKS VPC CNI) nodes have no podCIDRs and managed clusters have no
// kubeadm-config.
//
// Each part is aggregated to the smallest set of prefixes that covers exactly
// the same addresses, so a node that joins or leaves inside an already covered
// range does not change the class.
//
// TODO: Read lists Nodes on every call. Watch them with an informer instead.
type ClusterCIDRReader struct {
	pods, services []string
	// podsOK and svcOK: a source has answered for the part at least once.
	podsOK, svcOK bool
}

// Read reads the sources. err joins the read errors of the parts that kept
// their last good value (or stayed Missing); the result is usable either way.
func (r *ClusterCIDRReader) Read(ctx context.Context, client kubernetes.Interface) (sandboxpolicy.ClusterCIDRs, error) {
	pods, podsErr := nodePodCIDRs(ctx, client)
	services, svcErr := serviceCIDRs(ctx, client)
	podsFallback := podsErr == nil && len(pods) == 0
	svcFallback := svcErr == nil && len(services) == 0
	if podsFallback || svcFallback {
		kpods, kservices, kerr := kubeadmSubnets(ctx, client)
		if podsFallback {
			pods, podsErr = kpods, kerr
		}
		if svcFallback {
			services, svcErr = kservices, kerr
		}
	}
	if podsErr == nil {
		r.pods, r.podsOK = aggregate(pods), true
	}
	if svcErr == nil {
		r.services, r.svcOK = aggregate(services), true
	}
	out := sandboxpolicy.ClusterCIDRs{Pods: r.pods, Services: r.services}
	if len(out.Pods) == 0 {
		out.Missing = append(out.Missing, "pod CIDRs")
	}
	if len(out.Services) == 0 {
		out.Missing = append(out.Missing, "service CIDRs")
	}
	var err error
	if podsErr != nil {
		err = errors.Join(err, fmt.Errorf("pod CIDRs (last good value kept: %t): %w", r.podsOK, podsErr))
	}
	if svcErr != nil {
		err = errors.Join(err, fmt.Errorf("service CIDRs (last good value kept: %t): %w", r.svcOK, svcErr))
	}
	return out, err
}

func nodePodCIDRs(ctx context.Context, client kubernetes.Interface) ([]string, error) {
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{ResourceVersion: "0"})
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	var out []string
	for _, n := range nodes.Items {
		out = append(out, n.Spec.PodCIDRs...)
		if len(n.Spec.PodCIDRs) == 0 && n.Spec.PodCIDR != "" {
			out = append(out, n.Spec.PodCIDR)
		}
	}
	return out, nil
}

// serviceCIDRs lists ServiceCIDR objects. A cluster without the API (before
// Kubernetes 1.33) answers NotFound: that is an answer with no value.
func serviceCIDRs(ctx context.Context, client kubernetes.Interface) ([]string, error) {
	list, err := client.NetworkingV1().ServiceCIDRs().List(ctx, metav1.ListOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list servicecidrs: %w", err)
	}
	var out []string
	for _, s := range list.Items {
		out = append(out, s.Spec.CIDRs...)
	}
	return out, nil
}

// kubeadmSubnets reads networking.podSubnet and serviceSubnet (comma-separated
// on dual-stack clusters) from kube-system/kubeadm-config. A missing ConfigMap
// (a managed cluster) is an answer with no value.
func kubeadmSubnets(ctx context.Context, client kubernetes.Interface) (pods, services []string, err error) {
	cm, err := client.CoreV1().ConfigMaps("kube-system").Get(ctx, "kubeadm-config", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("get kubeadm-config: %w", err)
	}
	var config struct {
		Networking struct {
			PodSubnet     string `json:"podSubnet"`
			ServiceSubnet string `json:"serviceSubnet"`
		} `json:"networking"`
	}
	if err := yaml.Unmarshal([]byte(cm.Data["ClusterConfiguration"]), &config); err != nil {
		return nil, nil, fmt.Errorf("kubeadm-config ClusterConfiguration: %w", err)
	}
	split := func(s string) []string {
		var out []string
		for _, v := range strings.Split(s, ",") {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	return split(config.Networking.PodSubnet), split(config.Networking.ServiceSubnet), nil
}

// aggregate returns the smallest sorted set of prefixes that covers exactly
// the addresses of list: contained prefixes are removed and two halves of one
// prefix become that prefix. It never widens. Entries that are not CIDRs are
// kept as they are.
func aggregate(list []string) []string {
	var prefixes []netip.Prefix
	var other []string
	for _, s := range list {
		if p, err := netip.ParsePrefix(s); err == nil {
			prefixes = append(prefixes, p.Masked())
		} else {
			other = append(other, s)
		}
	}
	for changed := true; changed; {
		changed = false
		sort.Slice(prefixes, func(i, j int) bool {
			if c := prefixes[i].Addr().Compare(prefixes[j].Addr()); c != 0 {
				return c < 0
			}
			return prefixes[i].Bits() < prefixes[j].Bits()
		})
		// Sorted by address then length, a prefix follows the one that
		// contains it, and two halves of one prefix are neighbours.
		var kept []netip.Prefix
		for _, p := range prefixes {
			if n := len(kept); n > 0 {
				last := kept[n-1]
				if last.Bits() <= p.Bits() && last.Contains(p.Addr()) {
					continue
				}
				if last.Bits() == p.Bits() && p.Bits() > 0 {
					parent := netip.PrefixFrom(last.Addr(), last.Bits()-1).Masked()
					if parent.Addr() == last.Addr() && parent.Contains(p.Addr()) {
						kept[n-1], changed = parent, true
						continue
					}
				}
			}
			kept = append(kept, p)
		}
		prefixes = kept
	}
	out := make([]string, 0, len(prefixes)+len(other))
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	return append(out, unique(other)...)
}

func unique(list []string) []string {
	sort.Strings(list)
	var out []string
	for _, v := range list {
		if len(out) == 0 || out[len(out)-1] != v {
			out = append(out, v)
		}
	}
	return out
}
