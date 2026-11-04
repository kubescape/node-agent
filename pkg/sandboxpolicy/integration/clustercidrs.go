package integration

import (
	"context"
	"sort"
	"strings"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

// ClusterCIDRs learns the pod and service ranges of the clusterInternal class.
// Each part comes from the first source that answers:
//   - pods: the union of Nodes spec.podCIDRs, else kubeadm-config podSubnet;
//   - services: ServiceCIDR objects (networking.k8s.io/v1, needs list RBAC),
//     else kubeadm-config serviceSubnet.
//
// A part that no source gives is listed in Missing (the class is then partly
// resolved). On VPC-routed CNIs (for example EKS VPC CNI) nodes have no
// podCIDRs and managed clusters have no kubeadm-config.
func ClusterCIDRs(ctx context.Context, client kubernetes.Interface) sandboxpolicy.ClusterCIDRs {
	var out sandboxpolicy.ClusterCIDRs
	if nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{ResourceVersion: "0"}); err == nil {
		for _, n := range nodes.Items {
			out.Pods = append(out.Pods, n.Spec.PodCIDRs...)
			if len(n.Spec.PodCIDRs) == 0 && n.Spec.PodCIDR != "" {
				out.Pods = append(out.Pods, n.Spec.PodCIDR)
			}
		}
	}
	if list, err := client.NetworkingV1().ServiceCIDRs().List(ctx, metav1.ListOptions{}); err == nil {
		for _, s := range list.Items {
			out.Services = append(out.Services, s.Spec.CIDRs...)
		}
	}
	if len(out.Pods) == 0 || len(out.Services) == 0 {
		pods, services := kubeadmSubnets(ctx, client)
		if len(out.Pods) == 0 {
			out.Pods = pods
		}
		if len(out.Services) == 0 {
			out.Services = services
		}
	}
	out.Pods, out.Services = unique(out.Pods), unique(out.Services)
	if len(out.Pods) == 0 {
		out.Missing = append(out.Missing, "pod CIDRs")
	}
	if len(out.Services) == 0 {
		out.Missing = append(out.Missing, "service CIDRs")
	}
	return out
}

// kubeadmSubnets reads networking.podSubnet and serviceSubnet (comma-separated
// on dual-stack clusters) from kube-system/kubeadm-config.
func kubeadmSubnets(ctx context.Context, client kubernetes.Interface) (pods, services []string) {
	cm, err := client.CoreV1().ConfigMaps("kube-system").Get(ctx, "kubeadm-config", metav1.GetOptions{})
	if err != nil {
		return nil, nil
	}
	var config struct {
		Networking struct {
			PodSubnet     string `json:"podSubnet"`
			ServiceSubnet string `json:"serviceSubnet"`
		} `json:"networking"`
	}
	if err := yaml.Unmarshal([]byte(cm.Data["ClusterConfiguration"]), &config); err != nil {
		return nil, nil
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
	return split(config.Networking.PodSubnet), split(config.Networking.ServiceSubnet)
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
