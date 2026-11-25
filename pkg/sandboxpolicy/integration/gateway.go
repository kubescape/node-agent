package integration

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/httpgateway"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
)

// GatewayOptions configure the gateway redirect: the node-agent half of the
// http section. Off unless Enabled.
type GatewayOptions struct {
	Enabled bool
	// ListenPort and HealthPort are the gateway's listeners on the node address.
	ListenPort, HealthPort int
	// LookupSocket is the path of the workload lookup socket.
	LookupSocket string
	// TrustNamespace holds the rotation ConfigMap ("": the agent's namespace).
	TrustNamespace string
	// StaticAI is written to every bound pod's AI address set.
	StaticAI []netip.Addr
	// ExemptCIDRs are added to the destinations that are never redirected.
	ExemptCIDRs []string
	Gate        httpgateway.GateConfig
}

// gatewayPinDir is the directory of the redirect's pins under the pin root.
const gatewayPinDir = "http"

// gatewayContainer is a running container, as the gateway binding needs it.
type gatewayContainer struct {
	PodUID   types.UID
	Name     string
	CgroupID uint64
	PID      uint32
}

// gatewayPods builds the gateway's view of the node: every pod that a policy
// with an http section selects, with the policies that select it, its
// prepared annotation and the cgroups of its running containers. A policy
// selects a pod when it selects one of the pod's declared containers.
// podCgroup returns the id of a pod's cgroup, or 0. procRoot is the host's
// /proc as node-agent sees it.
func gatewayPods(pods []*corev1.Pod, namespaceLabels map[string]map[string]string, policies []sandboxpolicy.HTTPPolicy, containers []gatewayContainer, podCgroup func(*corev1.Pod) uint64, procRoot string) []httpgateway.Pod {
	byPod := map[types.UID][]gatewayContainer{}
	for _, c := range containers {
		if c.PodUID != "" && c.Name != "" {
			byPod[c.PodUID] = append(byPod[c.PodUID], c)
		}
	}
	var out []httpgateway.Pod
	for _, pod := range pods {
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		var declared []sandboxpolicy.Binding
		for _, group := range []struct {
			kind  string
			names []string
		}{{"regular", containerNames(pod.Spec.Containers)}, {"init", containerNames(pod.Spec.InitContainers)}, {"ephemeral", ephemeralNames(pod.Spec.EphemeralContainers)}} {
			for _, name := range group.names {
				declared = append(declared, sandboxpolicy.Binding{PodUID: pod.UID, Namespace: pod.Namespace, PodName: pod.Name, ContainerName: name, Kind: group.kind, PodLabels: pod.Labels, NamespaceLabels: namespaceLabels[pod.Namespace]})
			}
		}
		var selected []httpgateway.Policy
		for _, p := range policies {
			for _, b := range declared {
				if p.Selects(b) {
					selected = append(selected, httpgateway.Policy{Ref: httpgateway.PolicyRef{UID: string(p.Identity.UID), Generation: p.Identity.Generation}, Off: p.Off, Deny: p.Deny})
					break
				}
			}
		}
		if len(selected) == 0 {
			continue
		}
		sort.Slice(selected, func(i, j int) bool { return selected[i].Ref.UID < selected[j].Ref.UID })
		kind, name := podController(pod)
		g := httpgateway.Pod{
			UID: string(pod.UID), Namespace: pod.Namespace, Name: pod.Name, ControllerKind: kind, ControllerName: name,
			Prepared: pod.Annotations[httpgateway.PreparedAnnotation], Policies: selected, HostNetwork: pod.Spec.HostNetwork,
			Containers: map[string]uint64{},
		}
		if podCgroup != nil {
			g.PodCgroup = podCgroup(pod)
		}
		running := byPod[pod.UID]
		sort.Slice(running, func(i, j int) bool { return running[i].Name < running[j].Name })
		for _, c := range running {
			if c.CgroupID != 0 {
				g.Containers[c.Name] = c.CgroupID
			}
			if g.NetNS == "" && c.PID != 0 && !pod.Spec.HostNetwork {
				g.NetNS = filepath.Join(procRoot, strconv.FormatUint(uint64(c.PID), 10), "ns", "net")
			}
		}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out
}

func containerNames(containers []corev1.Container) []string {
	out := make([]string, 0, len(containers))
	for _, c := range containers {
		out = append(out, c.Name)
	}
	return out
}

func ephemeralNames(containers []corev1.EphemeralContainer) []string {
	out := make([]string, 0, len(containers))
	for _, c := range containers {
		out = append(out, c.Name)
	}
	return out
}

// podController returns the kind and name of the pod's controller. A
// ReplicaSet made by a Deployment is reported as the Deployment: its name is
// the Deployment's name followed by the pod template hash.
func podController(pod *corev1.Pod) (kind, name string) {
	owner := metav1.GetControllerOf(pod)
	if owner == nil {
		return "", ""
	}
	if hash := pod.Labels["pod-template-hash"]; owner.Kind == "ReplicaSet" && hash != "" && strings.HasSuffix(owner.Name, "-"+hash) {
		return "Deployment", strings.TrimSuffix(owner.Name, "-"+hash)
	}
	return owner.Kind, owner.Name
}

// nodeIPv4 returns the node's first internal IPv4 address.
func nodeIPv4(node *corev1.Node) (netip.Addr, bool) {
	for _, a := range node.Status.Addresses {
		if a.Type != corev1.NodeInternalIP {
			continue
		}
		if addr, err := netip.ParseAddr(a.Address); err == nil && addr.Unmap().Is4() {
			return addr.Unmap(), true
		}
	}
	return netip.Addr{}, false
}

// Backoff of the gateway startup retries.
var (
	gatewayRetryFirst = time.Second
	gatewayRetryMax   = time.Minute
)

// startGateway starts the gateway redirect, or removes what an earlier run
// with the redirect enabled left pinned. It needs the host bpffs: the redirect
// has to outlive node-agent. A start that fails is retried with backoff until
// it succeeds or ctx ends; Close waits for the retries to stop.
func (s *Service) startGateway(ctx context.Context) {
	root := RestartPinRoot()
	if !s.options.Gateway.Enabled {
		if root != "" {
			if err := httpgateway.Remove(filepath.Join(root, gatewayPinDir)); err != nil {
				s.report(fmt.Errorf("sandbox gateway redirect is off; removing its pins: %w", err))
			}
		}
		return
	}
	if root == "" {
		// Not transient: the DaemonSet has no host bpffs mount.
		s.report(fmt.Errorf("sandbox gateway redirect not started: node-agent sees no host bpffs to pin it on"))
		return
	}
	s.gatewayWG.Add(1)
	go func() {
		defer s.gatewayWG.Done()
		retryGateway(ctx, func(ctx context.Context) error { return s.tryStartGateway(ctx, root) }, s.report)
	}()
}

// retryGateway runs attempt until it succeeds or ctx ends, waiting twice as
// long after each failure, up to gatewayRetryMax.
func retryGateway(ctx context.Context, attempt func(context.Context) error, report func(error)) {
	wait := gatewayRetryFirst
	for {
		err := attempt(ctx)
		if err == nil || ctx.Err() != nil {
			return
		}
		report(fmt.Errorf("sandbox gateway redirect not started, retrying in %s: %w", wait, err))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(2*wait, gatewayRetryMax)
	}
}

// tryStartGateway makes one attempt to start the redirect.
func (s *Service) tryStartGateway(ctx context.Context, root string) error {
	node, err := s.options.Kubernetes.CoreV1().Nodes().Get(ctx, s.options.NodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("node: %w", err)
	}
	addr, ok := nodeIPv4(node)
	if !ok {
		return fmt.Errorf("node %s has no internal IPv4 address", node.Name)
	}
	o := s.options.Gateway
	trust := o.TrustNamespace
	if trust == "" {
		trust = s.options.AgentNamespace
	}
	cidrs := &ClusterCIDRReader{} // used by the manager's refresh loop only
	manager, err := httpgateway.StartManager(ctx, httpgateway.ManagerOptions{
		PinDir:       filepath.Join(root, gatewayPinDir),
		CgroupRoot:   filepath.Join(host.HostRoot, "sys/fs/cgroup"),
		Gateway:      netip.AddrPortFrom(addr, uint16(o.ListenPort)),
		HealthURL:    "http://" + netip.AddrPortFrom(addr, uint16(o.HealthPort)).String(),
		Gate:         o.Gate,
		LookupSocket: o.LookupSocket,
		StaticAI:     o.StaticAI,
		Pods:         s.gatewayPods,
		Exempt: func(ctx context.Context) ([]netip.Prefix, error) {
			// A failed read keeps the last good value of each part.
			ranges, readErr := cidrs.Read(ctx, s.options.Kubernetes)
			set, bad := httpgateway.ExemptSet(ranges.Pods, ranges.Services, httpgateway.NodeAddresses(node), o.ExemptCIDRs)
			if len(bad) > 0 {
				s.report(fmt.Errorf("sandbox gateway redirect: exempt ranges that do not parse: %v", bad))
			}
			if readErr != nil {
				s.report(fmt.Errorf("sandbox gateway redirect: cluster ranges: %w", readErr))
			}
			return set, nil
		},
		Rotation: func(ctx context.Context) (httpgateway.Rotation, error) {
			return httpgateway.ReadRotation(ctx, s.options.Kubernetes, trust)
		},
		Report:   func(err error) { s.report(fmt.Errorf("sandbox gateway redirect: %w", err)) },
		OnStatus: s.queueRefresh,
	})
	if err != nil {
		return err
	}
	s.gateway.Store(manager)
	return nil
}

// gatewayPods reads the node's pods, the namespaces' labels, the policies
// with an http section and the running containers.
func (s *Service) gatewayPods(ctx context.Context) ([]httpgateway.Pod, error) {
	policies := s.Controller.HTTPPolicies()
	if len(policies) == 0 {
		return nil, nil
	}
	// From the API server's cache: this runs every few seconds.
	list, err := s.options.Kubernetes.CoreV1().Pods("").List(ctx, metav1.ListOptions{FieldSelector: fields.OneTermEqualSelector("spec.nodeName", s.options.NodeName).String(), ResourceVersion: "0"})
	if err != nil {
		return nil, fmt.Errorf("list node pods: %w", err)
	}
	namespaces, err := s.options.Kubernetes.CoreV1().Namespaces().List(ctx, metav1.ListOptions{ResourceVersion: "0"})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	labels := make(map[string]map[string]string, len(namespaces.Items))
	for _, ns := range namespaces.Items {
		labels[ns.Name] = ns.Labels
	}
	var pods []*corev1.Pod
	for i := range list.Items {
		if list.Items[i].Spec.NodeName == s.options.NodeName {
			pods = append(pods, &list.Items[i])
		}
	}
	var containers []gatewayContainer
	s.options.Containers.ContainerRange(func(c *containercollection.Container) {
		if c != nil {
			containers = append(containers, gatewayContainer{PodUID: types.UID(c.K8s.PodUID), Name: c.K8s.ContainerName, CgroupID: c.CgroupID, PID: c.ContainerPid()})
		}
	})
	layout, known, _, _, _ := s.podCgroupLayout()
	podCgroup := func(pod *corev1.Pod) uint64 {
		if !known || s.podCgroupID == nil {
			return 0
		}
		path := layout.path(pod.UID, pod.Status.QOSClass)
		if path == "" {
			return 0
		}
		id, err := s.podCgroupID(path)
		if err != nil {
			return 0 // the pod cgroup is not there yet, or is already gone
		}
		return id
	}
	return gatewayPods(pods, labels, policies, containers, podCgroup, host.HostProcFs), nil
}

// httpStatus is the controller's HTTPStatus hook.
func (s *Service) httpStatus(uid types.UID) (*api.HTTPNodeStatus, bool) {
	manager := s.gateway.Load()
	if manager == nil {
		return nil, false
	}
	status, truncated := manager.PolicyStatus(string(uid))
	return &status, truncated
}
