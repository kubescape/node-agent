package tracers

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	peerHitTTL     = 30 * time.Second
	peerMissTTL    = 10 * time.Second
	maxPeerEntries = 1024
)

type peerIdentity struct {
	namespace string
	name      string
	labels    string
}

type peerRepair struct {
	mu        sync.Mutex
	stopped   bool
	positive  *expirable.LRU[string, peerIdentity]
	negative  *expirable.LRU[string, struct{}]
	pods      func() []*common.SlimPod
	inventory common.K8sInventoryCache
	initInv   func() common.K8sInventoryCache
}

func newPeerRepair() *peerRepair {
	r := &peerRepair{
		positive: expirable.NewLRU[string, peerIdentity](maxPeerEntries, nil, peerHitTTL),
		negative: expirable.NewLRU[string, struct{}](maxPeerEntries, nil, peerMissTTL),
	}
	r.initInv = func() common.K8sInventoryCache {
		inv, err := common.GetK8sInventoryCache()
		if err != nil {
			logger.L().Warning("network tracer: peer repair has no inventory", helpers.Error(err))
			return nil
		}
		inv.Start()
		return inv
	}
	r.pods = func() []*common.SlimPod {
		inv := r.getInventory()
		if inv == nil {
			return nil
		}
		return inv.GetPods()
	}
	return r
}

func (r *peerRepair) initCaches() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.positive == nil {
		r.positive = expirable.NewLRU[string, peerIdentity](maxPeerEntries, nil, peerHitTTL)
	}
	if r.negative == nil {
		r.negative = expirable.NewLRU[string, struct{}](maxPeerEntries, nil, peerMissTTL)
	}
}

func (r *peerRepair) getInventory() common.K8sInventoryCache {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return nil
	}
	if r.inventory == nil && r.initInv != nil {
		r.inventory = r.initInv()
	}
	return r.inventory
}

func (r *peerRepair) isStopped() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stopped
}

func (r *peerRepair) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopped = true
	if r.inventory != nil {
		r.inventory.Stop()
		r.inventory = nil
	}
	if r.positive != nil {
		r.positive.Purge()
	}
	if r.negative != nil {
		r.negative.Purge()
	}
}

func podByIP(pods []*common.SlimPod, ip, expectedNamespace, expectedName string) *common.SlimPod {
	var matches []*common.SlimPod
	for _, p := range pods {
		if p == nil || p.Spec.HostNetwork || p.Status.PodIP != ip {
			continue
		}
		matches = append(matches, p)
	}
	if len(matches) == 0 {
		return nil
	}
	if len(matches) == 1 {
		p := matches[0]
		if expectedName != "" && (p.Name != expectedName || (expectedNamespace != "" && p.Namespace != expectedNamespace)) {
			return nil
		}
		return p
	}
	// Ambiguous matches: multiple pods claim the same IP (terminating pod + replacement pod in cachedmap).
	if expectedName != "" {
		var disambiguated *common.SlimPod
		for _, p := range matches {
			if p.Name == expectedName && (expectedNamespace == "" || p.Namespace == expectedNamespace) {
				if disambiguated != nil {
					return nil
				}
				disambiguated = p
			}
		}
		return disambiguated
	}
	// Without expected name, decline repair to avoid nondeterministically emitting stale identity.
	return nil
}

func labelString(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, labels[k]))
	}
	return strings.Join(parts, ",")
}

// invalidate clears cached IP entries, or all entries if no IPs are specified.
func (r *peerRepair) invalidate(ips ...string) {
	r.initCaches()
	if len(ips) == 0 {
		r.positive.Purge()
		r.negative.Purge()
		return
	}
	for _, ip := range ips {
		r.positive.Remove(ip)
		r.negative.Remove(ip)
	}
}

func (r *peerRepair) lookup(ip string) (peerIdentity, bool) {
	return r.lookupWithExpected(ip, "", "")
}

func (r *peerRepair) lookupWithExpected(ip, expectedNamespace, expectedName string) (peerIdentity, bool) {
	if r.isStopped() {
		return peerIdentity{}, false
	}
	r.initCaches()
	inv := r.getInventory()

	// If expected identity is provided, bypass negative cache
	if expectedName != "" {
		r.negative.Remove(ip)
	} else if _, ok := r.negative.Get(ip); ok {
		return peerIdentity{}, false
	}

	if hit, ok := r.positive.Get(ip); ok {
		// Validate cached positive hit using indexed lookups to avoid scanning all pods,
		// while ensuring the pod still owns ip and no new pod took it over.
		var p *common.SlimPod
		if inv != nil {
			cand := inv.GetPodByName(hit.namespace, hit.name)
			if cand != nil && !cand.Spec.HostNetwork && cand.Status.PodIP == ip &&
				(expectedName == "" || cand.Name == expectedName) &&
				(expectedNamespace == "" || cand.Namespace == expectedNamespace) {
				// Ensure IP has not been reassigned to a different pod in the IP index
				if byIP := inv.GetPodByIp(ip); byIP == nil || (byIP.Name == hit.name && byIP.Namespace == hit.namespace) {
					p = cand
				}
			}
		} else if r.pods != nil {
			pods := r.pods()
			p = podByIP(pods, ip, expectedNamespace, expectedName)
		}
		if p != nil && p.Name == hit.name && p.Namespace == hit.namespace {
			// Refresh cached labels in case the pod was relabeled
			hit.labels = labelString(p.Labels)
			r.positive.Add(ip, hit)
			return hit, true
		}
		r.positive.Remove(ip)
	}

	var p *common.SlimPod
	if inv != nil && expectedName != "" && expectedNamespace != "" {
		cand := inv.GetPodByName(expectedNamespace, expectedName)
		if cand != nil && !cand.Spec.HostNetwork && cand.Status.PodIP == ip {
			if byIP := inv.GetPodByIp(ip); byIP == nil || (byIP.Name == cand.Name && byIP.Namespace == cand.Namespace) {
				p = cand
			} else {
				// The IP has been reassigned to a different pod in the IP index (IP reuse).
				// Do not let the expected-name fallback select the stale terminating pod.
				return peerIdentity{}, false
			}
		}
	}
	if p == nil && r.pods != nil {
		pods := r.pods()
		p = podByIP(pods, ip, expectedNamespace, expectedName)
	}
	if p != nil {
		id := peerIdentity{namespace: p.Namespace, name: p.Name, labels: labelString(p.Labels)}
		r.positive.Add(ip, id)
		return id, true
	}

	// Do not cache negative entries for identity-constrained lookups
	if expectedName == "" {
		r.negative.Add(ip, struct{}{})
	}
	return peerIdentity{}, false
}

func (r *peerRepair) repair(d datasource.DataSource, data datasource.Data, ev *utils.DatasourceEvent) bool {
	if r.isStopped() {
		return false
	}

	ep := ev.GetDstEndpoint()
	if ep.Addr == "" || ep.Addr == "0.0.0.0" || strings.HasPrefix(ep.Addr, "127.") {
		return false
	}
	// An endpoint is eligible for repair if:
	// 1. It is unresolved (empty kind or EndpointKindRaw from KubeIPResolver), OR
	// 2. It is resolved as a Pod but missing labels (partial enrichment).
	// Other resolved kinds (e.g. services) and pods that already possess labels are preserved.
	if ep.Kind != "" && ep.Kind != igtypes.EndpointKindRaw {
		if ep.Kind != igtypes.EndpointKindPod || len(ep.PodLabels) > 0 {
			return false
		}
	}
	id, ok := r.lookupWithExpected(ep.Addr, ep.Namespace, ep.Name)
	if !ok {
		return false
	}
	for name, value := range map[string]string{
		"endpoint.k8s.kind":      string(igtypes.EndpointKindPod),
		"endpoint.k8s.namespace": id.namespace,
		"endpoint.k8s.name":      id.name,
		"endpoint.k8s.labels":    id.labels,
	} {
		f := d.GetField(name)
		if f == nil {
			return false
		}
		if err := f.PutString(data, value); err != nil {
			return false
		}
	}
	return true
}
