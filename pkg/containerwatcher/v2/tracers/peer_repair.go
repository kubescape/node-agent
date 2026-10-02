package tracers

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

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
	at        time.Time
	found     bool
}

type peerRepair struct {
	mu        sync.Mutex
	stopped   bool
	byIP      map[string]peerIdentity
	now       func() time.Time
	pods      func() []*common.SlimPod
	inventory common.K8sInventoryCache
	initInv   func() common.K8sInventoryCache
}

func newPeerRepair() *peerRepair {
	r := &peerRepair{byIP: map[string]peerIdentity{}, now: time.Now}
	r.initInv = func() common.K8sInventoryCache {
		if r.stopped || r.inventory != nil {
			return r.inventory
		}
		inv, err := common.GetK8sInventoryCache()
		if err != nil {
			logger.L().Warning("network tracer: peer repair has no inventory", helpers.Error(err))
			return nil
		}
		inv.Start()
		r.inventory = inv
		return r.inventory
	}
	r.pods = func() []*common.SlimPod {
		r.mu.Lock()
		inv := r.inventory
		if inv == nil && r.initInv != nil {
			inv = r.initInv()
		}
		r.mu.Unlock()
		if inv == nil {
			return nil
		}
		return inv.GetPods()
	}
	return r
}

func (r *peerRepair) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopped = true
	if r.inventory != nil {
		r.inventory.Stop()
		r.inventory = nil
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

func (r *peerRepair) pruneExpired(now time.Time) {
	for ip, hit := range r.byIP {
		ttl := peerMissTTL
		if hit.found {
			ttl = peerHitTTL
		}
		if now.Sub(hit.at) >= ttl {
			delete(r.byIP, ip)
		}
	}
}

func (r *peerRepair) evictOldest() {
	var oldestIP string
	var oldestTime time.Time
	for ip, hit := range r.byIP {
		if oldestIP == "" || hit.at.Before(oldestTime) {
			oldestIP = ip
			oldestTime = hit.at
		}
	}
	if oldestIP != "" {
		delete(r.byIP, oldestIP)
	}
}

// invalidate clears cached IP entries, or all entries if no IPs are specified.
func (r *peerRepair) invalidate(ips ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(ips) == 0 {
		r.byIP = make(map[string]peerIdentity)
		return
	}
	for _, ip := range ips {
		delete(r.byIP, ip)
	}
}

func (r *peerRepair) lookup(ip string) (peerIdentity, bool) {
	return r.lookupWithExpected(ip, "", "")
}

func (r *peerRepair) lookupWithExpected(ip, expectedNamespace, expectedName string) (peerIdentity, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return peerIdentity{}, false
	}
	if r.inventory == nil && r.initInv != nil {
		r.initInv()
	}
	now := r.now()

	if hit, ok := r.byIP[ip]; ok {
		if !hit.found {
			// Do not reuse negative entries for lookups with an expected identity
			if expectedName != "" {
				delete(r.byIP, ip)
			} else if now.Sub(hit.at) < peerMissTTL {
				return hit, false
			} else {
				delete(r.byIP, ip)
			}
		} else {
			if now.Sub(hit.at) < peerHitTTL {
				// Validate cached positive hit using indexed lookups to avoid scanning all pods
				// under mutex, while ensuring the pod still owns ip and no new pod took it over.
				var p *common.SlimPod
				if r.inventory != nil {
					cand := r.inventory.GetPodByName(hit.namespace, hit.name)
					if cand != nil && !cand.Spec.HostNetwork && cand.Status.PodIP == ip &&
						(expectedName == "" || cand.Name == expectedName) &&
						(expectedNamespace == "" || cand.Namespace == expectedNamespace) {
						// Ensure IP has not been reassigned to a different pod in the IP index
						if byIP := r.inventory.GetPodByIp(ip); byIP == nil || (byIP.Name == hit.name && byIP.Namespace == hit.namespace) {
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
					r.byIP[ip] = hit
					return hit, true
				}
				delete(r.byIP, ip)
			} else {
				delete(r.byIP, ip)
			}
		}
	}

	id := peerIdentity{at: now}
	var p *common.SlimPod
	if r.inventory != nil && expectedName != "" && expectedNamespace != "" {
		cand := r.inventory.GetPodByName(expectedNamespace, expectedName)
		if cand != nil && !cand.Spec.HostNetwork && cand.Status.PodIP == ip {
			p = cand
		}
	}
	if p == nil && r.pods != nil {
		pods := r.pods()
		p = podByIP(pods, ip, expectedNamespace, expectedName)
	}
	if p != nil {
		id.found, id.namespace, id.name, id.labels = true, p.Namespace, p.Name, labelString(p.Labels)
	}

	// Do not cache negative entries for identity-constrained lookups
	if !id.found && expectedName != "" {
		return id, false
	}

	if len(r.byIP) >= maxPeerEntries {
		r.pruneExpired(now)
		if len(r.byIP) >= maxPeerEntries {
			r.evictOldest()
		}
	}
	r.byIP[ip] = id
	return id, id.found
}

func (r *peerRepair) repair(d datasource.DataSource, data datasource.Data, ev *utils.DatasourceEvent) bool {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return false
	}
	r.mu.Unlock()

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
