package tracers

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
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

type positiveEntry struct {
	identity  peerIdentity
	expiresAt time.Time
}

type negativeEntry struct {
	expiresAt time.Time
}

type peerRepair struct {
	mu        sync.Mutex
	stopped   bool
	hitTTL    time.Duration
	missTTL   time.Duration
	positive  *lru.Cache[string, positiveEntry]
	negative  *lru.Cache[string, negativeEntry]
	pods      func() []*common.SlimPod
	inventory common.K8sInventoryCache
	initInv   func() common.K8sInventoryCache
}

func newPeerRepair() *peerRepair {
	pos, _ := lru.New[string, positiveEntry](maxPeerEntries)
	neg, _ := lru.New[string, negativeEntry](maxPeerEntries)
	r := &peerRepair{
		positive: pos,
		negative: neg,
		hitTTL:   peerHitTTL,
		missTTL:  peerMissTTL,
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
		pos, _ := lru.New[string, positiveEntry](maxPeerEntries)
		r.positive = pos
	}
	if r.negative == nil {
		neg, _ := lru.New[string, negativeEntry](maxPeerEntries)
		r.negative = neg
	}
	if r.hitTTL == 0 {
		r.hitTTL = peerHitTTL
	}
	if r.missTTL == 0 {
		r.missTTL = peerMissTTL
	}
}

func (r *peerRepair) getPositive(ip string) (peerIdentity, bool) {
	entry, ok := r.positive.Get(ip)
	if !ok {
		return peerIdentity{}, false
	}
	if time.Now().After(entry.expiresAt) {
		r.positive.Remove(ip)
		return peerIdentity{}, false
	}
	return entry.identity, true
}

func (r *peerRepair) addPositive(ip string, id peerIdentity) {
	ttl := r.hitTTL
	if ttl == 0 {
		ttl = peerHitTTL
	}
	r.positive.Add(ip, positiveEntry{
		identity:  id,
		expiresAt: time.Now().Add(ttl),
	})
}

func (r *peerRepair) isNegative(ip string) bool {
	entry, ok := r.negative.Get(ip)
	if !ok {
		return false
	}
	if time.Now().After(entry.expiresAt) {
		r.negative.Remove(ip)
		return false
	}
	return true
}

func (r *peerRepair) addNegative(ip string) {
	ttl := r.missTTL
	if ttl == 0 {
		ttl = peerMissTTL
	}
	r.negative.Add(ip, negativeEntry{
		expiresAt: time.Now().Add(ttl),
	})
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
	} else if r.isNegative(ip) {
		return peerIdentity{}, false
	}

	if hit, ok := r.getPositive(ip); ok {
		// Validate cached positive hit using indexed lookups to avoid scanning all pods,
		// while ensuring the pod still owns ip and no new pod took it over.
		var p *common.SlimPod
		if inv != nil {
			cand := inv.GetPodByName(hit.namespace, hit.name)
			if cand != nil && !cand.Spec.HostNetwork && cand.Status.PodIP == ip &&
				(expectedName == "" || cand.Name == expectedName) &&
				(expectedNamespace == "" || cand.Namespace == expectedNamespace) {
				if byIP := inv.GetPodByIp(ip); byIP != nil {
					if byIP.Name == hit.name && byIP.Namespace == hit.namespace {
						p = cand
					}
				} else if r.pods != nil {
					if unambiguous := podByIP(r.pods(), ip, "", ""); unambiguous != nil && unambiguous.Name == hit.name && unambiguous.Namespace == hit.namespace {
						p = cand
					}
				}
			}
		} else if r.pods != nil {
			pods := r.pods()
			p = podByIP(pods, ip, expectedNamespace, expectedName)
		}
		if p != nil && p.Name == hit.name && p.Namespace == hit.namespace {
			// Refresh cached labels in case the pod was relabeled
			hit.labels = labelString(p.Labels)
			r.addPositive(ip, hit)
			return hit, true
		}
		r.positive.Remove(ip)
	}

	var p *common.SlimPod
	if inv != nil && expectedName != "" && expectedNamespace != "" {
		cand := inv.GetPodByName(expectedNamespace, expectedName)
		if cand != nil && !cand.Spec.HostNetwork && cand.Status.PodIP == ip {
			if byIP := inv.GetPodByIp(ip); byIP != nil {
				if byIP.Name == cand.Name && byIP.Namespace == cand.Namespace {
					p = cand
				} else {
					// The IP has been reassigned to a different pod in the IP index (IP reuse).
					// Do not let the expected-name fallback select the stale terminating pod.
					return peerIdentity{}, false
				}
			} else if r.pods != nil {
				// Validate the nil-index case against an unambiguous full-IP lookup before accepting the expected identity
				if unambiguous := podByIP(r.pods(), ip, "", ""); unambiguous != nil && unambiguous.Name == cand.Name && unambiguous.Namespace == cand.Namespace {
					p = cand
				} else {
					return peerIdentity{}, false
				}
			}
		}
	}
	if p == nil && r.pods != nil {
		pods := r.pods()
		p = podByIP(pods, ip, expectedNamespace, expectedName)
	}
	if p != nil {
		id := peerIdentity{namespace: p.Namespace, name: p.Name, labels: labelString(p.Labels)}
		r.addPositive(ip, id)
		return id, true
	}

	// Do not cache negative entries for identity-constrained lookups
	if expectedName == "" {
		r.addNegative(ip)
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
	// Non-pod resolved endpoints (e.g. services) are preserved.
	if ep.Kind != "" && ep.Kind != igtypes.EndpointKindRaw && ep.Kind != igtypes.EndpointKindPod {
		return false
	}

	var target peerIdentity
	if ep.Kind == igtypes.EndpointKindPod && ep.Name != "" {
		// Validate that the existing pod identity still owns the IP.
		if id, ok := r.lookupWithExpected(ep.Addr, ep.Namespace, ep.Name); ok {
			// Pod still owns the IP. If labels are already current, nothing to repair.
			if len(ep.PodLabels) > 0 && id.labels == labelString(ep.PodLabels) {
				return false
			}
			target = id
		} else {
			// Existing pod identity is stale (e.g. IP reused during pod churn).
			// Attempt to resolve the true current IP owner.
			if id, ok := r.lookup(ep.Addr); ok {
				target = id
			} else {
				// Ambiguous or unknown; clear stale pod identity to avoid misattribution.
				r.clearPodEndpoint(d, data)
				return true
			}
		}
	} else {
		// Unresolved endpoint or pod without name: look up current IP owner.
		id, ok := r.lookupWithExpected(ep.Addr, ep.Namespace, ep.Name)
		if !ok {
			return false
		}
		target = id
	}

	for name, value := range map[string]string{
		"endpoint.k8s.kind":      string(igtypes.EndpointKindPod),
		"endpoint.k8s.namespace": target.namespace,
		"endpoint.k8s.name":      target.name,
		"endpoint.k8s.labels":    target.labels,
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

func (r *peerRepair) clearPodEndpoint(d datasource.DataSource, data datasource.Data) {
	if f := d.GetField("endpoint.k8s.kind"); f != nil {
		_ = f.PutString(data, string(igtypes.EndpointKindRaw))
	}
	for _, name := range []string{"endpoint.k8s.namespace", "endpoint.k8s.name", "endpoint.k8s.labels"} {
		if f := d.GetField(name); f != nil {
			_ = f.PutString(data, "")
		}
	}
}
