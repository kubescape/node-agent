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
	byIP      map[string]peerIdentity
	now       func() time.Time
	pods      func() []*common.SlimPod
	inventory common.K8sInventoryCache
	once      sync.Once
}

func newPeerRepair() *peerRepair {
	r := &peerRepair{byIP: map[string]peerIdentity{}, now: time.Now}
	r.pods = func() []*common.SlimPod {
		r.once.Do(func() {
			inv, err := common.GetK8sInventoryCache()
			if err != nil {
				logger.L().Warning("network tracer: peer repair has no inventory", helpers.Error(err))
				return
			}
			r.inventory = inv
		})
		if r.inventory == nil {
			return nil
		}
		return r.inventory.GetPods()
	}
	return r
}

func podByIP(pods []*common.SlimPod, ip string) *common.SlimPod {
	for _, p := range pods {
		if p == nil || p.Spec.HostNetwork || p.Status.PodIP != ip {
			continue
		}
		return p
	}
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
	now := r.now()
	r.pruneExpired(now)

	if hit, ok := r.byIP[ip]; ok {
		if !hit.found {
			if now.Sub(hit.at) < peerMissTTL {
				return hit, false
			}
			delete(r.byIP, ip)
		} else {
			if now.Sub(hit.at) < peerHitTTL {
				// Ownership validation: validate cached positive hit against current pod list
				// and against any expected pod metadata from upstream.
				pods := r.pods()
				p := podByIP(pods, ip)
				if p != nil && p.Name == hit.name && p.Namespace == hit.namespace &&
					(expectedName == "" || p.Name == expectedName) &&
					(expectedNamespace == "" || p.Namespace == expectedNamespace) {
					return hit, true
				}
				delete(r.byIP, ip)
			} else {
				delete(r.byIP, ip)
			}
		}
	}

	id := peerIdentity{at: now}
	pods := r.pods()
	if p := podByIP(pods, ip); p != nil {
		if expectedName == "" || p.Name == expectedName {
			id.found, id.namespace, id.name, id.labels = true, p.Namespace, p.Name, labelString(p.Labels)
		}
	}
	if !id.found && expectedName != "" {
		for _, p := range pods {
			if p == nil || p.Spec.HostNetwork {
				continue
			}
			if p.Name == expectedName && (expectedNamespace == "" || p.Namespace == expectedNamespace) {
				id.found, id.namespace, id.name, id.labels = true, p.Namespace, p.Name, labelString(p.Labels)
				break
			}
		}
	}

	if len(r.byIP) >= maxPeerEntries {
		r.evictOldest()
	}
	r.byIP[ip] = id
	return id, id.found
}

func (r *peerRepair) repair(d datasource.DataSource, data datasource.Data, ev *utils.DatasourceEvent) bool {
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
