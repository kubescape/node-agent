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
	peerHitTTL  = 30 * time.Second
	peerMissTTL = 10 * time.Second
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

func (r *peerRepair) lookup(ip string) (peerIdentity, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if hit, ok := r.byIP[ip]; ok {
		ttl := peerMissTTL
		if hit.found {
			ttl = peerHitTTL
		}
		if r.now().Sub(hit.at) < ttl {
			return hit, hit.found
		}
	}
	id := peerIdentity{at: r.now()}
	if p := podByIP(r.pods(), ip); p != nil {
		id.found, id.namespace, id.name, id.labels = true, p.Namespace, p.Name, labelString(p.Labels)
	}
	r.byIP[ip] = id
	return id, id.found
}

func (r *peerRepair) repair(d datasource.DataSource, data datasource.Data, ev *utils.DatasourceEvent) bool {
	ep := ev.GetDstEndpoint()
	if ep.Kind != "" || ep.Addr == "" || ep.Addr == "0.0.0.0" || strings.HasPrefix(ep.Addr, "127.") {
		return false
	}
	id, ok := r.lookup(ep.Addr)
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
