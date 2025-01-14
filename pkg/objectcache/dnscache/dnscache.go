package dnscache

import (
	"github.com/kubescape/go-logger"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/objectcache"
)

var _ objectcache.DnsCache = (*DnsCacheImpl)(nil)

type DnsCacheImpl struct {
	dnsResolver dnsmanager.DNSResolver
}

func NewDnsCache(dnsResolver dnsmanager.DNSResolver) *DnsCacheImpl {
	return &DnsCacheImpl{
		dnsResolver: dnsResolver,
	}
}

func (d *DnsCacheImpl) ResolveIpToDomain(ip string) string {
	if d.dnsResolver == nil {
		logger.L().Debug("DnsCacheImpl - resolver is not set")
		return ""
	}

	domain, ok := d.dnsResolver.ResolveIPAddress(ip)
	if !ok {
		return ""
	}

	return domain
}
