package objectcache

type DnsCache interface {
	ResolveIpToDomain(ip string) string
}

var _DnsCache = (*DnsCacheMock)(nil)

type DnsCacheMock struct {
}

func (dc *DnsCacheMock) ResolveIpToDomain(_ string) string {
	return ""
}
