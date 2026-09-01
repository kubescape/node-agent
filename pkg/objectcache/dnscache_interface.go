package objectcache

type DnsCache interface {
	ResolveIpToDomain(containerID string, ip string) string
}

var _ DnsCache = (*DnsCacheMock)(nil)

type DnsCacheMock struct {
}

func (dc *DnsCacheMock) ResolveIpToDomain(_ string, _ string) string {
	return ""
}
