package net

import (
	"net"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

func (l *netLibrary) isPrivateIP(ip ref.Val) ref.Val {
	ipStr, ok := ip.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(ip)
	}

	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return types.Bool(false)
	}

	// Include loopback, RFC 1918, IPv6 unique-local and link-local addresses.
	if parsedIP.IsLoopback() || parsedIP.IsPrivate() || parsedIP.IsLinkLocalUnicast() {
		return types.Bool(true)
	}

	// Preserve the helper's IPv4 multicast and experimental ranges, and
	// include the shared address space used by carrier-grade NAT.
	v4 := parsedIP.To4()
	if v4 == nil {
		return types.Bool(false)
	}
	return types.Bool(v4[0] >= 224 || (v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127))
}
