package net

import (
	"net"
	"strconv"

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

// formatEndpoint joins an address and a port into one endpoint string,
// bracketing IPv6 addresses so the port stays unambiguous: "10.0.0.5:23" for
// IPv4 and "[fd00::1]:23" for IPv6. It is meant for rule message text only.
func (l *netLibrary) formatEndpoint(addr, port ref.Val) ref.Val {
	addrStr, ok := addr.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(addr)
	}
	portInt, ok := port.Value().(int64)
	if !ok {
		return types.MaybeNoSuchOverloadErr(port)
	}
	return types.String(net.JoinHostPort(addrStr, strconv.FormatInt(portInt, 10)))
}
