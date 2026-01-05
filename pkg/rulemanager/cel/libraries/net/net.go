package net

import (
	"bytes"
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

	// Check if IP is localhost
	if parsedIP.IsLoopback() {
		return types.Bool(true)
	}

	// Check if IP is in private IP ranges
	privateIPRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
		// Class D (Multicast)
		{net.ParseIP("224.0.0.0"), net.ParseIP("239.255.255.255")},
		// Class E (Experimental)
		{net.ParseIP("240.0.0.0"), net.ParseIP("255.255.255.255")},
		// APIPA (sometimes used for local dns)
		{net.ParseIP("169.254.0.0"), net.ParseIP("169.254.255.255")},
	}

	for _, r := range privateIPRanges {
		if bytes.Compare(parsedIP, r.start) >= 0 && bytes.Compare(parsedIP, r.end) <= 0 {
			return types.Bool(true)
		}
	}

	return types.Bool(false)
}
