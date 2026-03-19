package utils

import (
	"encoding/binary"
	"net"

	"github.com/kubescape/node-agent/pkg/intern"
)

func rawIPv4ToString(ipInt uint32) string {
	ipBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipBytes, ipInt)
	return intern.String(net.IP(ipBytes).String())
}

func rawIPv6ToString(b []byte) string {
	return intern.String(net.IP(b).String())
}
