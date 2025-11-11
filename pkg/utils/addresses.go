package utils

import (
	"encoding/binary"
	"net"
)

func rawIPv4ToString(ipInt uint32) string {
	ipBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipBytes, ipInt)
	return net.IP(ipBytes).String()
}

func rawIPv6ToString(b []byte) string {
	return net.IP(b).String()
}
