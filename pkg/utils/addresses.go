package utils

import "net"

func rawIPv4ToString(ipInt uint32) string {
	// An IPv4 address is 4 bytes. We use bitwise shifts to extract the four octets
	// in network (Big Endian) order, which is the standard for IP addresses.
	ipBytes := []byte{
		byte(ipInt >> 24), // First octet (MSB)
		byte(ipInt >> 16), // Second octet
		byte(ipInt >> 8),  // Third octet
		byte(ipInt),       // Fourth octet (LSB)
	}

	// net.IP(ipBytes) creates an IP address object from the bytes,
	// and .String() returns the dotted-decimal notation.
	return net.IP(ipBytes).String()
}
