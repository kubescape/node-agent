package v1

import (
	"encoding/hex"
	"net"
	"strconv"
	"strings"
)

// hexToString decodes a hex string to a regular string.
func hexToString(hexStr string) (string, error) {
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// hexToDec converts a hex string to a decimal number.
func hexToDec(hexStr string) (int64, error) {
	return strconv.ParseInt(hexStr, 16, 64)
}

// hexToIP converts a hex string to an IP address.
func hexToIP(hexStr string) (string, error) {
	// Convert hex string to bytes
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}

	// Convert bytes to IP address
	ip := net.IP(bytes)
	if ip == nil {
		return "", err
	}

	// Remove leading zeros for IPv4
	return strings.TrimLeft(ip.String(), "0:"), nil
}
