package utils

import (
	"net"
	"testing"
)

func TestRawIPv4ToString(t *testing.T) {
	tests := []struct {
		name     string
		ipInt    uint32
		expected string
	}{
		{
			name:     "All zeros",
			ipInt:    0x00000000,
			expected: "0.0.0.0",
		},
		{
			name:     "All ones",
			ipInt:    0xFFFFFFFF,
			expected: "255.255.255.255",
		},
		{
			name:     "Loopback",
			ipInt:    0x7F000001,
			expected: "127.0.0.1",
		},
		{
			name:     "Google DNS",
			ipInt:    0x08080808,
			expected: "8.8.8.8",
		},
		{
			name:     "Mixed",
			ipInt:    0xC0A80101,
			expected: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rawIPv4ToString(tt.ipInt)
			if got != tt.expected {
				t.Errorf("rawIPv4ToString(%#x) = %q, want %q", tt.ipInt, got, tt.expected)
			}
		})
	}
}

func TestRawIPv6ToString(t *testing.T) {
	tests := []struct {
		name     string
		ipBytes  []byte
		expected string
	}{
		{
			name:     "All zeros",
			ipBytes:  make([]byte, 16),
			expected: "::",
		},
		{
			name:     "Loopback",
			ipBytes:  []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			expected: "::1",
		},
		{
			name:     "Google Public DNS",
			ipBytes:  net.ParseIP("2001:4860:4860::8888").To16(),
			expected: "2001:4860:4860::8888",
		},
		{
			name:     "IPv4-mapped IPv6",
			ipBytes:  net.ParseIP("::ffff:192.168.1.1").To16(),
			expected: "192.168.1.1",
		},
		{
			name:     "Custom address",
			ipBytes:  net.ParseIP("fd12:3456:789a:1::1").To16(),
			expected: "fd12:3456:789a:1::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rawIPv6ToString(tt.ipBytes)
			if got != tt.expected {
				t.Errorf("rawIPv6ToString(%v) = %q, want %q", tt.ipBytes, got, tt.expected)
			}
		})
	}
}
