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
			ipInt:    0x0100007F,
			expected: "127.0.0.1",
		},
		{
			name:     "Google DNS",
			ipInt:    0x04040808,
			expected: "8.8.4.4",
		},
		{
			name:     "Mixed",
			ipInt:    0x0101A8C0,
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
			name:     "Custom address",
			ipBytes:  []byte{42, 14, 231, 1, 32, 193, 0, 0, 173, 60, 254, 9, 63, 22, 12, 247},
			expected: "2a0e:e701:20c1:0:ad3c:fe09:3f16:cf7",
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
