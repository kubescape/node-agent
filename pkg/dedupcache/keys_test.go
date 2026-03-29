package dedupcache

import "testing"

func TestComputeOpenKey_Deterministic(t *testing.T) {
	k1 := ComputeOpenKey(123456, 42, "/etc/passwd", 0x02)
	k2 := ComputeOpenKey(123456, 42, "/etc/passwd", 0x02)
	if k1 != k2 {
		t.Fatalf("non-deterministic: %x != %x", k1, k2)
	}
}

func TestComputeOpenKey_DifferentInputs(t *testing.T) {
	k1 := ComputeOpenKey(123456, 42, "/etc/passwd", 0x02)
	k2 := ComputeOpenKey(123456, 42, "/etc/shadow", 0x02)
	k3 := ComputeOpenKey(123456, 43, "/etc/passwd", 0x02)
	k4 := ComputeOpenKey(789012, 42, "/etc/passwd", 0x02)
	k5 := ComputeOpenKey(123456, 42, "/etc/passwd", 0x04)

	keys := []uint64{k1, k2, k3, k4, k5}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] == keys[j] {
				t.Fatalf("collision between key[%d]=%x and key[%d]=%x", i, keys[i], j, keys[j])
			}
		}
	}
}

func TestComputeNetworkKey_Deterministic(t *testing.T) {
	k1 := ComputeNetworkKey(100, 1, "10.0.0.1", 80, "tcp")
	k2 := ComputeNetworkKey(100, 1, "10.0.0.1", 80, "tcp")
	if k1 != k2 {
		t.Fatalf("non-deterministic: %x != %x", k1, k2)
	}
}

func TestComputeNetworkKey_DifferentInputs(t *testing.T) {
	k1 := ComputeNetworkKey(100, 1, "10.0.0.1", 80, "tcp")
	k2 := ComputeNetworkKey(100, 1, "10.0.0.2", 80, "tcp")
	k3 := ComputeNetworkKey(100, 1, "10.0.0.1", 443, "tcp")
	k4 := ComputeNetworkKey(100, 1, "10.0.0.1", 80, "udp")
	if k1 == k2 || k1 == k3 || k1 == k4 {
		t.Fatal("unexpected collision")
	}
}

func TestComputeDNSKey_Deterministic(t *testing.T) {
	k1 := ComputeDNSKey(100, "example.com")
	k2 := ComputeDNSKey(100, "example.com")
	if k1 != k2 {
		t.Fatalf("non-deterministic: %x != %x", k1, k2)
	}
}

func TestComputeDNSKey_DifferentInputs(t *testing.T) {
	k1 := ComputeDNSKey(100, "example.com")
	k2 := ComputeDNSKey(100, "other.com")
	k3 := ComputeDNSKey(200, "example.com")
	if k1 == k2 || k1 == k3 {
		t.Fatal("unexpected collision")
	}
}

func TestComputeHTTPKey_IncludesRawQuery(t *testing.T) {
	k1 := ComputeHTTPKey(100, 1, "outbound", "GET", "example.com", "/api", "page=1")
	k2 := ComputeHTTPKey(100, 1, "outbound", "GET", "example.com", "/api", "page=1' OR 1=1--")
	if k1 == k2 {
		t.Fatal("different query strings must produce different keys")
	}
}

func TestComputeSSHKey_Deterministic(t *testing.T) {
	k1 := ComputeSSHKey(100, "192.168.1.1", 22)
	k2 := ComputeSSHKey(100, "192.168.1.1", 22)
	if k1 != k2 {
		t.Fatalf("non-deterministic: %x != %x", k1, k2)
	}
}

func TestComputeCapabilitiesKey_Deterministic(t *testing.T) {
	k1 := ComputeCapabilitiesKey(100, 1, "CAP_NET_RAW", "socket")
	k2 := ComputeCapabilitiesKey(100, 1, "CAP_NET_RAW", "socket")
	if k1 != k2 {
		t.Fatalf("non-deterministic: %x != %x", k1, k2)
	}
}

func TestComputeSyscallKey_DifferentInputs(t *testing.T) {
	k1 := ComputeSyscallKey(100, 1, "read")
	k2 := ComputeSyscallKey(100, 1, "write")
	if k1 == k2 {
		t.Fatal("unexpected collision")
	}
}

func BenchmarkComputeOpenKey(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ComputeOpenKey(123456, 42, "/etc/passwd", 0x02)
	}
}

func BenchmarkComputeNetworkKey(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ComputeNetworkKey(100, 1, "10.0.0.1", 80, "tcp")
	}
}

func BenchmarkComputeDNSKey(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ComputeDNSKey(100, "example.com")
	}
}

func BenchmarkComputeHTTPKey(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ComputeHTTPKey(100, 1, "outbound", "GET", "example.com", "/api/v1/users", "page=1&limit=50")
	}
}

func BenchmarkComputeCapabilitiesKey(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ComputeCapabilitiesKey(100, 1, "CAP_NET_RAW", "socket")
	}
}

func BenchmarkComputeSyscallKey(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ComputeSyscallKey(100, 1, "read")
	}
}
