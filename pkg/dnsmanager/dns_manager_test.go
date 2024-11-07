package dnsmanager

import (
	"net"
	"testing"

	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
)

func TestResolveIPAddress(t *testing.T) {
	tests := []struct {
		name     string
		dnsEvent tracerdnstype.Event
		ipAddr   string
		want     string
		wantOk   bool
	}{
		{
			name:   "ip found",
			ipAddr: "67.225.146.248",
			dnsEvent: tracerdnstype.Event{
				DNSName:    "test.com",
				NumAnswers: 1,
				Addresses: []string{
					"67.225.146.248",
				},
			},
			want:   "test.com",
			wantOk: true,
		},
		{
			name:   "ip not found",
			ipAddr: "67.225.146.248",
			dnsEvent: tracerdnstype.Event{
				DNSName:    "test.com",
				NumAnswers: 1,
				Addresses: []string{
					"54.23.332.4",
				},
			},
			want:   "",
			wantOk: false,
		},
		{
			name:   "no address",
			ipAddr: "67.225.146.248",
			dnsEvent: tracerdnstype.Event{
				DNSName:    "test.com",
				NumAnswers: 0,
			},
			want:   "",
			wantOk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dm := CreateDNSManager()

			dm.ReportDNSEvent(tt.dnsEvent)
			got, ok := dm.ResolveIPAddress(tt.ipAddr)
			if got != tt.want || ok != tt.wantOk {
				t.Errorf("ResolveIPAddress() got = %v, ok = %v, want = %v, wantOk = %v", got, ok, tt.want, tt.wantOk)
			}
		})
	}
}

func TestResolveIPAddressFallback(t *testing.T) {
	// Skip the test if running in CI or without network access
	if testing.Short() {
		t.Skip("Skipping test that requires network access")
	}

	tests := []struct {
		name     string
		dnsEvent tracerdnstype.Event
		want     string
		wantOk   bool
	}{
		{
			name: "dns resolution fallback",
			dnsEvent: tracerdnstype.Event{
				DNSName:    "example.com", // Using example.com as it's guaranteed to exist
				NumAnswers: 1,
			},
			want:   "example.com",
			wantOk: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dm := CreateDNSManager()

			// Perform the actual DNS lookup
			addresses, err := net.LookupIP(tt.dnsEvent.DNSName)
			if err != nil {
				t.Skipf("DNS lookup failed: %v", err)
				return
			}
			if len(addresses) == 0 {
				t.Skip("No addresses returned from DNS lookup")
				return
			}

			dm.ReportDNSEvent(tt.dnsEvent)
			got, ok := dm.ResolveIPAddress(addresses[0].String())
			if got != tt.want || ok != tt.wantOk {
				t.Errorf("ResolveIPAddress() got = %v, ok = %v, want = %v, wantOk = %v", got, ok, tt.want, tt.wantOk)
			}
		})
	}
}

func TestCacheFallbackBehavior(t *testing.T) {
	dm := CreateDNSManager()

	// Test successful DNS lookup caching
	event := tracerdnstype.Event{
		DNSName: "test.com",
		Addresses: []string{
			"1.2.3.4",
		},
	}
	dm.ReportDNSEvent(event)

	// Check if the lookup is cached
	cached, found := dm.lookupCache.Get(event.DNSName)
	if !found {
		t.Error("Expected DNS lookup to be cached")
	}

	entry, ok := cached.(cacheEntry)
	if !ok {
		t.Error("Cached entry is not of type cacheEntry")
	}
	if len(entry.addresses) != 1 || entry.addresses[0] != "1.2.3.4" {
		t.Error("Cached addresses do not match expected values")
	}

	// Test failed lookup caching
	failEvent := tracerdnstype.Event{
		DNSName: "nonexistent.local",
	}
	dm.ReportDNSEvent(failEvent)

	// Check if the failure is cached
	_, found = dm.failureCache.Get(failEvent.DNSName)
	if !found {
		t.Error("Expected failed DNS lookup to be cached")
	}

	// Test cache hit behavior
	hitCount := 0
	for i := 0; i < 5; i++ {
		if cached, found := dm.lookupCache.Get(event.DNSName); found {
			entry := cached.(cacheEntry)
			if len(entry.addresses) > 0 {
				hitCount++
			}
		}
	}
	if hitCount != 5 {
		t.Errorf("Expected 5 cache hits, got %d", hitCount)
	}
}
