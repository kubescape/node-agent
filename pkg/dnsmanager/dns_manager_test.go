package dnsmanager

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/goradd/maps"
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
			// Create a properly initialized DNSManager
			dm := &DNSManager{
				addressToDomainMap: maps.SafeMap[string, string]{},
				lookupCache:        &sync.Map{},
				failureCache:       &sync.Map{},
				cleanupTicker:      time.NewTicker(cleanupInterval),
			}

			dm.ReportDNSEvent(tt.dnsEvent)
			got, ok := dm.ResolveIPAddress(tt.ipAddr)
			if got != tt.want || ok != tt.wantOk {
				t.Errorf("ResolveIPAddress() got = %v, ok = %v, want = %v, wantOk = %v", got, ok, tt.want, tt.wantOk)
			}

			// Cleanup
			dm.cleanupTicker.Stop()
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
			// Create a properly initialized DNSManager
			dm := &DNSManager{
				addressToDomainMap: maps.SafeMap[string, string]{},
				lookupCache:        &sync.Map{},
				failureCache:       &sync.Map{},
				cleanupTicker:      time.NewTicker(cleanupInterval),
			}

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

			// Cleanup
			dm.cleanupTicker.Stop()
		})
	}
}
