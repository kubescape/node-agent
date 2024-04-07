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
			want: "test.com",
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
			want: "",
		},
		{
			name:   "no address",
			ipAddr: "67.225.146.248",
			dnsEvent: tracerdnstype.Event{
				DNSName:    "test.com",
				NumAnswers: 0, // will not resolve
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dm := &DNSManager{}
			dm.ReportDNSEvent(tt.dnsEvent)
			got, _ := dm.ResolveIPAddress(tt.ipAddr)
			if got != tt.want {
				t.Errorf("ResolveIPAddress() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveIPAddressFallback(t *testing.T) {
	tests := []struct {
		name     string
		dnsEvent tracerdnstype.Event
		want     string
	}{

		{
			name: "dns resolution fallback",
			dnsEvent: tracerdnstype.Event{
				DNSName:    "test.com",
				NumAnswers: 1,
			},
			want: "test.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addresses, _ := net.LookupIP(tt.dnsEvent.DNSName)
			dm := &DNSManager{}
			dm.ReportDNSEvent(tt.dnsEvent)
			got, _ := dm.ResolveIPAddress(addresses[0].String())
			if got != tt.want {
				t.Errorf("ResolveIPAddress() got = %v, want %v", got, tt.want)
			}
		})
	}
}
