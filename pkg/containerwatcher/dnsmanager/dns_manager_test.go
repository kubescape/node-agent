package dnsmanager

import (
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
			ipAddr: "14.23.332.4",
			dnsEvent: tracerdnstype.Event{
				DNSName: "test.com",
				Addresses: []string{
					"14.23.332.4",
				},
			},
			want: "test.com",
		},
		{
			name:   "ip not found",
			ipAddr: "14.23.332.4",
			dnsEvent: tracerdnstype.Event{
				DNSName: "test.com",
				Addresses: []string{
					"54.23.332.4",
				},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dm := &DNSManager{}
			dm.SaveNetworkEvent(tt.dnsEvent)
			got, _ := dm.ResolveIPAddress(tt.ipAddr)
			if got != tt.want {
				t.Errorf("ResolveIPAddress() got = %v, want %v", got, tt.want)
			}
		})
	}
}
