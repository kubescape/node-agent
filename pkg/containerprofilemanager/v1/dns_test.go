package containerprofilemanager

import (
	"fmt"
	"testing"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"
	storagefile "github.com/kubescape/storage/pkg/registry/file"
	"github.com/stretchr/testify/require"
)

func dnsResponse(name, path string) *utils.StructEvent {
	return &utils.StructEvent{DNSName: name, ExePath: path, Qr: utils.DNSPktTypeResponse, NumAnswers: 1, Rcode: "Success", Addresses: []string{"192.0.2.1"}}
}

func TestDNSBaselineLearnsResponsesWithoutConnections(t *testing.T) {
	manager, entry := newTestManager(t, "container")
	for _, name := range []string{"API.VENDOR.COM", "cdn.vendor.com.", "db.default.svc.cluster.local.", "1.2.0.192.in-addr.arpa."} {
		manager.ReportDNSEvent("container", dnsResponse(name, "/app"))
		manager.ReportDNSEvent("container", dnsResponse(name, "/usr/bin/python3"))
	}
	require.Len(t, entry.data.getDNSLookups(), 4)
	require.Equal(t, "api.vendor.com.", entry.data.getDNSLookups()[1].Name)
	for _, lookup := range entry.data.getDNSLookups() {
		require.Equal(t, []string{"/app", "/usr/bin/python3"}, lookup.ExePaths)
		require.Equal(t, []string{"192.0.2.1"}, lookup.Addresses)
	}
	require.Nil(t, entry.data.networks)
	before := entry.data.size.Load()
	manager.ReportDNSEvent("container", dnsResponse("API.VENDOR.COM", "/app"))
	require.Equal(t, before, entry.data.size.Load())
	entry.data.emptyEvents()
	require.Empty(t, entry.data.getDNSLookups())
	require.Len(t, entry.data.dnsNames, 4)
	manager.ReportDNSEvent("container", dnsResponse("API.VENDOR.COM", "/app"))
	require.Len(t, entry.data.getDNSLookups(), 1)
}

func TestDNSBaselineRejectsUnansweredAndCompleted(t *testing.T) {
	for _, mutate := range []func(*utils.StructEvent){func(e *utils.StructEvent) { e.Qr = utils.DNSPktTypeQuery }, func(e *utils.StructEvent) { e.NumAnswers = 0 }, func(e *utils.StructEvent) { e.Rcode = "NameError" }, func(e *utils.StructEvent) { e.DNSName = "" }} {
		manager, entry := newTestManager(t, "container")
		event := dnsResponse("example.com.", "/app")
		mutate(event)
		manager.ReportDNSEvent("container", event)
		require.Empty(t, entry.data.getDNSLookups())
	}
	for _, status := range []objectcache.WatchedContainerStatus{objectcache.WatchedContainerStatusCompleted, objectcache.WatchedContainerStatusTooLarge, objectcache.WatchedContainerStatusRejected} {
		manager, entry := newTestManager(t, "container")
		entry.data.watchedContainerData = &objectcache.WatchedContainerData{}
		entry.data.watchedContainerData.SetStatus(status)
		manager.ReportDNSEvent("container", dnsResponse("example.com.", "/app"))
		require.Empty(t, entry.data.getDNSLookups())
	}
}

func TestDNSBaselineCapsPersistAcrossFlush(t *testing.T) {
	manager, entry := newTestManager(t, "container")
	event := dnsResponse("example.com.", "/app")
	for i := 0; i < 100; i++ {
		event.Addresses = append(event.Addresses, fmt.Sprintf("192.0.2.%d", i))
	}
	manager.ReportDNSEvent("container", event)
	require.Len(t, entry.data.getDNSLookups()[0].Addresses, storagefile.MaxDNSAddressesPerName)
	for i := 1; i < storagefile.MaxDNSBaselineNames; i++ {
		entry.data.dnsNames[fmt.Sprintf("%d.example.", i)] = struct{}{}
	}
	entry.data.emptyEvents()
	manager.ReportDNSEvent("container", dnsResponse("overflow.example.", "/app"))
	require.True(t, entry.data.dnsBaselineTruncated)
	require.Empty(t, entry.data.getDNSLookups())
}

func TestDNSBaselineLearnsRootName(t *testing.T) {
	manager, entry := newTestManager(t, "container")
	manager.ReportDNSEvent("container", dnsResponse(".", "/app"))
	require.Len(t, entry.data.getDNSLookups(), 1)
	require.Equal(t, ".", entry.data.getDNSLookups()[0].Name)
}
