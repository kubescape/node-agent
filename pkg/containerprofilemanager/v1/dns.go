package containerprofilemanager

import (
	"github.com/DmitriyVTitov/size"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	storagefile "github.com/kubescape/storage/pkg/registry/file"
	"net"
	"sort"
	"strings"
)

// ReportDNSEvent learns successful answered responses during the existing learning window.
// Queries, errors, missing names, and events after completion cannot extend the baseline.
func (cpm *ContainerProfileManager) ReportDNSEvent(containerID string, event utils.DNSEvent) {
	if event.GetQr() != utils.DNSPktTypeResponse || event.GetNumAnswers() <= 0 || event.GetRcode() != "Success" {
		return
	}
	name := strings.ToLower(strings.TrimSuffix(event.GetDNSName(), "."))
	if name == "" || len(name) > 253 {
		return
	}
	name += "."
	err := cpm.withContainer(containerID, func(data *containerData) (int, error) {
		if watched := data.watchedContainerData; watched != nil {
			status := watched.GetStatus()
			if status == objectcache.WatchedContainerStatusCompleted || status == objectcache.WatchedContainerStatusTooLarge || status == objectcache.WatchedContainerStatusRejected {
				return 0, nil
			}
		}
		if data.dnsNames == nil {
			data.dnsNames = make(map[string]struct{})
		}
		if _, known := data.dnsNames[name]; !known && len(data.dnsNames) >= storagefile.MaxDNSBaselineNames {
			data.dnsBaselineTruncated = true
			return 0, nil
		}
		data.dnsNames[name] = struct{}{}
		if data.dnsLookups == nil {
			data.dnsLookups = make(map[string]v1beta1.DNSLookup)
		}
		entry := data.dnsLookups[name]
		before := size.Of(entry)
		entry.Name = name
		if path := event.GetExePath(); path != "" {
			entry.ExePaths = appendUnique(entry.ExePaths, path)
		}
		for _, address := range event.GetAddresses() {
			if ip := net.ParseIP(address); ip != nil && len(entry.Addresses) < storagefile.MaxDNSAddressesPerName {
				entry.Addresses = appendUnique(entry.Addresses, ip.String())
			}
		}
		data.dnsLookups[name] = entry
		return size.Of(entry) - before, nil
	})
	cpm.logEventError(err, "dns", containerID)
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func (cd *containerData) getDNSLookups() []v1beta1.DNSLookup {
	result := make([]v1beta1.DNSLookup, 0, len(cd.dnsLookups))
	for _, entry := range cd.dnsLookups {
		sort.Strings(entry.ExePaths)
		sort.Strings(entry.Addresses)
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}
