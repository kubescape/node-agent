// Package hostidentity provides a single shared source of identity for the
// "host" pseudo-container (ContainerID == armotypes.HostContainerID), used to
// unblock the host profile, malware and (eventually) SBOM pipelines.
//
// It lives in its own package, rather than pkg/utils as originally sketched,
// because pkg/config transitively imports pkg/utils (config -> exporters ->
// malwaremanager -> utils), so pkg/utils cannot import pkg/config without
// creating an import cycle. This package depends on pkg/config,
// pkg/hostsensormanager and pkg/objectcache, none of which import it back.
package hostidentity

import (
	"fmt"
	"os"
	"path"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/instanceidhandler"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1/containerinstance"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/hostsensormanager"
	"github.com/kubescape/node-agent/pkg/objectcache"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// machineIDPath is the well-known location of the machine ID file, relative
// to the host filesystem root (see hostsensormanager.HostFSPrefix).
const machineIDPath = "/etc/machine-id"

// hostInstanceApiVersion/Kind/Namespace/Type are the synthetic workload
// identity components used to build the host's IInstanceID. There is no real
// Kubernetes object backing the "host" pseudo-container, so these are fixed,
// documented placeholders rather than derived from any API server data.
const (
	hostInstanceApiVersion = "v1"
	hostInstanceKind       = "Node"
	hostNamespace          = "host"
	hostInstanceType       = "host"
)

// ResolveHostID returns a stable identifier for the node the agent is running
// on. It never silently returns an empty string: if neither source below
// yields a non-empty value, it returns an error instead.
//
// Primary source: cfg.NodeName (pkg/config/config.go), populated from the
// NODE_NAME env var via the Kubernetes downward API - stable across restarts
// and already available with no new mechanism required.
//
// Fallback (only when NodeName is empty): the host's /etc/machine-id, read
// through the HOST_ROOT-aware host filesystem prefix used elsewhere in the
// codebase (see pkg/hostsensormanager.HostFSPrefix). Note this only resolves
// to the true node's machine-id when HOST_ROOT is mounted from the host (as
// the DaemonSet does); reading a container-local /etc/machine-id would return
// the container's own id, not the node's.
func ResolveHostID(cfg *config.Config) (string, error) {
	if cfg != nil {
		if nodeName := cfg.NodeName; nodeName != "" {
			return nodeName, nil
		}
	}

	machineIDFile := path.Join(hostsensormanager.HostFSPrefix(), machineIDPath)
	content, err := os.ReadFile(machineIDFile)
	if err != nil {
		return "", fmt.Errorf("resolveHostID: NodeName is empty and failed to read machine-id from %s: %w", machineIDFile, err)
	}

	machineID := trimTrailingNewline(content)
	if machineID == "" {
		return "", fmt.Errorf("resolveHostID: NodeName is empty and machine-id file %s is empty", machineIDFile)
	}

	return machineID, nil
}

func trimTrailingNewline(b []byte) string {
	s := string(b)
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

// BuildHostWlid builds the synthetic Wlid used to represent the host
// pseudo-workload for the profile/malware pipelines.
func BuildHostWlid(hostID string) string {
	return fmt.Sprintf("wlid://cluster-unknown/namespace-host/host-%s", hostID)
}

// BuildHostInstanceID builds a real instanceidhandler.IInstanceID for the
// host pseudo-container. InstanceType and TemplateHash are set explicitly
// since both surface via WatchedContainerData.GetLabels() /
// objectcache.GetLabels().
func BuildHostInstanceID(hostID string) instanceidhandler.IInstanceID {
	return &containerinstance.InstanceID{
		ApiVersion:    hostInstanceApiVersion,
		Namespace:     hostNamespace,
		Kind:          hostInstanceKind,
		Name:          fmt.Sprintf("host-%s", hostID),
		ContainerName: armotypes.HostContainerID,
		InstanceType:  hostInstanceType,
		TemplateHash:  hostInstanceType,
	}
}

// BuildHostWatchedContainerData builds the WatchedContainerData used to
// represent the host pseudo-container in the shared container data cache.
// Every field is explicitly set (no zero-value gaps), since downstream
// consumers (e.g. containerprofilemanager/v1/lifecycle.go) branch on unset
// fields such as PreRunningContainer.
//
// ContainerInfos/ContainerIndex are set explicitly to a single synthetic
// entry for the same reason: for a real container these are populated by
// WatchedContainerData.SetContainerInfo from a live pod spec/status (see
// pkg/objectcache/shared_container_data.go), a K8s-dependent path host
// deliberately never goes through (the single host injection point replaces,
// rather than falls through to, that lookup). Left unset, ContainerInfos is a
// nil map, and containerprofilemanager/v1/monitoring.go's saveContainerProfile
// unconditionally indexes
// watchedContainer.ContainerInfos[watchedContainer.ContainerType][watchedContainer.ContainerIndex]
// when building the CR -- a nil/empty slice index panics on host's very first
// profile save.
func BuildHostWatchedContainerData(hostID string) *objectcache.WatchedContainerData {
	return &objectcache.WatchedContainerData{
		InstanceID:     BuildHostInstanceID(hostID),
		ContainerID:    armotypes.HostContainerID,
		PodName:        fmt.Sprintf("host-%s", hostID),
		Namespace:      hostNamespace,
		Wlid:           BuildHostWlid(hostID),
		ContainerType:  objectcache.Container,
		ContainerIndex: 0,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {{Name: armotypes.HostContainerID}},
		},
		PreRunningContainer:    false,
		UserDefinedProfile:     "",
		ParentWorkloadSelector: &metav1.LabelSelector{},
	}
}
