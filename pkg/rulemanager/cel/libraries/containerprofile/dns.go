package containerprofile

import (
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
)

func (l *containerProfileLibrary) wasDNSResolved(containerID, domain, process ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}
	id, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	name, ok := domain.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(domain)
	}
	path := ""
	if process != nil {
		var ok bool
		path, ok = process.Value().(string)
		if !ok {
			return types.MaybeNoSuchOverloadErr(process)
		}
	}
	profileCache := l.objectCache.ContainerProfileCache()
	if profileCache == nil {
		return cache.NewProfileNotAvailableErr("no container profile cache available")
	}
	cp, state := profileCache.GetContainerProfileSnapshot(id)
	if state == nil || state.Error != nil || state.Status != helpersv1.Completed || state.Completion != helpersv1.Full {
		return cache.NewProfileNotAvailableErr("DNS baseline requires a completed full profile")
	}
	if cp == nil {
		return cache.NewProfileNotAvailableErr("no DNS profile available")
	}
	if cp.DNSBaselineVersion != "v1" || cp.DNSBaselineTruncated {
		return cache.NewProfileNotAvailableErr("DNS baseline unavailable or truncated; relearning required")
	}
	if name == "" {
		return types.Bool(false)
	}
	paths, found := cp.DNSLookups[strings.ToLower(strings.TrimSuffix(name, "."))+"."]
	if process == nil {
		return types.Bool(found)
	}
	if path == "" {
		return cache.NewProfileNotAvailableErr("DNS process identity unavailable")
	}
	_, found = paths[path]
	return types.Bool(found)
}
