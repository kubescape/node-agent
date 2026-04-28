package applicationprofile

import (
	"net/url"
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/celparse"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilehelper"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
)

// wasEndpointAccessed checks if a specific HTTP endpoint was accessed
func (l *apLibrary) wasEndpointAccessed(containerID, endpoint ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	endpointStr, ok := endpoint.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(endpoint)
	}

	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	for ep := range cp.Endpoints.Values {
		if dynamicpathdetector.CompareDynamic(ep, endpointStr) {
			return types.Bool(true)
		}
	}
	for _, ep := range cp.Endpoints.Patterns {
		if dynamicpathdetector.CompareDynamic(ep, endpointStr) {
			return types.Bool(true)
		}
	}

	return types.Bool(false)
}

// wasEndpointAccessedWithMethod checks if a specific HTTP endpoint was accessed with a specific method
func (l *apLibrary) wasEndpointAccessedWithMethod(containerID, endpoint, method ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	endpointStr, ok := endpoint.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(endpoint)
	}
	if _, ok := method.Value().(string); !ok {
		return types.MaybeNoSuchOverloadErr(method)
	}

	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	// EndpointMethodsByPath is out of scope for v1 — check path membership only.
	for ep := range cp.Endpoints.Values {
		if dynamicpathdetector.CompareDynamic(ep, endpointStr) {
			return types.Bool(true)
		}
	}
	for _, ep := range cp.Endpoints.Patterns {
		if dynamicpathdetector.CompareDynamic(ep, endpointStr) {
			return types.Bool(true)
		}
	}

	return types.Bool(false)
}

// wasEndpointAccessedWithMethods checks if a specific HTTP endpoint was accessed with any of the specified methods
func (l *apLibrary) wasEndpointAccessedWithMethods(containerID, endpoint, methods ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	endpointStr, ok := endpoint.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(endpoint)
	}

	if _, err := celparse.ParseList[string](methods); err != nil {
		return types.NewErr("failed to parse methods: %v", err)
	}

	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	// EndpointMethodsByPath is out of scope for v1 — check path membership only.
	for ep := range cp.Endpoints.Values {
		if dynamicpathdetector.CompareDynamic(ep, endpointStr) {
			return types.Bool(true)
		}
	}
	for _, ep := range cp.Endpoints.Patterns {
		if dynamicpathdetector.CompareDynamic(ep, endpointStr) {
			return types.Bool(true)
		}
	}

	return types.Bool(false)
}

// wasEndpointAccessedWithPrefix checks if any HTTP endpoint with the specified prefix was accessed
func (l *apLibrary) wasEndpointAccessedWithPrefix(containerID, prefix ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	prefixStr, ok := prefix.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(prefix)
	}

	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	if cp.Endpoints.All {
		// All entries retained — scan to check for the prefix.
		for ep := range cp.Endpoints.Values {
			if strings.HasPrefix(ep, prefixStr) {
				return types.Bool(true)
			}
		}
		for _, ep := range cp.Endpoints.Patterns {
			if strings.HasPrefix(ep, prefixStr) {
				return types.Bool(true)
			}
		}
		return types.Bool(false)
	}
	// Projection applied — PrefixHits is authoritative; absent key = undeclared.
	hit, declared := cp.Endpoints.PrefixHits[prefixStr]
	if !declared {
		if l.metrics != nil {
			l.metrics.IncProjectionUndeclaredLiteral("ap.was_endpoint_accessed_with_prefix")
		}
		return types.Bool(false)
	}
	return types.Bool(hit)
}

// wasEndpointAccessedWithSuffix checks if any HTTP endpoint with the specified suffix was accessed
func (l *apLibrary) wasEndpointAccessedWithSuffix(containerID, suffix ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	suffixStr, ok := suffix.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(suffix)
	}

	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	if cp.Endpoints.All {
		// All entries retained — scan to check for the suffix.
		for ep := range cp.Endpoints.Values {
			if strings.HasSuffix(ep, suffixStr) {
				return types.Bool(true)
			}
		}
		for _, ep := range cp.Endpoints.Patterns {
			if strings.HasSuffix(ep, suffixStr) {
				return types.Bool(true)
			}
		}
		return types.Bool(false)
	}
	// Projection applied — SuffixHits is authoritative; absent key = undeclared.
	hit, declared := cp.Endpoints.SuffixHits[suffixStr]
	if !declared {
		if l.metrics != nil {
			l.metrics.IncProjectionUndeclaredLiteral("ap.was_endpoint_accessed_with_suffix")
		}
		return types.Bool(false)
	}
	return types.Bool(hit)
}

// wasHostAccessed checks if a specific host was accessed via HTTP endpoints or network connections
func (l *apLibrary) wasHostAccessed(containerID, host ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	hostStr, ok := host.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(host)
	}

	// Check HTTP endpoints for host access
	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	if !cp.Endpoints.All {
		// Only a subset of endpoints is retained — results may not reflect the full profile.
		logger.L().Debug("was_host_accessed called with Endpoints.All=false; results limited to projected subset",
			helpers.String("containerID", containerIDStr),
			helpers.String("host", hostStr))
	}
	allEndpoints := make([]string, 0, len(cp.Endpoints.Values)+len(cp.Endpoints.Patterns))
	for ep := range cp.Endpoints.Values {
		allEndpoints = append(allEndpoints, ep)
	}
	allEndpoints = append(allEndpoints, cp.Endpoints.Patterns...)

	for _, ep := range allEndpoints {
		// Parse the endpoint URL to extract host
		if parsedURL, err := url.Parse(ep); err == nil && parsedURL.Host != "" {
			if parsedURL.Host == hostStr || parsedURL.Hostname() == hostStr {
				return types.Bool(true)
			}
		}
		// For non-URL endpoints check for a whole-token match so that a short
		// host like "api" does not match path segments like "/v1/api/users".
		if ep == hostStr || strings.HasPrefix(ep, hostStr+"/") || strings.HasPrefix(ep, hostStr+":") {
			return types.Bool(true)
		}
	}

	return types.Bool(false)
}
