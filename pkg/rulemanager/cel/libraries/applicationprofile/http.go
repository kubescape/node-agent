package applicationprofile

import (
	"net/url"
	"slices"
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
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

	container, err := profilehelper.GetContainerApplicationProfile(l.objectCache, containerIDStr)
	if err != nil {
		return types.Bool(false)
	}

	for _, ep := range container.Endpoints {
		if dynamicpathdetector.CompareDynamic(ep.Endpoint, endpointStr) {
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
	methodStr, ok := method.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(method)
	}

	container, err := profilehelper.GetContainerApplicationProfile(l.objectCache, containerIDStr)
	if err != nil {
		return types.Bool(false)
	}

	for _, ep := range container.Endpoints {
		if dynamicpathdetector.CompareDynamic(ep.Endpoint, endpointStr) {
			if slices.Contains(ep.Methods, methodStr) {
				return types.Bool(true)
			}
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

	celMethods, err := celparse.ParseList[string](methods)
	if err != nil {
		return types.NewErr("failed to parse methods: %v", err)
	}

	container, err := profilehelper.GetContainerApplicationProfile(l.objectCache, containerIDStr)
	if err != nil {
		return types.Bool(false)
	}

	for _, ep := range container.Endpoints {
		if dynamicpathdetector.CompareDynamic(ep.Endpoint, endpointStr) {
			for _, method := range celMethods {
				if slices.Contains(ep.Methods, method) {
					return types.Bool(true)
				}
			}
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

	container, err := profilehelper.GetContainerApplicationProfile(l.objectCache, containerIDStr)
	if err != nil {
		return types.Bool(false)
	}

	for _, ep := range container.Endpoints {
		if strings.HasPrefix(ep.Endpoint, prefixStr) {
			return types.Bool(true)
		}
	}

	return types.Bool(false)
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

	container, err := profilehelper.GetContainerApplicationProfile(l.objectCache, containerIDStr)
	if err != nil {
		return types.Bool(false)
	}

	for _, ep := range container.Endpoints {
		if strings.HasSuffix(ep.Endpoint, suffixStr) {
			return types.Bool(true)
		}
	}

	return types.Bool(false)
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
	container, err := profilehelper.GetContainerApplicationProfile(l.objectCache, containerIDStr)
	if err == nil {
		for _, ep := range container.Endpoints {
			// Parse the endpoint URL to extract host
			if parsedURL, err := url.Parse(ep.Endpoint); err == nil && parsedURL.Host != "" {
				if parsedURL.Host == hostStr || parsedURL.Hostname() == hostStr {
					return types.Bool(true)
				}
			}
			// Also check if the endpoint contains the host as a substring (for cases where it's not a full URL)
			if strings.Contains(ep.Endpoint, hostStr) {
				return types.Bool(true)
			}
		}
	}
	return types.Bool(false)
}
