package networkneighborhood

import (
	"slices"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilehelper"
)

func (l *nnLibrary) wasAddressInEgress(containerID, address ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	addressStr, ok := address.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(address)
	}

	container, err := profilehelper.GetContainerNetworkNeighborhood(l.objectCache, containerIDStr)
	if err != nil {
		return types.Bool(false)
	}

	for _, egress := range container.Egress {
		if egress.IPAddress == addressStr {
			return types.Bool(true)
		}
	}

	return types.Bool(false)
}

func (l *nnLibrary) wasAddressInIngress(containerID, address ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	addressStr, ok := address.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(address)
	}

	container, err := profilehelper.GetContainerNetworkNeighborhood(l.objectCache, containerIDStr)
	if err != nil {
		return types.Bool(false)
	}

	for _, ingress := range container.Ingress {
		if ingress.IPAddress == addressStr {
			return types.Bool(true)
		}
	}

	return types.Bool(false)
}

func (l *nnLibrary) isDomainInEgress(containerID, domain ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	domainStr, ok := domain.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(domain)
	}

	container, err := profilehelper.GetContainerNetworkNeighborhood(l.objectCache, containerIDStr)
	if err != nil {
		return types.Bool(false)
	}

	for _, egress := range container.Egress {
		if slices.Contains(egress.DNSNames, domainStr) || egress.DNS == domainStr {
			return types.Bool(true)
		}
	}

	return types.Bool(false)
}

func (l *nnLibrary) isDomainInIngress(containerID, domain ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	domainStr, ok := domain.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(domain)
	}

	container, err := profilehelper.GetContainerNetworkNeighborhood(l.objectCache, containerIDStr)
	if err != nil {
		return types.Bool(false)
	}

	for _, ingress := range container.Ingress {
		if slices.Contains(ingress.DNSNames, domainStr) {
			return types.Bool(true)
		}
	}

	return types.Bool(false)
}
