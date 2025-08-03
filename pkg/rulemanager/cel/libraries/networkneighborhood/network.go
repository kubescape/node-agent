package networkneighborhood

import (
	"slices"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilehelper"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
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

func (l *nnLibrary) wasAddressPortProtocolInEgress(containerID, address, port, protocol ref.Val) ref.Val {
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
	portInt, ok := port.Value().(int64)
	if !ok {
		return types.MaybeNoSuchOverloadErr(port)
	}
	protocolStr, ok := protocol.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(protocol)
	}

	container, err := profilehelper.GetContainerNetworkNeighborhood(l.objectCache, containerIDStr)
	if err != nil {
		return types.Bool(false)
	}

	for _, egress := range container.Egress {
		if egress.IPAddress == addressStr {
			for _, portInfo := range egress.Ports {
				if portInfo.Protocol == v1beta1.Protocol(protocolStr) && portInfo.Port != nil && *portInfo.Port == int32(portInt) {
					return types.Bool(true)
				}
			}
		}
	}

	return types.Bool(false)
}

func (l *nnLibrary) wasAddressPortProtocolInIngress(containerID, address, port, protocol ref.Val) ref.Val {
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
	portInt, ok := port.Value().(int64)
	if !ok {
		return types.MaybeNoSuchOverloadErr(port)
	}
	protocolStr, ok := protocol.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(protocol)
	}

	container, err := profilehelper.GetContainerNetworkNeighborhood(l.objectCache, containerIDStr)
	if err != nil {
		return types.Bool(false)
	}

	for _, ingress := range container.Ingress {
		if ingress.IPAddress == addressStr {
			for _, portInfo := range ingress.Ports {
				if portInfo.Protocol == v1beta1.Protocol(protocolStr) && portInfo.Port != nil && *portInfo.Port == int32(portInt) {
					return types.Bool(true)
				}
			}
		}
	}

	return types.Bool(false)
}
