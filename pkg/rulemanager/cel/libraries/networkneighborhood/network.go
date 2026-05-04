package networkneighborhood

import (
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
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

	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	if _, ok := cp.EgressAddresses.Values[addressStr]; ok {
		return types.Bool(true)
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

	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	if _, ok := cp.IngressAddresses.Values[addressStr]; ok {
		return types.Bool(true)
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

	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	if _, ok := cp.EgressDomains.Values[domainStr]; ok {
		return types.Bool(true)
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

	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	if _, ok := cp.IngressDomains.Values[domainStr]; ok {
		return types.Bool(true)
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
	// port/protocol projection (AddressPortsByAddr) is out of scope for v1; degrade to address-only matching.
	if _, ok := port.Value().(int64); !ok {
		return types.MaybeNoSuchOverloadErr(port)
	}
	if _, ok := protocol.Value().(string); !ok {
		return types.MaybeNoSuchOverloadErr(protocol)
	}

	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	if _, ok := cp.EgressAddresses.Values[addressStr]; ok {
		return types.Bool(true)
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
	// port/protocol projection (AddressPortsByAddr) is out of scope for v1; degrade to address-only matching.
	if _, ok := port.Value().(int64); !ok {
		return types.MaybeNoSuchOverloadErr(port)
	}
	if _, ok := protocol.Value().(string); !ok {
		return types.MaybeNoSuchOverloadErr(protocol)
	}

	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	if _, ok := cp.IngressAddresses.Values[addressStr]; ok {
		return types.Bool(true)
	}

	return types.Bool(false)
}
