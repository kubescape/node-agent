package validators

import (
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/node-agent/pkg/utils"
)

// RegisterAllValidators registers all available profile validators with the factory
func RegisterAllValidators(factory profilevalidator.ProfileValidatorFactory, objectCache objectcache.ObjectCache) {
	// Register exec validator
	execValidator := NewExecProfileValidator(objectCache)
	factory.RegisterProfileValidator(execValidator, utils.ExecveEventType)

	// Register open validator
	openValidator := NewOpenProfileValidator(objectCache)
	factory.RegisterProfileValidator(openValidator, utils.OpenEventType)

	// Register syscall validator
	syscallValidator := NewSyscallProfileValidator(objectCache)
	factory.RegisterProfileValidator(syscallValidator, utils.SyscallEventType)

	// Register capability validator
	capabilityValidator := NewCapabilityProfileValidator(objectCache)
	factory.RegisterProfileValidator(capabilityValidator, utils.CapabilitiesEventType)

	// Register network validator
	networkValidator := NewNetworkProfileValidator(objectCache)
	factory.RegisterProfileValidator(networkValidator, utils.NetworkEventType)

	// Register domain validator
	domainValidator := NewDomainProfileValidator(objectCache)
	factory.RegisterProfileValidator(domainValidator, utils.DnsEventType)
}
