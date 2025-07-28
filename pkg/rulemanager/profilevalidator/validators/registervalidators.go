package validators

import (
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
)

// RegisterAllValidators registers all available profile validators with the factory
func RegisterAllValidators(factory profilevalidator.ProfileValidatorFactory, objectCache objectcache.ObjectCache) {
	// Register exec validator
	execValidator := NewExecProfileValidator(objectCache)
	factory.RegisterProfileValidator(execValidator, execValidator.GetRequiredEventType())

	// Register open validator
	openValidator := NewOpenProfileValidator(objectCache)
	factory.RegisterProfileValidator(openValidator, openValidator.GetRequiredEventType())

	// Register syscall validator
	syscallValidator := NewSyscallProfileValidator(objectCache)
	factory.RegisterProfileValidator(syscallValidator, syscallValidator.GetRequiredEventType())

	// Register capability validator
	capabilityValidator := NewCapabilityProfileValidator(objectCache)
	factory.RegisterProfileValidator(capabilityValidator, capabilityValidator.GetRequiredEventType())

	// Register network validator
	networkValidator := NewNetworkProfileValidator(objectCache)
	factory.RegisterProfileValidator(networkValidator, networkValidator.GetRequiredEventType())

	// Register domain validator
	domainValidator := NewDomainProfileValidator(objectCache)
	factory.RegisterProfileValidator(domainValidator, domainValidator.GetRequiredEventType())
}
