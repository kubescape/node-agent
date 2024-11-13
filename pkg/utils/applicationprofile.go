package utils

import (
	"fmt"
	"sort"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func CreateCapabilitiesPatchOperations(capabilities, syscalls []string, execs map[string][]string, opens map[string]mapset.Set[string], endpoints map[string]*v1beta1.HTTPEndpoint, containerType string, containerIndex int) []PatchOperation {
	var profileOperations []PatchOperation
	// add capabilities
	sort.Strings(capabilities)
	capabilitiesPath := fmt.Sprintf("/spec/%s/%d/capabilities/-", containerType, containerIndex)
	for _, capability := range capabilities {
		profileOperations = append(profileOperations, PatchOperation{
			Op:    "add",
			Path:  capabilitiesPath,
			Value: capability,
		})
	}
	// add syscalls
	sort.Strings(syscalls)
	sysCallsPath := fmt.Sprintf("/spec/%s/%d/syscalls/-", containerType, containerIndex)
	for _, syscall := range syscalls {
		profileOperations = append(profileOperations, PatchOperation{
			Op:    "add",
			Path:  sysCallsPath,
			Value: syscall,
		})
	}

	// add execs
	execsPath := fmt.Sprintf("/spec/%s/%d/execs/-", containerType, containerIndex)
	for _, pathAndArgs := range execs {
		path := pathAndArgs[0]
		var args []string
		if len(pathAndArgs) > 1 {
			args = pathAndArgs[1:]
		}
		profileOperations = append(profileOperations, PatchOperation{
			Op:   "add",
			Path: execsPath,
			Value: v1beta1.ExecCalls{
				Path: path,
				Args: args,
			},
		})
	}
	// add opens
	opensPath := fmt.Sprintf("/spec/%s/%d/opens/-", containerType, containerIndex)
	for path, open := range opens {
		flags := open.ToSlice()
		sort.Strings(flags)

		profileOperations = append(profileOperations, PatchOperation{
			Op:   "add",
			Path: opensPath,
			Value: v1beta1.OpenCalls{
				Path:  path,
				Flags: flags,
			},
		})
	}

	httpEndpoints := fmt.Sprintf("/spec/%s/%d/endpoints/-", containerType, containerIndex)
	for _, endpoint := range endpoints {
		profileOperations = append(profileOperations, PatchOperation{
			Op:    "add",
			Path:  httpEndpoints,
			Value: *endpoint,
		})
	}

	return profileOperations
}

func EnrichApplicationProfileContainer(container *v1beta1.ApplicationProfileContainer, observedCapabilities, observedSyscalls []string, execs map[string][]string, opens map[string]mapset.Set[string], endpoints map[string]*v1beta1.HTTPEndpoint) {
	// add capabilities
	caps := mapset.NewSet(observedCapabilities...)
	caps.Append(container.Capabilities...)
	container.Capabilities = caps.ToSlice()
	sort.Strings(container.Capabilities)

	// add syscalls
	syscalls := mapset.NewSet(observedSyscalls...)
	syscalls.Append(container.Syscalls...)
	container.Syscalls = syscalls.ToSlice()
	sort.Strings(container.Syscalls)

	// add execs
	for _, pathAndArgs := range execs {
		path := pathAndArgs[0]
		var args []string
		if len(pathAndArgs) > 1 {
			args = pathAndArgs[1:]
		}
		container.Execs = append(container.Execs, v1beta1.ExecCalls{
			Path: path,
			Args: args,
		})
	}
	// add opens
	for path, open := range opens {
		flags := open.ToSlice()
		sort.Strings(flags)
		container.Opens = append(container.Opens, v1beta1.OpenCalls{
			Path:  path,
			Flags: flags,
		})
	}

	// add endpoints
	for _, endpoint := range endpoints {
		container.Endpoints = append(container.Endpoints, *endpoint)
	}
}

// TODO make generic?
func GetApplicationProfileContainer(object *v1beta1.ApplicationProfile, containerType ContainerType, containerIndex int) *v1beta1.ApplicationProfileContainer {
	if object == nil {
		return nil
	}
	switch containerType {
	case Container:
		if len(object.Spec.Containers) > containerIndex {
			return &object.Spec.Containers[containerIndex]
		}
	case InitContainer:
		if len(object.Spec.InitContainers) > containerIndex {
			return &object.Spec.InitContainers[containerIndex]
		}
	case EphemeralContainer:
		if len(object.Spec.EphemeralContainers) > containerIndex {
			return &object.Spec.EphemeralContainers[containerIndex]
		}
	}
	return nil
}
