package containerprofilemanager

import (
	"errors"
	"regexp"
	"slices"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerhardlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/types"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	tracersymlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/types"
	"github.com/kubescape/node-agent/pkg/ruleengine/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
)

var procRegex = regexp.MustCompile(`^/proc/\d+`)

func (cpm *ContainerProfileManager) RegisterPeekFunc(peek func(mntns uint64) ([]string, error)) {
	cpm.syscallPeekFunc = peek
}

func (cpm *ContainerProfileManager) ReportCapability(containerID, capability string) {
	err := cpm.containerLocks.WithLockAndError(containerID, func() error {
		if containerData, ok := cpm.containerIDToInfo.Load(containerID); ok {
			if containerData.capabilites == nil {
				containerData.capabilites = mapset.NewSet[string]()
			}
			if !containerData.capabilites.Contains(capability) {
				containerData.capabilites.Add(capability)
			}
			return nil
		}

		return ErrContainerNotFound
	},
	)

	if err != nil {
		if !errors.Is(err, ErrContainerNotFound) {
			logger.L().Error("ContainerProfileManager - failed to report capability event", helpers.String("container ID", containerID), helpers.Error(err))
		} else {
			cpm.containerLocks.ReleaseLock(containerID)
		}
	}
}

func (cpm *ContainerProfileManager) ReportFileExec(containerID string, event events.ExecEvent) {
	err := cpm.containerLocks.WithLockAndError(containerID, func() error {
		if containerData, ok := cpm.containerIDToInfo.Load(containerID); ok {
			if containerData.execs == nil {
				containerData.execs = &maps.SafeMap[string, []string]{}
			}

			path := event.Comm
			if len(event.Args) > 0 {
				path = event.Args[0]
			}

			// we use a SHA256 hash of the exec to identify it uniquely (path + args, in the order they were provided)
			execIdentifier := utils.CalculateSHA256FileExecHash(path, event.Args)
			if cpm.enricher != nil {
				go cpm.enricher.EnrichEvent(containerID, &event, execIdentifier)
			}

			containerData.execs.Set(execIdentifier, append([]string{path}, event.Args...))

			return nil
		}
		return ErrContainerNotFound
	},
	)

	if err != nil {
		if !errors.Is(err, ErrContainerNotFound) {
			logger.L().Error("ContainerProfileManager - failed to report file exec event", helpers.String("container ID", containerID), helpers.Error(err))
		} else {
			cpm.containerLocks.ReleaseLock(containerID)
		}
	}
}

func (cpm *ContainerProfileManager) ReportFileOpen(containerID string, event events.OpenEvent) {
	err := cpm.containerLocks.WithLockAndError(containerID, func() error {
		if containerData, ok := cpm.containerIDToInfo.Load(containerID); ok {
			if containerData.opens == nil {
				containerData.opens = &maps.SafeMap[string, mapset.Set[string]]{}
			}

			// deduplicate /proc/1234/* into /proc/.../* (quite a common case)
			// we perform it here instead of waiting for compression
			path := event.Path
			if strings.HasPrefix(path, "/proc/") {
				path = procRegex.ReplaceAllString(path, "/proc/"+dynamicpathdetector.DynamicIdentifier)
			}

			isSensitive := utils.IsSensitivePath(path, ruleengine.SensitiveFiles)

			if cpm.enricher != nil && isSensitive {
				openIdentifier := utils.CalculateSHA256FileOpenHash(path)
				go cpm.enricher.EnrichEvent(containerID, &event, openIdentifier)
			}

			// Check if we already have this open
			if opens, ok := containerData.opens.Load(path); ok && opens.Contains(event.Flags...) {
				return nil
			}
			// Add to open map
			if opens, ok := containerData.opens.Load(path); ok {
				opens.Append(event.Flags...)
			} else {
				containerData.opens.Set(path, mapset.NewSet[string](event.Flags...))
			}

			return nil
		}
		return ErrContainerNotFound
	})

	if err != nil {
		if !errors.Is(err, ErrContainerNotFound) {
			logger.L().Error("ContainerProfileManager - failed to report file open event", helpers.String("container ID", containerID), helpers.Error(err))
		} else {
			cpm.containerLocks.ReleaseLock(containerID)
		}
	}
}

func (cpm *ContainerProfileManager) ReportSymlinkEvent(containerID string, event *tracersymlinktype.Event) {
	err := cpm.containerLocks.WithLockAndError(containerID, func() error {
		if _, ok := cpm.containerIDToInfo.Load(containerID); ok {
			if cpm.enricher != nil {
				symlinkIdentifier := utils.CalculateSHA256FileOpenHash(event.OldPath + event.NewPath)
				go cpm.enricher.EnrichEvent(containerID, event, symlinkIdentifier)
			}
			return nil
		}
		return ErrContainerNotFound
	})

	if err != nil {
		if !errors.Is(err, ErrContainerNotFound) {
			logger.L().Error("ContainerProfileManager - failed to report symlink event", helpers.String("container ID", containerID), helpers.Error(err))
		} else {
			cpm.containerLocks.ReleaseLock(containerID)
		}
	}
}

func (cpm *ContainerProfileManager) ReportHardlinkEvent(containerID string, event *tracerhardlinktype.Event) {
	err := cpm.containerLocks.WithLockAndError(containerID, func() error {
		if _, ok := cpm.containerIDToInfo.Load(containerID); ok {
			if cpm.enricher != nil {
				hardlinkIdentifier := utils.CalculateSHA256FileOpenHash(event.OldPath + event.NewPath)
				go cpm.enricher.EnrichEvent(containerID, event, hardlinkIdentifier)
			}
			return nil
		}
		return ErrContainerNotFound
	})

	if err != nil {
		if !errors.Is(err, ErrContainerNotFound) {
			logger.L().Error("ContainerProfileManager - failed to report hardlink event", helpers.String("container ID", containerID), helpers.Error(err))
		} else {
			cpm.containerLocks.ReleaseLock(containerID)
		}
	}
}

func (cpm *ContainerProfileManager) ReportDroppedEvent(containerID string) {
	// TODO: what to do with this? just log it?
}

func (cpm *ContainerProfileManager) ReportHTTPEvent(containerID string, event *tracerhttptype.Event) {
	err := cpm.containerLocks.WithLockAndError(containerID, func() error {
		if containerData, ok := cpm.containerIDToInfo.Load(containerID); ok {
			if event.Response == nil {
				logger.L().Debug("ContainerProfileManager - HTTP event without response", helpers.String("container ID", containerID))
				return nil
			}

			if containerData.endpoints == nil {
				containerData.endpoints = &maps.SafeMap[string, *v1beta1.HTTPEndpoint]{}
			}

			endpointIdentifier, err := GetEndpointIdentifier(event)
			if err != nil {
				logger.L().Warning("ContainerProfileManager - failed to get endpoint identifier", helpers.Error(err))
				return nil
			}
			endpoint, err := GetNewEndpoint(event, endpointIdentifier)
			if err != nil {
				logger.L().Warning("ContainerProfileManager - failed to get new endpoint", helpers.Error(err))
				return nil
			}
			// check if we already have this endpoint
			endpointHash := CalculateHTTPEndpointHash(endpoint)
			if containerData.endpoints.Has(endpointHash) {
				return nil
			}
			// add to endpoint map
			containerData.endpoints.Set(endpointHash, endpoint)
			return nil
		}
		return ErrContainerNotFound
	})

	if err != nil {
		if !errors.Is(err, ErrContainerNotFound) {
			logger.L().Error("ContainerProfileManager - failed to report http event", helpers.String("container ID", containerID), helpers.Error(err))
		} else {
			cpm.containerLocks.ReleaseLock(containerID)
		}
	}
}

func (cpm *ContainerProfileManager) ReportRulePolicy(containerID, ruleId, allowedProcess string, allowedContainer bool) { // TODO: do we need to do the initial operation as in the old manager?
	err := cpm.containerLocks.WithLockAndError(containerID, func() error {
		if containerData, ok := cpm.containerIDToInfo.Load(containerID); ok {
			if containerData.rulePolicies == nil {
				containerData.rulePolicies = &maps.SafeMap[string, *v1beta1.RulePolicy]{}
			}

			newPolicy := &v1beta1.RulePolicy{
				AllowedContainer: allowedContainer,
				AllowedProcesses: []string{allowedProcess},
			}

			existingPolicy, hasExisting := containerData.rulePolicies.Load(ruleId)
			if hasExisting {
				if IsPolicyIncluded(existingPolicy, newPolicy) {
					return nil
				}
			}

			var finalPolicy *v1beta1.RulePolicy
			if hasExisting {
				finalPolicy = existingPolicy
				if allowedContainer {
					finalPolicy.AllowedContainer = true
				}
				if allowedProcess != "" && !slices.Contains(finalPolicy.AllowedProcesses, allowedProcess) {
					finalPolicy.AllowedProcesses = append(finalPolicy.AllowedProcesses, allowedProcess)
				}
			} else {
				finalPolicy = newPolicy
			}

			containerData.rulePolicies.Set(ruleId, finalPolicy)
			return nil
		}
		return ErrContainerNotFound
	})

	if err != nil {
		if !errors.Is(err, ErrContainerNotFound) {
			logger.L().Error("ContainerProfileManager - failed to report rule policy", helpers.String("container ID", containerID), helpers.Error(err))
		} else {
			cpm.containerLocks.ReleaseLock(containerID)
		}
	}
}

func (cpm *ContainerProfileManager) ReportIdentifiedCallStack(containerID string, callStack *v1beta1.IdentifiedCallStack) {
	err := cpm.containerLocks.WithLockAndError(containerID, func() error {
		if containerData, ok := cpm.containerIDToInfo.Load(containerID); ok {
			if containerData.callStacks == nil {
				containerData.callStacks = &maps.SafeMap[string, *v1beta1.IdentifiedCallStack]{}
			}

			// Generate unique identifier for the call stack
			callStackIdentifier := CalculateSHA256CallStackHash(*callStack)

			// Check if we already have this call stack
			if containerData.callStacks.Has(callStackIdentifier) {
				return nil
			}

			// Add to call stacks map
			containerData.callStacks.Set(callStackIdentifier, callStack)
			return nil
		}
		return ErrContainerNotFound
	})

	if err != nil {
		if !errors.Is(err, ErrContainerNotFound) {
			logger.L().Error("ContainerProfileManager - failed to report callstack", helpers.String("container ID", containerID), helpers.Error(err))
		} else {
			cpm.containerLocks.ReleaseLock(containerID)
		}
	}
}

func (cpm *ContainerProfileManager) ReportNetworkEvent(containerID string, event *tracernetworktype.Event) {
	err := cpm.containerLocks.WithLockAndError(containerID, func() error {
		if containerData, ok := cpm.containerIDToInfo.Load(containerID); ok {
			if !cpm.isValidNetworkEvent(event) {
				return nil
			}

			if containerData.networks == nil {
				containerData.networks = mapset.NewSet[NetworkEvent]()
			}

			networkEvent := NetworkEvent{
				Port:     event.Port,
				Protocol: event.Proto,
				PktType:  event.PktType,
				Destination: Destination{
					Namespace: event.DstEndpoint.Namespace,
					Name:      event.DstEndpoint.Name,
					Kind:      EndpointKind(event.DstEndpoint.Kind),
					IPAddress: event.DstEndpoint.Addr,
				},
			}
			networkEvent.SetPodLabels(event.PodLabels)
			networkEvent.SetDestinationPodLabels(event.DstEndpoint.PodLabels)

			// skip if we already saved this event
			if containerData.networks.Contains(networkEvent) {
				return nil
			}
			containerData.networks.Add(networkEvent)
			return nil
		}
		return ErrContainerNotFound
	})

	if err != nil {
		if !errors.Is(err, ErrContainerNotFound) {
			logger.L().Error("ContainerProfileManager - failed to report network event", helpers.String("container ID", containerID), helpers.Error(err))
		} else {
			cpm.containerLocks.ReleaseLock(containerID)
		}
	}
}

// isValidNetworkEvent checks if the network event is valid for processing.
func (cpm *ContainerProfileManager) isValidNetworkEvent(event *tracernetworktype.Event) bool {
	// unknown type, shouldn't happen
	if event.PktType != HostPktType && event.PktType != OutgoingPktType {
		logger.L().Debug("NetworkManager - pktType is not HOST or OUTGOING", helpers.Interface("event", event))
		return false
	}

	// ignore localhost
	if event.PktType == HostPktType && event.PodHostIP == event.DstEndpoint.Addr {
		return false
	}

	// ignore host netns
	if event.K8s.HostNetwork {
		return false
	}

	return true
}

// PeekSyscalls returns the syscalls for the given mount namespace ID.
func (cpm *ContainerProfileManager) PeekSyscalls(containerID string, nsMountId uint64) ([]string, error) {
	syscalls := []string{}
	var err error

	err = cpm.containerLocks.WithLockAndError(containerID, func() error {
		if containerData, ok := cpm.containerIDToInfo.Load(containerID); ok {
			if cpm.syscallPeekFunc == nil {
				return errors.New("syscall peek function is not set")
			}

			if syscalls, err = cpm.syscallPeekFunc(nsMountId); err != nil {
				logger.L().Error("ContainerProfileManager - failed to peek syscalls", helpers.String("container ID", containerID), helpers.Error(err))
				return err
			}

			if containerData.syscalls == nil {
				containerData.syscalls = mapset.NewSet[string]()
			} else {
				syscallsSet := mapset.NewSet[string](syscalls...)
				syscalls = syscallsSet.Difference(containerData.syscalls).ToSlice()
			}

			// Store the syscalls in the container data
			containerData.syscalls.Append(syscalls...)
			return nil
		}
		return ErrContainerNotFound
	},
	)
	if err != nil {
		if !errors.Is(err, ErrContainerNotFound) {
			logger.L().Error("ContainerProfileManager - failed to report capability", helpers.String("container ID", containerID), helpers.Error(err))
		} else {
			cpm.containerLocks.ReleaseLock(containerID)
		}
	}

	return syscalls, nil
}
