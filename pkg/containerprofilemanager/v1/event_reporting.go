package containerprofilemanager

import (
	"errors"
	"reflect"
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

// ReportCapability reports a capability event for a container
func (cpm *ContainerProfileManager) ReportCapability(containerID, capability string) {
	err := cpm.withContainer(containerID, func(data *containerData) error {
		if data.capabilites == nil {
			data.capabilites = mapset.NewSet[string]()
		}
		if !data.capabilites.Contains(capability) {
			data.capabilites.Add(capability)
		}
		return nil
	})

	cpm.logEventError(err, "capability", containerID)
}

// ReportFileExec reports a file execution event for a container
func (cpm *ContainerProfileManager) ReportFileExec(containerID string, event events.ExecEvent) {
	err := cpm.withContainer(containerID, func(data *containerData) error {
		if data.execs == nil {
			data.execs = &maps.SafeMap[string, []string]{}
		}

		path := event.Comm
		if len(event.Args) > 0 {
			path = event.Args[0]
		}

		// Use SHA256 hash of the exec to identify it uniquely
		execIdentifier := utils.CalculateSHA256FileExecHash(path, event.Args)
		if cpm.enricher != nil {
			go cpm.enricher.EnrichEvent(containerID, &event, execIdentifier)
		}

		data.execs.Set(execIdentifier, append([]string{path}, event.Args...))
		return nil
	})

	cpm.logEventError(err, "file exec", containerID)
}

// ReportFileOpen reports a file open event for a container
func (cpm *ContainerProfileManager) ReportFileOpen(containerID string, event events.OpenEvent) {
	err := cpm.withContainer(containerID, func(data *containerData) error {
		if data.opens == nil {
			data.opens = &maps.SafeMap[string, mapset.Set[string]]{}
		}

		// Deduplicate /proc/1234/* into /proc/.../*
		path := event.Path
		if strings.HasPrefix(path, "/proc/") {
			path = procRegex.ReplaceAllString(path, "/proc/"+dynamicpathdetector.DynamicIdentifier)
		}

		isSensitive := utils.IsSensitivePath(path, ruleengine.SensitiveFiles)
		if cpm.enricher != nil && isSensitive {
			openIdentifier := utils.CalculateSHA256FileOpenHash(path)
			go cpm.enricher.EnrichEvent(containerID, &event, openIdentifier)
		}

		// Check if we already have this open with these flags
		if opens, ok := data.opens.Load(path); ok && opens.Contains(event.Flags...) {
			return nil
		}

		// Add to open map
		if opens, ok := data.opens.Load(path); ok {
			opens.Append(event.Flags...)
		} else {
			data.opens.Set(path, mapset.NewSet[string](event.Flags...))
		}

		return nil
	})

	cpm.logEventError(err, "file open", containerID)
}

// ReportSymlinkEvent reports a symlink creation event for a container
func (cpm *ContainerProfileManager) ReportSymlinkEvent(containerID string, event *tracersymlinktype.Event) {
	err := cpm.withContainer(containerID, func(data *containerData) error {
		if cpm.enricher != nil {
			symlinkIdentifier := utils.CalculateSHA256FileOpenHash(event.OldPath + event.NewPath)
			go cpm.enricher.EnrichEvent(containerID, event, symlinkIdentifier)
		}
		return nil
	})

	cpm.logEventError(err, "symlink", containerID)
}

// ReportHardlinkEvent reports a hardlink creation event for a container
func (cpm *ContainerProfileManager) ReportHardlinkEvent(containerID string, event *tracerhardlinktype.Event) {
	err := cpm.withContainer(containerID, func(data *containerData) error {
		if cpm.enricher != nil {
			hardlinkIdentifier := utils.CalculateSHA256FileOpenHash(event.OldPath + event.NewPath)
			go cpm.enricher.EnrichEvent(containerID, event, hardlinkIdentifier)
		}
		return nil
	})

	cpm.logEventError(err, "hardlink", containerID)
}

// ReportHTTPEvent reports an HTTP event for a container
func (cpm *ContainerProfileManager) ReportHTTPEvent(containerID string, event *tracerhttptype.Event) {
	err := cpm.withContainer(containerID, func(data *containerData) error {
		if event.Response == nil {
			logger.L().Debug("HTTP event without response", helpers.String("containerID", containerID))
			return nil
		}

		if data.endpoints == nil {
			data.endpoints = &maps.SafeMap[string, *v1beta1.HTTPEndpoint]{}
		}

		endpointIdentifier, err := GetEndpointIdentifier(event)
		if err != nil {
			logger.L().Warning("failed to get endpoint identifier", helpers.Error(err))
			return nil
		}

		endpoint, err := GetNewEndpoint(event, endpointIdentifier)
		if err != nil {
			logger.L().Warning("failed to get new endpoint", helpers.Error(err))
			return nil
		}

		// Check if we already have this endpoint
		endpointHash := CalculateHTTPEndpointHash(endpoint)
		if data.endpoints.Has(endpointHash) {
			return nil
		}

		// Add to endpoint map
		data.endpoints.Set(endpointHash, endpoint)
		return nil
	})

	cpm.logEventError(err, "http", containerID)
}

// ReportRulePolicy reports a rule policy for a container
func (cpm *ContainerProfileManager) ReportRulePolicy(containerID, ruleId, allowedProcess string, allowedContainer bool) {
	err := cpm.withContainer(containerID, func(data *containerData) error {
		if data.rulePolicies == nil {
			data.rulePolicies = &maps.SafeMap[string, *v1beta1.RulePolicy]{}
		}

		newPolicy := &v1beta1.RulePolicy{
			AllowedContainer: allowedContainer,
			AllowedProcesses: []string{allowedProcess},
		}

		existingPolicy, hasExisting := data.rulePolicies.Load(ruleId)
		if hasExisting && IsPolicyIncluded(existingPolicy, newPolicy) {
			return nil
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

		data.rulePolicies.Set(ruleId, finalPolicy)
		return nil
	})

	cpm.logEventError(err, "rule policy", containerID)
}

// ReportIdentifiedCallStack reports a call stack for a container
func (cpm *ContainerProfileManager) ReportIdentifiedCallStack(containerID string, callStack *v1beta1.IdentifiedCallStack) {
	err := cpm.withContainer(containerID, func(data *containerData) error {
		if data.callStacks == nil {
			data.callStacks = &maps.SafeMap[string, *v1beta1.IdentifiedCallStack]{}
		}

		// Generate unique identifier for the call stack
		callStackIdentifier := CalculateSHA256CallStackHash(*callStack)

		// Check if we already have this call stack
		if data.callStacks.Has(callStackIdentifier) {
			return nil
		}

		// Add to call stacks map
		data.callStacks.Set(callStackIdentifier, callStack)
		return nil
	})

	cpm.logEventError(err, "callstack", containerID)
}

// ReportNetworkEvent reports a network event for a container
func (cpm *ContainerProfileManager) ReportNetworkEvent(containerID string, event *tracernetworktype.Event) {
	if !cpm.isValidNetworkEvent(event) {
		return
	}

	err := cpm.withContainer(containerID, func(data *containerData) error {
		if data.networks == nil {
			data.networks = mapset.NewSet[NetworkEvent]()
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

		// Skip if we already saved this event
		if !data.networks.Contains(networkEvent) {
			data.networks.Add(networkEvent)
		}

		return nil
	})

	cpm.logEventError(err, "network", containerID)
}

// ReportDroppedEvent reports a dropped event (currently just logs)
func (cpm *ContainerProfileManager) ReportDroppedEvent(containerID string) {
	err := cpm.withContainer(containerID, func(data *containerData) error {
		data.droppedEvents = true
		return nil
	})
	if err != nil && !errors.Is(err, ErrContainerNotFound) {
		logger.L().Error("failed to report dropped event",
			helpers.String("containerID", containerID),
			helpers.Error(err))
		return
	}
	logger.L().Debug("dropped event reported", helpers.String("containerID", containerID))
}

// PeekSyscalls returns the syscalls for the given mount namespace ID
// Note: This function should be called with a lock held on the container data
func (cpm *ContainerProfileManager) PeekSyscalls(data *containerData) ([]string, error) {
	var syscalls []string

	if cpm.syscallPeekFunc == nil {
		return nil, errors.New("syscall peek function is not set")
	}

	peekedSyscalls, err := cpm.syscallPeekFunc(data.watchedContainerData.NsMntId)
	if err != nil {
		return nil, err
	}

	if data.syscalls == nil {
		data.syscalls = mapset.NewSet[string]()
	}

	// Get only new syscalls
	syscallsSet := mapset.NewSet[string](peekedSyscalls...)
	newSyscalls := syscallsSet.Difference(data.syscalls)
	syscalls = newSyscalls.ToSlice()

	// Store all syscalls in container data
	data.syscalls.Append(syscalls...)

	return syscalls, err
}

// isValidNetworkEvent checks if the network event is valid for processing
func (cpm *ContainerProfileManager) isValidNetworkEvent(event *tracernetworktype.Event) bool {
	// Unknown type, shouldn't happen
	if event.PktType != HostPktType && event.PktType != OutgoingPktType {
		logger.L().Debug("pktType is not HOST or OUTGOING", helpers.Interface("event", event))
		return false
	}

	// Ignore localhost
	if event.PktType == HostPktType && event.PodHostIP == event.DstEndpoint.Addr {
		return false
	}

	// Ignore host netns
	if event.K8s.HostNetwork {
		return false
	}

	return true
}

func (cpm *ContainerProfileManager) reportInitialPolicies(containerID string) {
	policies := cpm.getRulePolicies()

	err := cpm.withContainer(containerID, func(data *containerData) error {
		if data.rulePolicies == nil {
			data.rulePolicies = &maps.SafeMap[string, *v1beta1.RulePolicy]{}
		}

		for id, policy := range policies {
			data.rulePolicies.Set(id, &policy)
		}
		return nil
	})

	cpm.logEventError(err, "initial policies", containerID)
}

// getRulePolicies returns a map of rule policies based on the rule cache
func (cpm *ContainerProfileManager) getRulePolicies() map[string]v1beta1.RulePolicy {
	operations := make(map[string]v1beta1.RulePolicy)

	if reflect.ValueOf(cpm.ruleBindingCache).IsNil() {
		return operations
	}

	ids := cpm.ruleBindingCache.GetRuleCreator().GetAllRuleIDs()
	for _, id := range ids {
		operations[id] = v1beta1.RulePolicy{
			AllowedContainer: false,
			AllowedProcesses: []string{},
		}
	}

	return operations
}

// logEventError provides consistent error logging for event reporting
func (cpm *ContainerProfileManager) logEventError(err error, eventType, containerID string) {
	if err != nil && !errors.Is(err, ErrContainerNotFound) {
		logger.L().Error("failed to report "+eventType+" event",
			helpers.String("containerID", containerID),
			helpers.Error(err))
	}
}
