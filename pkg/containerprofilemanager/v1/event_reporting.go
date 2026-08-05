package containerprofilemanager

import (
	"crypto/sha256"
	"errors"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/DmitriyVTitov/size"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

var procRegex = regexp.MustCompile(`^/proc/\d+`)

// networkNeighborExpansionEstimate is the number of bytes a NetworkEvent gains when
// createNetworkNeighbor() (container_data.go) turns it into a v1beta1.NetworkNeighbor at
// serialization time. None of these fields exist on the raw event, and none can be computed
// exactly at report time since DNS resolution and the Service selector lookup are deferred
// to serialization, so each is sized at its documented worst case instead of guessed:
//
//   - Identifier: hex.EncodeToString of a sha256 sum, always exactly 2*sha256.Size bytes.
//   - Type: the longer of "internal"/"external".
//   - Ports: createNetworkNeighbor always appends exactly one NetworkPort entry.
//   - DNS/DNSNames: the longest legal DNS name (RFC 1035 §3.1: 253 bytes), stored once in
//     DNS and again in DNSNames - previously undercounted entirely (253*2 alone exceeds the
//     old flat 256-byte guess this replaces).
//   - NamespaceSelector: getNamespaceMatchLabels always produces exactly one entry keyed
//     "kubernetes.io/metadata.name", valued with a namespace name (DNS-1123 label, RFC 1123:
//     63 bytes max) - this bound is exact, not assumed.
//   - PodSelector: filterLabels forwards whatever label set the destination pod has. Core
//     Kubernetes caps a label's key (253 bytes, optional DNS-subdomain prefix + "/" + 63-byte
//     name) and value (63 bytes) but not the number of labels on an object, so no fixed bound
//     is exact here. maxBudgetedPodLabels labels at that per-label maximum is budgeted as a
//     documented, deliberately generous headroom for typical (e.g. Helm-templated) workloads;
//     a pod with more labels than that could still push a profile past MaxTsProfileSize before
//     this estimator catches it, in which case the queue-level split from #866 is the backstop.
//
// A single event never produces DNS and both selectors at once (createNetworkNeighbor takes
// one branch per Destination.Kind), so summing every component here is deliberately
// conservative on top of the already-generous per-field bounds.
var networkNeighborExpansionEstimate = computeNetworkNeighborExpansionEstimate()

const maxBudgetedPodLabels = 12

func computeNetworkNeighborExpansionEstimate() int {
	identifier := strings.Repeat("f", sha256.Size*2)
	maxDNSName := strings.Repeat("a", 253)
	maxLabelKey := strings.Repeat("k", 253)
	maxLabelValue := strings.Repeat("v", 63)

	ports := []v1beta1.NetworkPort{{
		Name:     "protocol-65535",
		Protocol: v1beta1.ProtocolTCP,
		Port:     ptr.To(int32(65535)),
	}}

	namespaceSelector := &metav1.LabelSelector{
		MatchLabels: map[string]string{"kubernetes.io/metadata.name": maxLabelValue},
	}

	podLabels := make(map[string]string, maxBudgetedPodLabels)
	for i := 0; i < maxBudgetedPodLabels; i++ {
		// Trailing rune only exists to keep the map keys distinct; length is still ~maxLabelKey.
		podLabels[maxLabelKey+string(rune('a'+i))] = maxLabelValue
	}
	podSelector := &metav1.LabelSelector{MatchLabels: podLabels}

	return size.Of(identifier) +
		size.Of(ExternalTrafficType) +
		size.Of(ports) +
		size.Of(maxDNSName) + size.Of([]string{maxDNSName}) +
		size.Of(namespaceSelector) +
		size.Of(podSelector)
}

// ReportCapability reports a capability event for a container
func (cpm *ContainerProfileManager) ReportCapability(containerID, capability string) {
	err := cpm.withContainer(containerID, func(data *containerData) (int, error) {
		if data.capabilites == nil {
			data.capabilites = mapset.NewSet[string]()
		}
		data.capabilites.Add(capability)
		return size.Of(capability), nil
	})

	cpm.logEventError(err, "capability", containerID)
}

// resolveExecPath derives the path to record for an exec event. It is kept
// symmetric with the rule-side resolver in
// pkg/rulemanager/cel/libraries/parse/parse.go (parse.get_exec_path): prefer
// the kernel-authoritative exepath, then argv[0] when non-empty, then comm.
// Using args[0] unconditionally produces an empty Path when the syscall has
// an empty pathname (fexecve / execveat AT_EMPTY_PATH — the libpam helper
// invocation pattern), while the rule-side resolver falls back to comm —
// leaving the AP entry unreachable to ap.was_executed and producing spurious
// "Unexpected process launched" alerts.
func resolveExecPath(exepath, comm string, args []string) string {
	if exepath != "" {
		return exepath
	}
	if len(args) > 0 && args[0] != "" {
		return args[0]
	}
	return comm
}

// ReportFileExec reports a file execution event for a container
func (cpm *ContainerProfileManager) ReportFileExec(containerID string, event utils.ExecEvent) {
	err := cpm.withContainer(containerID, func(data *containerData) (int, error) {
		if data.execs == nil {
			data.execs = &maps.SafeMap[string, []string]{}
		}
		args := event.GetArgs()
		path := resolveExecPath(event.GetExePath(), event.GetComm(), args)

		// Use SHA256 hash of the exec to identify it uniquely
		execIdentifier := utils.CalculateSHA256FileExecHash(path, args)
		if cpm.enricher != nil {
			go cpm.enricher.EnrichEvent(containerID, event, execIdentifier)
		}

		exec := append([]string{path}, args...)
		data.execs.Set(execIdentifier, exec)
		return size.Of(exec), nil
	})

	cpm.logEventError(err, "file exec", containerID)
}

// ReportFileOpen reports a file open event for a container
func (cpm *ContainerProfileManager) ReportFileOpen(containerID string, event utils.OpenEvent) {
	err := cpm.withContainer(containerID, func(data *containerData) (int, error) {
		if data.opens == nil {
			data.opens = &maps.SafeMap[string, mapset.Set[string]]{}
		}

		// Deduplicate /proc/1234/* into /proc/.../*
		path := event.GetPath()
		if strings.HasPrefix(path, "/proc/") {
			path = procRegex.ReplaceAllString(path, "/proc/"+dynamicpathdetector.DynamicIdentifier)
		}

		isSensitive := utils.IsSensitivePath(path, []string{})
		if cpm.enricher != nil && isSensitive {
			openIdentifier := utils.CalculateSHA256FileOpenHash(path)
			go cpm.enricher.EnrichEvent(containerID, event, openIdentifier)
		}

		// Check if we already have this open with these flags
		flags := event.GetFlags()
		if opens, ok := data.opens.Load(path); ok && opens.Contains(flags...) {
			return 0, nil
		}

		// Add to open map
		if opens, ok := data.opens.Load(path); ok {
			opens.Append(flags...)
		} else {
			data.opens.Set(path, mapset.NewSet(flags...))
		}

		return size.Of(path) + size.Of(flags), nil
	})

	cpm.logEventError(err, "file open", containerID)
}

// ReportSymlinkEvent reports a symlink creation event for a container
func (cpm *ContainerProfileManager) ReportSymlinkEvent(containerID string, event utils.LinkEvent) {
	err := cpm.withContainerNoSizeUpdate(containerID, func(data *containerData) error {
		if cpm.enricher != nil {
			symlinkIdentifier := utils.CalculateSHA256FileOpenHash(event.GetOldPath() + event.GetNewPath())
			go cpm.enricher.EnrichEvent(containerID, event, symlinkIdentifier)
		}
		return nil
	})

	cpm.logEventError(err, "symlink", containerID)
}

// ReportHardlinkEvent reports a hardlink creation event for a container
func (cpm *ContainerProfileManager) ReportHardlinkEvent(containerID string, event utils.LinkEvent) {
	err := cpm.withContainerNoSizeUpdate(containerID, func(data *containerData) error {
		if cpm.enricher != nil {
			hardlinkIdentifier := utils.CalculateSHA256FileOpenHash(event.GetOldPath() + event.GetNewPath())
			go cpm.enricher.EnrichEvent(containerID, event, hardlinkIdentifier)
		}
		return nil
	})

	cpm.logEventError(err, "hardlink", containerID)
}

// ReportHTTPEvent reports an HTTP event for a container
func (cpm *ContainerProfileManager) ReportHTTPEvent(containerID string, event utils.HttpEvent) {
	err := cpm.withContainer(containerID, func(data *containerData) (int, error) {
		if event.GetResponse() == nil {
			return 0, nil
		}

		if data.endpoints == nil {
			data.endpoints = &maps.SafeMap[string, *v1beta1.HTTPEndpoint]{}
		}

		endpointIdentifier, err := GetEndpointIdentifier(event)
		if err != nil {
			logger.L().Warning("failed to get endpoint identifier", helpers.Error(err))
			return 0, nil
		}

		endpoint, err := GetNewEndpoint(event, endpointIdentifier)
		if err != nil {
			logger.L().Warning("failed to get new endpoint", helpers.Error(err))
			return 0, nil
		}

		// Check if we already have this endpoint
		endpointHash := CalculateHTTPEndpointHash(endpoint)
		if data.endpoints.Has(endpointHash) {
			return 0, nil
		}

		// Add to endpoint map
		data.endpoints.Set(endpointHash, endpoint)
		return size.Of(endpoint), nil
	})

	cpm.logEventError(err, "http", containerID)
}

// ReportRulePolicy reports a rule policy for a container
func (cpm *ContainerProfileManager) ReportRulePolicy(containerID, ruleId, allowedProcess string, allowedContainer bool) {
	err := cpm.withContainer(containerID, func(data *containerData) (int, error) {
		if data.rulePolicies == nil {
			data.rulePolicies = &maps.SafeMap[string, *v1beta1.RulePolicy]{}

			policies := cpm.getRulePolicies()

			for id, policy := range policies {
				data.rulePolicies.Set(id, &policy)
			}
		}

		newPolicy := &v1beta1.RulePolicy{
			AllowedContainer: allowedContainer,
			AllowedProcesses: []string{allowedProcess},
		}

		existingPolicy, hasExisting := data.rulePolicies.Load(ruleId)
		if hasExisting && IsPolicyIncluded(existingPolicy, newPolicy) {
			return 0, nil
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
		return size.Of(finalPolicy), nil
	})

	cpm.logEventError(err, "rule policy", containerID)
}

// ReportIdentifiedCallStack reports a call stack for a container
func (cpm *ContainerProfileManager) ReportIdentifiedCallStack(containerID string, callStack *v1beta1.IdentifiedCallStack) {
	err := cpm.withContainer(containerID, func(data *containerData) (int, error) {
		if data.callStacks == nil {
			data.callStacks = &maps.SafeMap[string, *v1beta1.IdentifiedCallStack]{}
		}

		// Generate unique identifier for the call stack
		callStackIdentifier := CalculateSHA256CallStackHash(*callStack)

		// Check if we already have this call stack
		if data.callStacks.Has(callStackIdentifier) {
			return 0, nil
		}

		// Add to call stacks map
		data.callStacks.Set(callStackIdentifier, callStack)
		return size.Of(callStack), nil
	})

	cpm.logEventError(err, "callstack", containerID)
}

// ReportNetworkEvent reports a network event for a container
func (cpm *ContainerProfileManager) ReportNetworkEvent(containerID string, event utils.NetworkEvent) {
	if !cpm.isValidNetworkEvent(event) {
		return
	}

	err := cpm.withContainer(containerID, func(data *containerData) (int, error) {
		if data.networks == nil {
			data.networks = mapset.NewSet[NetworkEvent]()
		}

		dstEndpoint := event.GetDstEndpoint()
		networkEvent := NetworkEvent{
			Port:     event.GetDstPort(),
			Protocol: event.GetProto(),
			PktType:  event.GetPktType(),
			Destination: Destination{
				Namespace: dstEndpoint.Namespace,
				Name:      dstEndpoint.Name,
				Kind:      EndpointKind(dstEndpoint.Kind),
				IPAddress: dstEndpoint.Addr,
			},
		}
		networkEvent.SetPodLabels(event.GetPodLabels())
		networkEvent.SetDestinationPodLabels(dstEndpoint.PodLabels)

		// Skip if we already saved this event
		if data.networks.Contains(networkEvent) {
			return 0, nil
		}

		data.networks.Add(networkEvent)
		return size.Of(networkEvent) + networkNeighborExpansionEstimate, nil
	})

	cpm.logEventError(err, "network", containerID)
}

// ReportDroppedEvent reports a dropped event (currently just logs)
func (cpm *ContainerProfileManager) ReportDroppedEvent(containerID string) {
	err := cpm.withContainerNoSizeUpdate(containerID, func(data *containerData) error {
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

func (cpm *ContainerProfileManager) ReportSyscall(containerID string, syscall string) {
	err := cpm.withContainer(containerID, func(data *containerData) (int, error) {
		if data.syscalls == nil {
			data.syscalls = mapset.NewSet[string]()
		}
		// Append returns the number of elements newly added (0 or 1 here), not their
		// serialized size - using it directly mixed element-count units into a
		// byte-size accumulator and made syscalls contribute ~0 to MaxTsProfileSize.
		if data.syscalls.Append(syscall) == 0 {
			return 0, nil
		}
		return size.Of(syscall), nil
	})

	cpm.logEventError(err, "syscalls", containerID)
}

// isValidNetworkEvent checks if the network event is valid for processing
func (cpm *ContainerProfileManager) isValidNetworkEvent(event utils.NetworkEvent) bool {
	pktType := event.GetPktType()
	// Unknown type, shouldn't happen
	if pktType != utils.HostPktType && pktType != utils.OutgoingPktType {
		logger.L().Debug("pktType is not HOST or OUTGOING", helpers.Interface("event", event))
		return false
	}

	// Ignore localhost
	if pktType == utils.HostPktType && event.GetPodHostIP() == event.GetDstEndpoint().Addr {
		return false
	}

	// Ignore host netns
	if event.GetHostNetwork() {
		return false
	}

	return true
}

// getRulePolicies returns a map of rule policies based on the rule cache
func (cpm *ContainerProfileManager) getRulePolicies() map[string]v1beta1.RulePolicy {
	policies := make(map[string]v1beta1.RulePolicy)

	if reflect.ValueOf(cpm.ruleBindingCache).IsNil() {
		return policies
	}

	ids := cpm.ruleBindingCache.GetRuleCreator().GetAllRuleIDs()
	for _, id := range ids {
		policies[id] = v1beta1.RulePolicy{
			AllowedContainer: false,
			AllowedProcesses: []string{},
		}
	}

	return policies
}

// logEventError provides consistent error logging for event reporting
func (cpm *ContainerProfileManager) logEventError(err error, eventType, containerID string) {
	if err != nil && !errors.Is(err, ErrContainerNotFound) {
		logger.L().Error("failed to report "+eventType+" event",
			helpers.String("containerID", containerID),
			helpers.Error(err))
	}
}
