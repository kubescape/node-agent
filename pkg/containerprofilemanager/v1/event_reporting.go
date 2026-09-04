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

// neighborFixedOverhead is the number of bytes every v1beta1.NetworkNeighbor gains over its
// source NetworkEvent regardless of Destination.Kind: a generated Identifier hash and a Type
// string. Both are exactly bounded, so they're measured once rather than guessed:
// Identifier is hex.EncodeToString of a sha256 sum (always 2*sha256.Size bytes), Type is the
// longer of "internal"/"external".
var neighborFixedOverhead = size.Of(strings.Repeat("f", sha256.Size*2)) + size.Of(ExternalTrafficType)

// maxDNSNameEstimate budgets the one field that's genuinely unknowable at report time on
// container_data.go's raw/DNS branch: DNS resolution happens at serialization, not when the
// event is reported. RFC 1035 §3.1 bounds an encoded domain name to 253 bytes;
// createNetworkNeighbor stores it twice (DNS and DNSNames[0]).
var maxDNSNameEstimate = func() int {
	maxDNSName := strings.Repeat("a", 253)
	return size.Of(maxDNSName) + size.Of([]string{maxDNSName})
}()

// maxBudgetedServiceLabels bounds maxServiceSelectorEstimate below. Kubernetes Services are
// conventionally selected on a handful of short labels (e.g. "app: foo"), unlike Pods which
// can carry many more, so this is deliberately smaller than a Pod label budget would be.
const maxBudgetedServiceLabels = 6

// maxServiceSelectorEstimate budgets the other field genuinely unknowable at report time:
// on the Service branch, svc.GetServiceSelector() is fetched from the k8s API at
// serialization time and has no relationship to anything on the raw event. Each of
// maxBudgetedServiceLabels labels is sized at Kubernetes' per-label maximum (253-byte key,
// 63-byte value) as generous headroom.
var maxServiceSelectorEstimate = func() int {
	maxLabelKey := strings.Repeat("k", 253)
	maxLabelValue := strings.Repeat("v", 63)
	labels := make(map[string]string, maxBudgetedServiceLabels)
	for i := 0; i < maxBudgetedServiceLabels; i++ {
		// Trailing rune only exists to keep the map keys distinct; length is still ~maxLabelKey.
		labels[maxLabelKey+string(rune('a'+i))] = maxLabelValue
	}
	return size.Of(&metav1.LabelSelector{MatchLabels: labels})
}()

// networkNeighborIncrement estimates the additional bytes createNetworkNeighbor()
// (container_data.go) adds beyond the raw NetworkEvent when it builds the eventual
// v1beta1.NetworkNeighbor. createNetworkNeighbor takes exactly one branch per
// Destination.Kind, so only that branch's cost is charged - summing every branch
// unconditionally, as an earlier version of this function did, overcounted by 6-20x and
// turned the split path from #866 into the normal case instead of a rare backstop.
//
// PodSelector on the Pod branch is not budgeted as a guess: its label *bytes* are already on
// the meter via Destination.PodLabels, a string field size.Of(networkEvent) counts by the
// caller, but re-shaping that string into map[string]string costs real additional bytes (Go
// map bucket overhead), so this measures that wrapper delta exactly from the same data
// filterLabels/GetDestinationPodLabels would produce, rather than assuming it's zero or
// guessing a label count. NamespaceSelector is computed exactly from fields already on the
// event. Port/Protocol on Pod and raw branches are also exact from the event; on the Service
// branch serialization may remap observed socket ports to enforcement (target/endpoint)
// ports and may emit multiple NetworkPort entries, so the Service case budgets a
// conservative upper bound instead.
func networkNeighborIncrement(data *containerData, networkEvent NetworkEvent) int {
	est := neighborFixedOverhead + size.Of([]v1beta1.NetworkPort{{
		Name:     generatePortIdentifierFromEvent(networkEvent),
		Protocol: v1beta1.Protocol(networkEvent.Protocol),
		Port:     ptr.To(int32(networkEvent.Port)),
	}})

	sourceNamespace := ""
	if data.watchedContainerData != nil {
		sourceNamespace = data.watchedContainerData.Namespace
	}
	if namespaceLabels := getNamespaceMatchLabels(networkEvent.Destination.Namespace, sourceNamespace); namespaceLabels != nil {
		est += size.Of(&metav1.LabelSelector{MatchLabels: namespaceLabels})
	}

	switch networkEvent.Destination.Kind {
	case EndpointKindService:
		est += maxServiceSelectorEstimate
		est += size.Of(v1beta1.NetworkPort{
			Name:     generatePortIdentifier(networkEvent.Protocol, 65535),
			Protocol: v1beta1.Protocol(networkEvent.Protocol),
			Port:     ptr.To(int32(65535)),
		})
	case EndpointKindPod:
		// The label bytes are already on the meter via Destination.PodLabels; only charge the
		// extra cost of wrapping them into a LabelSelector's map, and never a negative one.
		podSelector := &metav1.LabelSelector{MatchLabels: filterLabels(networkEvent.GetDestinationPodLabels())}
		if delta := size.Of(podSelector) - size.Of(networkEvent.Destination.PodLabels); delta > 0 {
			est += delta
		}
	default:
		est += maxDNSNameEstimate
	}
	return est
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
		return size.Of(networkEvent) + networkNeighborIncrement(data, networkEvent), nil
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

// ReportSyscalls reports a batch of syscalls for a container in a single locked operation -
// one container-lock acquisition and one size update, rather than one per syscall. The eBPF
// syscall tracer decodes a whole periodically- or on-demand-fetched bitmap at once (see
// pkg/containerwatcher/v2/tracers/syscall.go), so this is called with that whole batch directly,
// bypassing the generic per-event pipeline entirely for this consumer (kubescape/node-agent#922).
func (cpm *ContainerProfileManager) ReportSyscalls(containerID string, syscalls []string) {
	err := cpm.withContainer(containerID, func(data *containerData) (int, error) {
		if data.syscalls == nil {
			data.syscalls = mapset.NewSet[string]()
		}
		addedSize := 0
		for _, syscall := range syscalls {
			// Append returns the number of elements newly added (0 or 1 here), not their
			// serialized size - using it directly mixed element-count units into a
			// byte-size accumulator and made syscalls contribute ~0 to MaxTsProfileSize.
			if data.syscalls.Append(syscall) > 0 {
				addedSize += size.Of(syscall)
			}
		}
		return addedSize, nil
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
