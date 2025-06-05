package containerprofilemanager

import (
	"regexp"
	"slices"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/ruleengine/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

var procRegex = regexp.MustCompile(`^/proc/\d+`)

func (cpm *ContainerProfileManager) RegisterPeekFunc(peek func(mntns uint64) ([]string, error)) {
	cpm.syscallPeekFunc = peek
}

func (cpm *ContainerProfileManager) ReportCapability(k8sContainerID, capability string) {
	if err := cpm.waitForContainer(k8sContainerID); err != nil {
		return
	}
	// check if we already have this capability
	if _, ok := cpm.savedCapabilities.Get(k8sContainerID).Get(capability); ok {
		return
	}
	// add to capability map
	cpm.toSaveCapabilities.Get(k8sContainerID).Add(capability)
}

func (cpm *ContainerProfileManager) ReportFileExec(k8sContainerID string, event events.ExecEvent) {
	if err := cpm.waitForContainer(k8sContainerID); err != nil {
		return
	}

	path := event.Comm
	if len(event.Args) > 0 {
		path = event.Args[0]
	}

	// check if we already have this exec
	// we use a SHA256 hash of the exec to identify it uniquely (path + args, in the order they were provided)
	execIdentifier := utils.CalculateSHA256FileExecHash(path, event.Args)
	if cpm.enricher != nil {
		go cpm.enricher.EnrichEvent(k8sContainerID, &event, execIdentifier)
	}

	if _, ok := cpm.savedExecs.Get(k8sContainerID).Get(execIdentifier); ok {
		return
	}
	// add to exec map, first element is the path, the rest are the args
	cpm.toSaveExecs.Get(k8sContainerID).Set(execIdentifier, append([]string{path}, event.Args...))
}

func (cpm *ContainerProfileManager) ReportFileOpen(k8sContainerID string, event events.OpenEvent) {
	if err := cpm.waitForContainer(k8sContainerID); err != nil {
		return
	}
	// deduplicate /proc/1234/* into /proc/.../* (quite a common case)
	// we perform it here instead of waiting for compression
	path := event.Path
	if strings.HasPrefix(path, "/proc/") {
		path = procRegex.ReplaceAllString(path, "/proc/"+dyncpmicpathdetector.DyncpmicIdentifier)
	}

	isSensitive := utils.IsSensitivePath(path, ruleengine.SensitiveFiles)

	if cpm.enricher != nil && isSensitive {
		openIdentifier := utils.CalculateSHA256FileOpenHash(path)
		go cpm.enricher.EnrichEvent(k8sContainerID, &event, openIdentifier)
	}

	// check if we already have this open
	if opens, ok := cpm.savedOpens.Get(k8sContainerID).Get(path); ok && opens.(mapset.Set[string]).Contains(event.Flags...) {
		return
	}
	// add to open map
	openMap := cpm.toSaveOpens.Get(k8sContainerID)
	if openMap.Has(path) {
		openMap.Get(path).Append(event.Flags...)
	} else {
		openMap.Set(path, mapset.NewSet[string](event.Flags...))
	}
}

func (cpm *ContainerProfileManager) ReportSymlinkEvent(k8sContainerID string, event *tracersymlinktype.Event) {
	if err := cpm.waitForContainer(k8sContainerID); err != nil {
		return
	}

	if cpm.enricher != nil {
		symlinkIdentifier := utils.CalculateSHA256FileOpenHash(event.OldPath + event.NewPath)
		go cpm.enricher.EnrichEvent(k8sContainerID, event, symlinkIdentifier)
	}
}

func (cpm *ContainerProfileManager) ReportHardlinkEvent(k8sContainerID string, event *tracerhardlinktype.Event) {
	if err := cpm.waitForContainer(k8sContainerID); err != nil {
		return
	}

	if cpm.enricher != nil {
		hardlinkIdentifier := utils.CalculateSHA256FileOpenHash(event.OldPath + event.NewPath)
		go cpm.enricher.EnrichEvent(k8sContainerID, event, hardlinkIdentifier)
	}
}

func (cpm *ContainerProfileManager) ReportDroppedEvent(k8sContainerID string) {
	cpm.droppedEventsContainers.Add(k8sContainerID)
}

func (cpm *ContainerProfileManager) ReportHTTPEvent(k8sContainerID string, event *tracerhttptype.Event) {
	if err := cpm.waitForContainer(k8sContainerID); err != nil {
		return
	}

	if event.Response == nil {
		logger.L().Debug("ContainerProfileManager - HTTP event without response", helpers.String("container ID", k8sContainerID))
		return
	}

	endpointIdentifier, err := GetEndpointIdentifier(event)
	if err != nil {
		logger.L().Ctx(cpm.ctx).Warning("ContainerProfileManager - failed to get endpoint identifier", helpers.Error(err))
		return
	}
	endpoint, err := GetNewEndpoint(event, endpointIdentifier)
	if err != nil {
		logger.L().Ctx(cpm.ctx).Warning("ContainerProfileManager - failed to get new endpoint", helpers.Error(err))
		return
	}
	// check if we already have this endpoint
	endpointHash := CalculateHTTPEndpointHash(endpoint)
	if _, ok := cpm.savedEndpoints.Get(k8sContainerID).Get(endpointHash); ok {
		return
	}
	// add to endpoint map
	cpm.toSaveEndpoints.Get(k8sContainerID).Set(endpointHash, endpoint)
}

func (cpm *ContainerProfileManager) ReportRulePolicy(k8sContainerID, ruleId, allowedProcess string, allowedContainer bool) {
	if err := cpm.waitForContainer(k8sContainerID); err != nil {
		return
	}

	newPolicy := &v1beta1.RulePolicy{
		AllowedContainer: allowedContainer,
		AllowedProcesses: []string{allowedProcess},
	}

	savedPolicies := cpm.savedRulePolicies.Get(k8sContainerID)
	savedPolicy, ok := savedPolicies.Get(ruleId)
	if ok {
		savedPolicy := savedPolicy.(*v1beta1.RulePolicy)
		if IsPolicyIncluded(savedPolicy, newPolicy) {
			return
		}
	}

	toBeSavedPolicies := cpm.toSaveRulePolicies.Get(k8sContainerID)
	toBeSavedPolicy := toBeSavedPolicies.Get(ruleId)

	if IsPolicyIncluded(toBeSavedPolicy, newPolicy) {
		return
	}

	var finalPolicy *v1beta1.RulePolicy
	if toBeSavedPolicy != nil {
		finalPolicy = toBeSavedPolicy
		if allowedContainer {
			finalPolicy.AllowedContainer = true
		}
		if allowedProcess != "" && !slices.Contains(finalPolicy.AllowedProcesses, allowedProcess) {
			finalPolicy.AllowedProcesses = append(finalPolicy.AllowedProcesses, allowedProcess)
		}
	} else {
		finalPolicy = newPolicy
	}

	toBeSavedPolicies.Set(ruleId, finalPolicy)
}

func (cpm *ContainerProfileManager) ReportIdentifiedCallStack(k8sContainerID string, callStack *v1beta1.IdentifiedCallStack) {
	if err := cpm.waitForContainer(k8sContainerID); err != nil {
		return
	}

	// Generate unique identifier for the call stack
	callStackIdentifier := CalculateSHA256CallStackHash(*callStack)

	// Check if we already have this call stack
	if _, ok := cpm.savedCallStacks.Get(k8sContainerID).Get(callStackIdentifier); ok {
		return
	}

	// Add to call stacks map
	cpm.toSaveCallStacks.Get(k8sContainerID).Set(callStackIdentifier, callStack)
}
