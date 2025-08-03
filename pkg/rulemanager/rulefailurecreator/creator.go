package rulefailurecreator

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/dustin/go-humanize"
	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulefailurecreator/setters"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	maxFileSize = 50 * 1024 * 1024 // 50MB
)

var ErrRuleShouldNotBeAlerted = errors.New("rule should not be alerted")

type RuleFailureCreator struct {
	setterByEventType map[utils.EventType]EventMetadataSetter
	containerIdToPid  *maps.SafeMap[string, uint32]
	dnsManager        dnsmanager.DNSResolver
	enricher          types.Enricher
}

func NewRuleFailureCreator(enricher types.Enricher, dnsManager dnsmanager.DNSResolver) *RuleFailureCreator {
	r := &RuleFailureCreator{
		setterByEventType: make(map[utils.EventType]EventMetadataSetter),
		dnsManager:        dnsManager,
		enricher:          enricher,
	}
	r.RegisterAllSetters()
	return r
}

func (r *RuleFailureCreator) SetContainerIdToPid(containerIdToPid *maps.SafeMap[string, uint32]) {
	r.containerIdToPid = containerIdToPid
}

func (r *RuleFailureCreator) RegisterCreator(eventType utils.EventType, creator EventMetadataSetter) {
	r.setterByEventType[eventType] = creator
}

func (r *RuleFailureCreator) CreateRuleFailure(rule typesv1.Rule, enrichedEvent *events.EnrichedEvent, objectCache objectcache.ObjectCache, message, uniqueID string) types.RuleFailure {
	eventSetter, ok := r.setterByEventType[enrichedEvent.EventType]
	if !ok {
		logger.L().Error("RuleFailureCreator - no creator registered for event type", helpers.String("eventType", string(enrichedEvent.EventType)))
		return nil
	}

	ruleFailure := &types.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:  uniqueID,
			AlertName: rule.Name,
			Severity:  rule.Severity,
			Arguments: map[string]interface{}{
				"message": message,
			},
			Timestamp:   enrichedEvent.Timestamp,
			Nanoseconds: uint64(enrichedEvent.Timestamp.UnixNano()),
			InfectedPID: enrichedEvent.ProcessTree.PID,
		},
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: message,
		},
		RuleID:        rule.ID,
		AlertPlatform: apitypes.AlertSourcePlatformK8s,
	}

	eventSetter.SetFailureMetadata(ruleFailure, enrichedEvent)

	r.setBaseRuntimeAlert(ruleFailure)
	r.setRuntimeAlertK8sDetails(ruleFailure)
	r.setCloudServices(ruleFailure)
	r.setProfileMetadata(rule, ruleFailure, objectCache)
	r.enrichRuleFailure(ruleFailure)

	if enrichedEvent.ProcessTree.PID != 0 {
		ruleFailure.SetRuntimeProcessDetails(apitypes.ProcessTree{
			ProcessTree: enrichedEvent.ProcessTree,
		})
	}

	return ruleFailure
}

func (r *RuleFailureCreator) enrichRuleFailure(ruleFailure *types.GenericRuleFailure) {
	if r.enricher != nil && !reflect.ValueOf(r.enricher).IsNil() {
		if err := r.enricher.EnrichRuleFailure(ruleFailure); err != nil {
			if errors.Is(err, ErrRuleShouldNotBeAlerted) {
				return
			}
		}
	}

}

func (r *RuleFailureCreator) setProfileMetadata(rule typesv1.Rule, ruleFailure *types.GenericRuleFailure, objectCache objectcache.ObjectCache) {
	var profileType armotypes.ProfileType
	baseRuntimeAlert := ruleFailure.GetBaseRuntimeAlert()
	profileRequirment := rule.ProfileDependency
	if !(profileRequirment == armotypes.Required || profileRequirment == armotypes.Optional) {
		return
	}

	for _, tag := range rule.Tags {
		switch tag {
		case types.ApplicationProfile:
			profileType = armotypes.ApplicationProfile
		case types.NetworkProfile:
			profileType = armotypes.NetworkProfile
		}
	}

	switch profileType {
	case armotypes.ApplicationProfile:
		state := objectCache.ApplicationProfileCache().GetApplicationProfileState(ruleFailure.GetTriggerEvent().Runtime.ContainerID)
		if state != nil {
			profileMetadata := &armotypes.ProfileMetadata{
				Status:            state.Status,
				Completion:        state.Completion,
				Name:              state.Name,
				FailOnProfile:     state.Status == helpersv1.Completed,
				Type:              armotypes.ApplicationProfile,
				ProfileDependency: profileRequirment,
				Error:             state.Error,
			}
			baseRuntimeAlert.ProfileMetadata = profileMetadata
		}

	case armotypes.NetworkProfile:
		state := objectCache.NetworkNeighborhoodCache().GetNetworkNeighborhoodState(ruleFailure.GetTriggerEvent().Runtime.ContainerID)
		if state != nil {
			profileMetadata := &armotypes.ProfileMetadata{
				Status:            state.Status,
				Completion:        state.Completion,
				Name:              state.Name,
				FailOnProfile:     state.Status == helpersv1.Completed,
				Type:              armotypes.NetworkProfile,
				ProfileDependency: profileRequirment,
				Error:             state.Error,
			}
			baseRuntimeAlert.ProfileMetadata = profileMetadata
		}
	default:
		profileMetadata := &armotypes.ProfileMetadata{
			ProfileDependency: profileRequirment,
			FailOnProfile:     false,
			Error:             fmt.Errorf("profile type %d not supported", profileRequirment),
		}
		baseRuntimeAlert.ProfileMetadata = profileMetadata
	}
	ruleFailure.SetBaseRuntimeAlert(baseRuntimeAlert)
}

func (r *RuleFailureCreator) setCloudServices(ruleFailure *types.GenericRuleFailure) {
	if cloudServices := r.dnsManager.ResolveContainerProcessToCloudServices(ruleFailure.GetTriggerEvent().Runtime.ContainerID, ruleFailure.GetBaseRuntimeAlert().InfectedPID); cloudServices != nil {
		ruleFailure.SetCloudServices(cloudServices.ToSlice())
	}

}

func (r *RuleFailureCreator) setBaseRuntimeAlert(ruleFailure *types.GenericRuleFailure) {
	var hostPath string
	var err error
	var path string

	if ruleFailure.GetRuntimeProcessDetails().ProcessTree.Path == "" {
		path, err = utils.GetPathFromPid(ruleFailure.GetRuntimeProcessDetails().ProcessTree.PID)
		if err != nil {
			return
		}
		hostPath = filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", ruleFailure.GetRuntimeProcessDetails().ProcessTree.PID, path))
	}

	if err != nil {
		if ruleFailure.GetRuntimeProcessDetails().ProcessTree.Path != "" {
			hostPath = filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", r.containerIdToPid.Get(ruleFailure.GetTriggerEvent().Runtime.ContainerID),
				ruleFailure.GetRuntimeProcessDetails().ProcessTree.Path))
		}
	} else {
		hostPath = filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", ruleFailure.GetRuntimeProcessDetails().ProcessTree.PID, path))
	}

	baseRuntimeAlert := ruleFailure.GetBaseRuntimeAlert()

	baseRuntimeAlert.Timestamp = time.Unix(0, int64(ruleFailure.GetTriggerEvent().Timestamp))
	var size int64 = 0
	if hostPath != "" {
		size, err = utils.GetFileSize(hostPath)
		if err != nil {
			size = 0
		}
	}

	if baseRuntimeAlert.Size == "" && hostPath != "" && size != 0 {
		baseRuntimeAlert.Size = humanize.Bytes(uint64(size))
	}

	if size != 0 && size < maxFileSize && hostPath != "" {
		if baseRuntimeAlert.MD5Hash == "" || baseRuntimeAlert.SHA1Hash == "" {
			sha1hash, md5hash, err := utils.CalculateFileHashes(hostPath)
			if err == nil {
				baseRuntimeAlert.MD5Hash = md5hash
				baseRuntimeAlert.SHA1Hash = sha1hash
			}
		}
	}

	ruleFailure.SetBaseRuntimeAlert(baseRuntimeAlert)

}

func (r *RuleFailureCreator) setRuntimeAlertK8sDetails(ruleFailure *types.GenericRuleFailure) {
	runtimek8sdetails := ruleFailure.GetRuntimeAlertK8sDetails()
	if runtimek8sdetails.Image == "" {
		runtimek8sdetails.Image = ruleFailure.GetTriggerEvent().Runtime.ContainerImageName
	}

	if runtimek8sdetails.ImageDigest == "" {
		runtimek8sdetails.ImageDigest = ruleFailure.GetTriggerEvent().Runtime.ContainerImageDigest
	}

	if runtimek8sdetails.Namespace == "" {
		runtimek8sdetails.Namespace = ruleFailure.GetTriggerEvent().K8s.Namespace
	}

	if runtimek8sdetails.PodName == "" {
		runtimek8sdetails.PodName = ruleFailure.GetTriggerEvent().K8s.PodName
	}

	if runtimek8sdetails.PodNamespace == "" {
		runtimek8sdetails.PodNamespace = ruleFailure.GetTriggerEvent().K8s.Namespace
	}

	if runtimek8sdetails.ContainerName == "" {
		runtimek8sdetails.ContainerName = ruleFailure.GetTriggerEvent().K8s.ContainerName
	}

	if runtimek8sdetails.ContainerID == "" {
		runtimek8sdetails.ContainerID = ruleFailure.GetTriggerEvent().Runtime.ContainerID
	}

	if runtimek8sdetails.HostNetwork == nil {
		hostNetwork := ruleFailure.GetTriggerEvent().K8s.HostNetwork
		runtimek8sdetails.HostNetwork = &hostNetwork
	}

	ruleFailure.SetRuntimeAlertK8sDetails(runtimek8sdetails)
}

func (r *RuleFailureCreator) RegisterAllSetters() {
	r.RegisterCreator(utils.ExecveEventType, setters.NewExecCreator())
	r.RegisterCreator(utils.OpenEventType, setters.NewOpenCreator())
	r.RegisterCreator(utils.CapabilitiesEventType, setters.NewCapabilitiesCreator())
	r.RegisterCreator(utils.DnsEventType, setters.NewDnsCreator())
	r.RegisterCreator(utils.NetworkEventType, setters.NewNetworkCreator())
	r.RegisterCreator(utils.SyscallEventType, setters.NewSyscallCreator())
	r.RegisterCreator(utils.SymlinkEventType, setters.NewSymlinkCreator())
	r.RegisterCreator(utils.HardlinkEventType, setters.NewHardlinkCreator())
	r.RegisterCreator(utils.SSHEventType, setters.NewSSHCreator())
	r.RegisterCreator(utils.HTTPEventType, setters.NewHTTPCreator())
	r.RegisterCreator(utils.PtraceEventType, setters.NewPtraceCreator())
	r.RegisterCreator(utils.IoUringEventType, setters.NewIoUringCreator())
	r.RegisterCreator(utils.RandomXEventType, setters.NewRandomXCreator())
}
