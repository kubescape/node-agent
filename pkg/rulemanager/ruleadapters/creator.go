package ruleadapters

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
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	maxFileSize      = 50 * 1024 * 1024 // 50MB
	hashCacheTTL     = 1 * time.Minute
	hashCacheMaxSize = 50000
)

var ErrRuleShouldNotBeAlerted = errors.New("rule should not be alerted")

type FileHashCache struct {
	SHA1Hash string
	MD5Hash  string
}

type RuleFailureCreator struct {
	adapterFactory   *EventRuleAdapterFactory
	containerIdToPid *maps.SafeMap[string, uint32]
	dnsManager       dnsmanager.DNSResolver
	enricher         types.Enricher
	hashCache        *expirable.LRU[string, *FileHashCache]
}

func NewRuleFailureCreator(enricher types.Enricher, dnsManager dnsmanager.DNSResolver, adapterFactory *EventRuleAdapterFactory) *RuleFailureCreator {
	hashCache := expirable.NewLRU[string, *FileHashCache](hashCacheMaxSize, nil, hashCacheTTL)
	return &RuleFailureCreator{
		adapterFactory: adapterFactory,
		dnsManager:     dnsManager,
		enricher:       enricher,
		hashCache:      hashCache,
	}
}

func (r *RuleFailureCreator) CreateRuleFailure(rule typesv1.Rule, enrichedEvent *events.EnrichedEvent, objectCache objectcache.ObjectCache, message, uniqueID string) types.RuleFailure {
	eventAdapter, ok := r.adapterFactory.GetAdapter(enrichedEvent.EventType)
	if !ok {
		logger.L().Error("RuleFailureCreator - no adapter registered for event type", helpers.String("eventType", string(enrichedEvent.EventType)))
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
			InfectedPID: enrichedEvent.ProcessTree.PID,
		},
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: message,
		},
		RuleID:        rule.ID,
		AlertPlatform: apitypes.AlertSourcePlatformK8s,
	}

	eventAdapter.SetFailureMetadata(ruleFailure, enrichedEvent)

	r.setBaseRuntimeAlert(ruleFailure)
	r.setRuntimeAlertK8sDetails(ruleFailure)
	r.setCloudServices(ruleFailure)
	r.setProfileMetadata(rule, ruleFailure, objectCache)
	r.enrichRuleFailure(ruleFailure)

	if enrichedEvent.ProcessTree.PID != 0 {
		ruleFailure.SetRuntimeProcessDetails(apitypes.ProcessTree{
			ProcessTree: enrichedEvent.ProcessTree,
			ContainerID: enrichedEvent.ContainerID,
		})
	}

	return ruleFailure
}

func (r *RuleFailureCreator) enrichRuleFailure(ruleFailure *types.GenericRuleFailure) {
	if r.enricher != nil && !reflect.ValueOf(r.enricher).IsNil() {
		if err := r.enricher.EnrichRuleFailure(ruleFailure); err != nil {
			if errors.Is(err, ErrRuleShouldNotBeAlerted) { // TODO: @amitschendel - I think this check doesn't work.
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
		state := objectCache.ApplicationProfileCache().GetApplicationProfileState(ruleFailure.GetTriggerEvent().GetContainerID())
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
		state := objectCache.NetworkNeighborhoodCache().GetNetworkNeighborhoodState(ruleFailure.GetTriggerEvent().GetContainerID())
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
	if cloudServices := r.dnsManager.ResolveContainerProcessToCloudServices(ruleFailure.GetTriggerEvent().GetContainerID(), ruleFailure.GetBaseRuntimeAlert().InfectedPID); cloudServices != nil {
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

	if err != nil { // FIXME WTF it's always nil here
		if ruleFailure.GetRuntimeProcessDetails().ProcessTree.Path != "" {
			hostPath = filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", r.containerIdToPid.Get(ruleFailure.GetTriggerEvent().GetContainerID()),
				ruleFailure.GetRuntimeProcessDetails().ProcessTree.Path))
		}
	} else {
		hostPath = filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", ruleFailure.GetRuntimeProcessDetails().ProcessTree.PID, path))
	}

	baseRuntimeAlert := ruleFailure.GetBaseRuntimeAlert()

	baseRuntimeAlert.Timestamp = time.Unix(0, int64(ruleFailure.GetTriggerEvent().GetTimestamp()))
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

	if size != 0 && size < maxFileSize { //&& hostPath != "" {
		if baseRuntimeAlert.MD5Hash == "" || baseRuntimeAlert.SHA1Hash == "" {
			if cached, found := r.hashCache.Get(hostPath); found {
				baseRuntimeAlert.MD5Hash = cached.MD5Hash
				baseRuntimeAlert.SHA1Hash = cached.SHA1Hash
			} else {
				sha1hash, md5hash, err := utils.CalculateFileHashes(hostPath)
				if err == nil {
					baseRuntimeAlert.MD5Hash = md5hash
					baseRuntimeAlert.SHA1Hash = sha1hash
					r.hashCache.Add(hostPath, &FileHashCache{
						SHA1Hash: sha1hash,
						MD5Hash:  md5hash,
					})
				}
			}
		}
	}

	ruleFailure.SetBaseRuntimeAlert(baseRuntimeAlert)

}

func (r *RuleFailureCreator) setRuntimeAlertK8sDetails(ruleFailure *types.GenericRuleFailure) {
	runtimek8sdetails := ruleFailure.GetRuntimeAlertK8sDetails()
	if runtimek8sdetails.Image == "" {
		runtimek8sdetails.Image = ruleFailure.GetTriggerEvent().GetContainerImage()
	}

	if runtimek8sdetails.ImageDigest == "" {
		runtimek8sdetails.ImageDigest = ruleFailure.GetTriggerEvent().GetContainerImageDigest()
	}

	if runtimek8sdetails.Namespace == "" {
		runtimek8sdetails.Namespace = ruleFailure.GetTriggerEvent().GetNamespace()
	}

	if runtimek8sdetails.PodName == "" {
		runtimek8sdetails.PodName = ruleFailure.GetTriggerEvent().GetPod()
	}

	if runtimek8sdetails.PodNamespace == "" {
		runtimek8sdetails.PodNamespace = ruleFailure.GetTriggerEvent().GetNamespace()
	}

	if runtimek8sdetails.ContainerName == "" {
		runtimek8sdetails.ContainerName = ruleFailure.GetTriggerEvent().GetContainer()
	}

	if runtimek8sdetails.ContainerID == "" {
		runtimek8sdetails.ContainerID = ruleFailure.GetTriggerEvent().GetContainerID()
	}

	if runtimek8sdetails.HostNetwork == nil {
		hostNetwork := ruleFailure.GetTriggerEvent().GetHostNetwork()
		runtimek8sdetails.HostNetwork = &hostNetwork
	}

	ruleFailure.SetRuntimeAlertK8sDetails(runtimek8sdetails)
}
