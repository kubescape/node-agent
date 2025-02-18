package hostrulemanager

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/cenkalti/backoff/v4"
	"github.com/dustin/go-humanize"
	"github.com/goradd/maps"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/cooldownqueue"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/hostrulemanager"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/processmanager"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	ruleenginetypes "github.com/kubescape/node-agent/pkg/ruleengine/types"
	ruleenginev1 "github.com/kubescape/node-agent/pkg/ruleengine/v1"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	maxFileSize            = 50 * 1024 * 1024 // 50MB
	hostPID                = 1
	syscallPeekingInterval = 5 * time.Second
	evictionInterval       = 5 * time.Second
	cooldownDuration       = 5 * time.Minute
)

type RuleManager struct {
	ctx             context.Context
	exporter        exporters.Exporter
	objectCache     objectcache.ObjectCache
	syscallPeekFunc func(nsMountId uint64) ([]string, error)
	processManager  processmanager.ProcessManagerClient
	hostname        string
	rules           []ruleengine.RuleEvaluator
	cooldownQueues  maps.SafeMap[string, *cooldownqueue.CooldownQueue[ruleengine.RuleFailure]] // ruleID+PID -> cooldown queue
}

var _ hostrulemanager.HostRuleManagerClient = &RuleManager{}

func NewRuleManager(ctx context.Context, exporter exporters.Exporter, objectCache objectcache.ObjectCache, processManager processmanager.ProcessManagerClient, ruleCreator *ruleenginev1.RuleCreatorImpl) *RuleManager {
	hostname, err := os.Hostname()
	if err != nil {
		logger.L().Error("RuleManager - failed to get hostname", helpers.Error(err))
	}

	ruleManager := RuleManager{
		ctx:            ctx,
		exporter:       exporter,
		objectCache:    objectCache,
		processManager: processManager,
		hostname:       hostname,
		rules:          ruleCreator.CreateAllRules(), // Create all host rules (in the context of the host).
	}

	go func() {
		if err := ruleManager.startSyscallPeek(); err != nil {
			logger.L().Error("RuleManager - failed to start syscall peek", helpers.Error(err))
		}
	}()

	return &ruleManager
}

func (rm *RuleManager) RegisterPeekFunc(peek func(mntns uint64) ([]string, error)) {
	rm.syscallPeekFunc = peek
}

func (r *RuleManager) startSyscallPeek() error {
	logger.L().Debug("RuleManager - startSyscallPeek")

	syscallTicker := time.NewTicker(syscallPeekingInterval)
	var hostMntNsId uint64
	if mntns, err := r.getHostMountNamespaceId(); err == nil {
		hostMntNsId = mntns
	}

	for {
		select {
		case <-r.ctx.Done():
			logger.L().Debug("RuleManager - syscallPeek stopped")
			return nil
		case <-syscallTicker.C:
			if r.syscallPeekFunc == nil {
				logger.L().Debug("RuleManager - syscallPeekFunc is not set")
				continue
			}

			if hostMntNsId == 0 {
				logger.L().Debug("RuleManager - mount namespace ID is not set")
			}

			var syscalls []string
			if syscallsFromFunc, err := r.syscallPeekFunc(hostMntNsId); err == nil {
				syscalls = syscallsFromFunc
			}

			if len(syscalls) == 0 {
				continue
			}

			for _, syscall := range syscalls {
				event := ruleenginetypes.SyscallEvent{
					Event: eventtypes.Event{
						Timestamp: eventtypes.Time(time.Now().UnixNano()),
						Type:      eventtypes.NORMAL,
						CommonData: eventtypes.CommonData{
							K8s: eventtypes.K8sMetadata{
								Node: r.hostname,
							},
						},
					},
					WithMountNsID: eventtypes.WithMountNsID{
						MountNsID: hostMntNsId,
					},
					Pid: uint32(hostPID),
					// TODO: Figure out how to get UID, GID and comm from the syscall.
					// Uid:         container.OciConfig.Process.User.UID,
					// Gid:         container.OciConfig.Process.User.GID,
					// Comm:        container.OciConfig.Process.Args[0],
					SyscallName: syscall,
				}

				r.processEvent(utils.SyscallEventType, &event, r.rules)
			}
		}
	}
}

func (r *RuleManager) getHostMountNamespaceId() (uint64, error) {
	mntns, err := containerutils.GetMntNs(hostPID)
	if err != nil {
		return 0, fmt.Errorf("getting mount namespace ID for host PID %d: %w", hostPID, err)
	}

	return mntns, nil
}

func (r *RuleManager) ReportEvent(eventType utils.EventType, event utils.K8sEvent) {
	r.processEvent(eventType, event, r.rules)
}

func (r *RuleManager) processEvent(eventType utils.EventType, event utils.K8sEvent, rules []ruleengine.RuleEvaluator) {
	for _, rule := range rules {
		if rule == nil {
			continue
		}

		if !isEventRelevant(rule.Requirements(), eventType) {
			continue
		}

		res := rule.ProcessEvent(eventType, event, r.objectCache)
		if res != nil {
			res = r.enrichRuleFailure(res)
			cooldownKey := fmt.Sprintf("%s-%d", rule.ID(), res.GetRuntimeProcessDetails().ProcessTree.PID)
			cooldownQueue, ok := r.cooldownQueues.Load(cooldownKey)
			if !ok {
				cooldownQueue = cooldownqueue.NewCooldownQueue[ruleengine.RuleFailure](cooldownDuration, evictionInterval)
				r.cooldownQueues.Set(cooldownKey, cooldownQueue)
				r.exporter.SendRuleAlert(res)
			} else {
				// Enqueue the alert to the cooldown queue.
				cooldownQueue.Enqueue(res, res.GetRuleAlert().RuleDescription) // TODO: Have a proper unique key for the cooldown queue.
			}
		}
	}
}

func (r *RuleManager) enrichRuleFailure(ruleFailure ruleengine.RuleFailure) ruleengine.RuleFailure {
	var err error
	var path string
	var hostPath string
	if ruleFailure.GetRuntimeProcessDetails().ProcessTree.Path == "" {
		path, err = utils.GetPathFromPid(ruleFailure.GetRuntimeProcessDetails().ProcessTree.PID)
	}

	if err != nil {
		if ruleFailure.GetRuntimeProcessDetails().ProcessTree.Path != "" {
			hostPath = ruleFailure.GetRuntimeProcessDetails().ProcessTree.Path
		}
	} else {
		hostPath = path
	}

	// Enrich BaseRuntimeAlert
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

	runtimeProcessDetails := ruleFailure.GetRuntimeProcessDetails()

	err = backoff.Retry(func() error {
		tree, err := r.processManager.GetProcessTreeForPID(
			ruleFailure.GetRuntimeProcessDetails().ContainerID,
			int(ruleFailure.GetRuntimeProcessDetails().ProcessTree.PID),
		)
		if err != nil {
			return err
		}
		runtimeProcessDetails.ProcessTree = tree
		return nil
	}, backoff.NewExponentialBackOff(
		backoff.WithInitialInterval(50*time.Millisecond),
		backoff.WithMaxInterval(200*time.Millisecond),
		backoff.WithMaxElapsedTime(500*time.Millisecond),
	))

	if err != nil {
		if tree, err := utils.CreateProcessTree(&runtimeProcessDetails.ProcessTree, hostPID); err == nil {
			if tree != nil {
				runtimeProcessDetails.ProcessTree = *tree
			} else {
				runtimeProcessDetails = armotypes.ProcessTree{
					ProcessTree: armotypes.Process{
						PID: uint32(ruleFailure.GetRuntimeProcessDetails().ProcessTree.PID),
					},
				}
			}
		}
	}

	ruleFailure.SetRuntimeProcessDetails(runtimeProcessDetails)

	// Enrich RuntimeAlertK8sDetails
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

	return ruleFailure
}

// Checks if the event type is relevant to the rule.
func isEventRelevant(ruleSpec ruleengine.RuleSpec, eventType utils.EventType) bool {
	for _, i := range ruleSpec.RequiredEventTypes() {
		if i == eventType {
			return true
		}
	}
	return false
}
