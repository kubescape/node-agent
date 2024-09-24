package nodeprofilemanager

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/nodeprofilemanager"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	"github.com/kubescape/node-agent/pkg/utils"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"golang.org/x/net/context"
	v1 "k8s.io/api/core/v1"
)

type NodeProfileManager struct {
	clusterData    armometadata.ClusterConfig
	config         config.Config
	httpClient     *http.Client
	k8sObjectCache objectcache.K8sObjectCache
	nodeName       string
	ruleManager    rulemanager.RuleManagerClient
}

func NewNodeProfileManager(config config.Config, clusterData armometadata.ClusterConfig, nodeName string, k8sObjectCache objectcache.K8sObjectCache, ruleManager rulemanager.RuleManagerClient) *NodeProfileManager {
	return &NodeProfileManager{
		clusterData: clusterData,
		config:      config,
		httpClient: &http.Client{
			Timeout: time.Duration(config.Exporters.HTTPExporterConfig.TimeoutSeconds) * time.Second,
		},
		k8sObjectCache: k8sObjectCache,
		nodeName:       nodeName,
		ruleManager:    ruleManager,
	}
}

var _ nodeprofilemanager.NodeProfileManagerClient = (*NodeProfileManager)(nil)

func (n *NodeProfileManager) Start(ctx context.Context) {
	go func() {
		time.Sleep(utils.AddJitter(n.config.InitialDelay, n.config.MaxJitterPercentage))
		for {
			time.Sleep(n.config.NodeProfileInterval)
			profile, err := n.getProfile()
			if err != nil {
				logger.L().Ctx(ctx).Warning("get profile error", helpers.Error(err))
			} else {
				err := n.sendProfile(profile)
				if err != nil {
					logger.L().Ctx(ctx).Warning("send profile error", helpers.Error(err))
				}
			}
		}
	}()
}

func (n *NodeProfileManager) getProfile() (*armotypes.NodeProfile, error) {
	profile := &armotypes.NodeProfile{
		PodStatuses:             []armotypes.PodStatus{},
		CurrentState:            "Running",
		NodeAgentRunning:        true,
		RuntimeDetectionEnabled: n.config.EnableRuntimeDetection,
	}
	for _, pod := range n.k8sObjectCache.GetPods() {
		var app string
		if pod.Labels != nil {
			for _, k := range []string{"app", "app.kubernetes.io/name"} {
				if v, ok := pod.Labels[k]; ok {
					app = v
					break
				}
			}
		}
		state, reason, message, transitionTime := getPodState(pod.Status.Conditions)
		statusesMap := mapContainerStatuses(utils.GetContainerStatuses(pod.Status))
		podStatus := armotypes.PodStatus{
			CustomerGUID:               n.clusterData.AccountID,
			Cluster:                    n.clusterData.ClusterName,
			ResourceHash:               "", // filled on backend side
			ResourceVersion:            pod.ResourceVersion,
			Name:                       pod.Name,
			Namespace:                  pod.Namespace,
			NodeName:                   n.nodeName,
			App:                        app,
			Phase:                      string(pod.Status.Phase),
			CurrentState:               state,
			LastStateReason:            reason,
			LastStateMessage:           message,
			LastStateTransitionTime:    transitionTime,
			CreationTimestamp:          pod.CreationTimestamp.Time,
			Containers:                 n.getContainers(pod.Namespace, pod.Name, pod.Spec.Containers, statusesMap),
			InitContainers:             n.getContainers(pod.Namespace, pod.Name, pod.Spec.InitContainers, statusesMap),
			EphemeralContainers:        n.getEphemeralContainers(pod.Namespace, pod.Name, pod.Spec.EphemeralContainers, statusesMap),
			HasFinalApplicationProfile: n.ruleManager.HasFinalApplicationProfile(pod),
			HasApplicableRuleBindings:  n.ruleManager.HasApplicableRuleBindings(pod.Namespace, pod.Name),
			IsKDRMonitored:             n.ruleManager.IsPodMonitored(pod.Namespace, pod.Name),
		}
		profile.PodStatuses = append(profile.PodStatuses, podStatus)
	}
	return profile, nil
}

func getContainerState(state v1.ContainerState) (string, time.Time, time.Time, int) {
	if state.Running != nil {
		return "Running", state.Running.StartedAt.Time, time.Time{}, 0
	}
	if state.Terminated != nil {
		return "Terminated", state.Terminated.StartedAt.Time, state.Terminated.FinishedAt.Time, int(state.Terminated.ExitCode)
	}
	if state.Waiting != nil {
		return "Waiting", time.Time{}, time.Time{}, 0
	}
	return "Unknown", time.Time{}, time.Time{}, 0
}

func getPodState(conditions []v1.PodCondition) (string, string, string, time.Time) {
	for _, c := range conditions {
		if c.Type == v1.PodReady && c.Status == v1.ConditionTrue {
			return string(c.Type), c.Reason, c.Message, c.LastTransitionTime.Time
		}
	}
	return "", "", "", time.Time{}
}

func mapContainerStatuses(statuses []v1.ContainerStatus) map[string]v1.ContainerStatus {
	statusesMap := make(map[string]v1.ContainerStatus)
	for _, s := range statuses {
		statusesMap[s.Name] = s
	}
	return statusesMap
}

func (n *NodeProfileManager) getContainers(namespace, name string, containers []v1.Container, statusesMap map[string]v1.ContainerStatus) []armotypes.PodContainer {
	var podContainers []armotypes.PodContainer
	for _, c := range containers {
		podContainers = n.appendPodContainer(namespace, name, c, statusesMap, podContainers)
	}
	return podContainers
}

func (n *NodeProfileManager) getEphemeralContainers(namespace, name string, containers []v1.EphemeralContainer, statusesMap map[string]v1.ContainerStatus) []armotypes.PodContainer {
	var podContainers []armotypes.PodContainer
	for _, c := range containers {
		podContainers = n.appendPodContainer(namespace, name, v1.Container(c.EphemeralContainerCommon), statusesMap, podContainers)
	}
	return podContainers
}

// TODO rewrite with podutil.VisitContainers()
func (n *NodeProfileManager) appendPodContainer(namespace string, name string, c v1.Container, statusesMap map[string]v1.ContainerStatus, podContainers []armotypes.PodContainer) []armotypes.PodContainer {
	k8sContainerID := utils.CreateK8sContainerID(namespace, name, c.Name)
	status := statusesMap[c.Name]
	state, started, finished, exitCode := getContainerState(status.State)
	podContainers = append(podContainers, armotypes.PodContainer{
		Name:                c.Name,
		Image:               c.Image,
		IsKDRMonitored:      n.ruleManager.IsContainerMonitored(k8sContainerID),
		CurrentState:        state,
		LastStateExitCode:   exitCode,
		LastStateFinishedAt: finished,
		LastStateStartedAt:  started,
		RestartCount:        int(status.RestartCount),
	})
	return podContainers
}

func (n *NodeProfileManager) sendProfile(profile *armotypes.NodeProfile) error {
	// create a GenericCRD with NodeProfile as Spec
	crd := armotypes.GenericCRD[armotypes.NodeProfile]{
		Kind:       "NodeProfiles",
		ApiVersion: "kubescape.io/v1",
		Metadata: armotypes.Metadata{
			Name: n.nodeName,
		},
		Spec: *profile,
	}
	// create the JSON representation of the crd
	bodyBytes, err := json.Marshal(crd)
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}
	bodyReader := bytes.NewReader(bodyBytes)
	// prepare the request
	req, err := http.NewRequest(n.config.Exporters.HTTPExporterConfig.Method,
		n.config.Exporters.HTTPExporterConfig.URL+"/v1/nodeprofiles", bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	for key, value := range n.config.Exporters.HTTPExporterConfig.Headers {
		req.Header.Set(key, value)
	}
	// send the request
	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("non-2xx status code: %d", resp.StatusCode)
	}
	// discard the body
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return fmt.Errorf("clear response body: %w", err)
	}
	return nil
}
