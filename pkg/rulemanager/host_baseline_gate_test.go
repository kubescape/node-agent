package rulemanager

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/contextdetection/detectors"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/objectcache/containerprofilecache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/node-agent/pkg/rulebindingmanager"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type hostBaselineRules struct {
	rulebindingmanager.RuleBindingCacheMock
	creator *rulecreator.RuleCreatorMock
}

func (r *hostBaselineRules) GetRuleCreator() rulecreator.RuleCreator { return r.creator }

// Observe the real evaluator's decision; stop only at presentation/export,
// which is outside this runtime-baseline regression's scope.
type hostBaselineEvaluator struct {
	*cel.CEL
	decisions []bool
}

func (e *hostBaselineEvaluator) EvaluateRuleWithContext(ctx map[string]any, kind utils.EventType, expressions []typesv1.RuleExpression) (bool, error) {
	result, err := e.CEL.EvaluateRuleWithContext(ctx, kind, expressions)
	e.decisions = append(e.decisions, result)
	return result, err
}
func (e *hostBaselineEvaluator) EvaluateExpression(*events.EnrichedEvent, string) (string, error) {
	return "", errors.New("test stops after runtime decision, before presentation")
}

type hostBaselineStorage struct{ profile *v1beta1.ContainerProfile }

func (s hostBaselineStorage) GetContainerProfile(_ context.Context, namespace, name string) (*v1beta1.ContainerProfile, error) {
	if s.profile != nil && namespace == s.profile.Namespace && name == s.profile.Name {
		return s.profile, nil
	}
	return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "containerprofiles"}, name)
}

func TestCanonicalHostRequiredProfileGate(t *testing.T) {
	identity := armotypes.KubernetesHostIdentity{Version: 1, ClusterUID: "cluster", ClusterName: "cluster-a", NodeUID: "node-uid", NodeName: "node-a"}
	var err error
	identity.MachineFingerprint, err = armotypes.KubernetesHostMachineFingerprint("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	identity.Key, err = armotypes.KubernetesHostKey(identity.ClusterUID, identity.NodeUID, identity.MachineFingerprint)
	require.NoError(t, err)
	data := hostidentity.BuildKubernetesHostWatchedContainerData(identity)
	child, err := data.InstanceID.GetSlug(false)
	require.NoError(t, err)
	for _, tc := range []struct {
		name, status string
		canonical    bool
		dependency   armotypes.ProfileDependency
		syscall      string
		decisions    []bool
	}{
		{"learning required", helpersv1.Learning, true, armotypes.Required, "execve", nil},
		{"replacement missing required", "", true, armotypes.Required, "execve", nil},
		{"completed learned", helpersv1.Completed, true, armotypes.Required, "openat", []bool{false}},
		{"completed unseen", helpersv1.Completed, true, armotypes.Required, "execve", []bool{true}},
		{"legacy host remains unchanged", "", false, armotypes.Required, "execve", []bool{true}},
		{"canonical optional remains evaluated", "", true, armotypes.Optional, "execve", []bool{true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Config{HostMonitoringEnabled: true, RequireKubernetesHostIdentity: tc.canonical, NamespaceName: "kubescape"}
			var profile *v1beta1.ContainerProfile
			if tc.status != "" {
				profile = &v1beta1.ContainerProfile{Name: child, Namespace: "kubescape", ResourceVersion: "1", Annotations: map[string]string{helpersv1.StatusMetadataKey: tc.status, helpersv1.CompletionMetadataKey: helpersv1.Full}, Spec: v1beta1.ContainerProfileSpec{Syscalls: []string{"openat"}}}
			}
			k8s := &objectcache.K8sObjectCacheMock{}
			currentData := data
			if tc.name == "replacement missing required" {
				replacement := identity
				replacement.NodeUID = "replacement-node-uid"
				replacement.Key, err = armotypes.KubernetesHostKey(replacement.ClusterUID, replacement.NodeUID, replacement.MachineFingerprint)
				require.NoError(t, err)
				require.NotEqual(t, identity.Key, replacement.Key)
				currentData = hostidentity.BuildKubernetesHostWatchedContainerData(replacement)
				// The predecessor remains in storage, but is not the replacement's baseline.
				profile = &v1beta1.ContainerProfile{Name: child, Namespace: "kubescape", ResourceVersion: "1", Annotations: map[string]string{helpersv1.StatusMetadataKey: helpersv1.Completed, helpersv1.CompletionMetadataKey: helpersv1.Full}, Spec: v1beta1.ContainerProfileSpec{Syscalls: []string{"openat"}}}
			}
			k8s.SetSharedContainerData(armotypes.HostContainerID, currentData)
			cache := containerprofilecache.NewContainerProfileCache(cfg, hostBaselineStorage{profile}, k8s, nil)
			cache.SetProjectionSpec(objectcache.RuleProjectionSpec{Hash: "syscalls", Syscalls: objectcache.FieldSpec{InUse: true, All: true}})
			container := &containercollection.Container{}
			container.Runtime.ContainerID = armotypes.HostContainerID
			container.Runtime.ContainerPID = 1
			cache.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeAddContainer, Container: container})
			if tc.status == helpersv1.Completed {
				require.Eventually(t, func() bool { return cache.GetProjectedContainerProfile(armotypes.HostContainerID) != nil }, time.Second, time.Millisecond)
			}
			objects := objectcachev1.NewObjectCache(k8s, cache, nil)
			realCEL, err := cel.NewCEL(objects, cfg)
			require.NoError(t, err)
			evaluator := &hostBaselineEvaluator{CEL: realCEL}
			rule := typesv1.Rule{Enabled: true, ID: "unexpected-syscall", Tags: []string{"context:host"}, ProfileDependency: tc.dependency, Expressions: typesv1.RuleExpressions{RuleExpression: []typesv1.RuleExpression{{EventType: utils.SyscallEventType, Expression: `!cp.was_syscall_used("host", event.syscallName)`}}}}
			rm := &RuleManager{ctx: t.Context(), cfg: cfg, objectCache: objects, celEvaluator: evaluator, metrics: metricsmanager.NewMetricsMock(), ruleBindingCache: &hostBaselineRules{creator: &rulecreator.RuleCreatorMock{Rules: []typesv1.Rule{rule}}}}
			rm.ReportEnrichedEvent(&events.EnrichedEvent{ContainerID: armotypes.HostContainerID, SourceContext: &detectors.HostContextInfo{HostName: "node-a"}, Event: &utils.StructEvent{ContainerID: armotypes.HostContainerID, EventType: utils.SyscallEventType, Syscall: tc.syscall}})
			require.Equal(t, tc.decisions, evaluator.decisions)
		})
	}
}
