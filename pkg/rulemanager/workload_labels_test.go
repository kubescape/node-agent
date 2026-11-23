package rulemanager

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/hashicorp/golang-lru/v2/expirable"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/contextdetection/detectors"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecooldown"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const stepJobWlid = "wlid://cluster-test/namespace-test/job-step"

type alertCapturingExporter struct {
	exporters.ExporterMock
	alerts []types.RuleFailure
}

func (e *alertCapturingExporter) SendRuleAlert(failure types.RuleFailure) {
	e.alerts = append(e.alerts, failure)
}

// newAlertingRuleManager returns a rule manager with one rule that fires on
// every exec event of the pod test/pod, and the exporter that gets its alerts.
func newAlertingRuleManager() (*RuleManager, *alertCapturingExporter) {
	exporter := &alertCapturingExporter{}
	rule := typesv1.Rule{
		ID: "R1000", Enabled: true, ProfileDependency: armotypes.NotRequired,
		Tags:        []string{"context:container"},
		Expressions: typesv1.RuleExpressions{RuleExpression: []typesv1.RuleExpression{{EventType: utils.ExecveEventType, Expression: "true"}}},
	}
	rm := &RuleManager{
		ctx:                context.Background(),
		cfg:                config.Config{},
		trackedContainers:  mapset.NewSet[string](),
		detectorManager:    detectors.NewDetectorManager(nil),
		ruleBindingCache:   &profileGateBindings{rules: []typesv1.Rule{rule}},
		objectCache:        &stateObjectCacheFake{cpc: &profileGateCache{}},
		celEvaluator:       &profileGateEvaluator{},
		exporter:           exporter,
		metrics:            &profileGateMetrics{},
		ruleCooldown:       rulecooldown.NewRuleCooldown(rulecooldown.RuleCooldownConfig{Disabled: true, MaxSize: 1}),
		alertLogDedup:      expirable.NewLRU[string, struct{}](1, nil, 0),
		ruleFailureCreator: profileGateFailureCreator{},
	}
	return rm, exporter
}

func alertDetails(t *testing.T, exporter *alertCapturingExporter) (armotypes.RuntimeAlertK8sDetails, string) {
	t.Helper()
	require.Len(t, exporter.alerts, 1)
	details := exporter.alerts[0].GetRuntimeAlertK8sDetails()
	raw, err := json.Marshal(details)
	require.NoError(t, err)
	return details, string(raw)
}

// An alert carries the labels of the pod's top-level workload: absent when the
// pod is its own workload, and {} when the owner has no labels.
func TestWorkloadLabelsOnAlert(t *testing.T) {
	for _, tc := range []struct {
		name     string
		wlid     string
		labels   map[string]string
		wantKind string
		wantJSON string
	}{
		{"the workload is the pod", "wlid://cluster-test/namespace-test/pod-pod", nil, "Pod", ""},
		{"owner with labels", stepJobWlid, map[string]string{"runner-pod": "runner-1"}, "Job", `"workloadLabels":{"runner-pod":"runner-1"}`},
		{"owner with no labels", stepJobWlid, map[string]string{}, "Job", `"workloadLabels":{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rm, exporter := newAlertingRuleManager()
			shared := &objectcache.WatchedContainerData{Wlid: tc.wlid, WorkloadLabels: tc.labels}
			require.True(t, rm.bindPodWorkload("test/pod", shared))

			rm.ReportEnrichedEvent(&events.EnrichedEvent{Event: profileGateEvent{}, ContainerID: "cid"})

			details, raw := alertDetails(t, exporter)
			assert.Equal(t, tc.wantKind, details.WorkloadKind)
			if tc.labels == nil {
				assert.Nil(t, details.WorkloadLabels)
				assert.NotContains(t, raw, "workloadLabels")
				return
			}
			assert.Equal(t, tc.labels, details.WorkloadLabels)
			assert.Contains(t, raw, tc.wantJSON)

			// The alert holds its own copy, and so does the rule manager.
			details.WorkloadLabels["changed"] = "x"
			shared.WorkloadLabels["changed"] = "x"
			stored, _ := rm.podToWorkload.Load("test/pod")
			assert.NotContains(t, stored.workloadLabels, "changed")
		})
	}
}

// An event of a container can be evaluated after the container was removed: the
// container watcher has then deleted the shared container data, while the rule
// manager keeps the workload identity of the pod. The alert must not name the
// workload and leave out its labels, because a consumer reads that as an agent
// that predates the field.
func TestWorkloadLabelsOnAlertAfterContainerRemoval(t *testing.T) {
	rm, exporter := newAlertingRuleManager()
	labels := map[string]string{"runner-pod": "runner-1"}
	require.True(t, rm.bindPodWorkload("test/pod", &objectcache.WatchedContainerData{Wlid: stepJobWlid, WorkloadLabels: labels}))

	container := &containercollection.Container{}
	container.Runtime.ContainerID = "cid"
	container.K8s.Namespace, container.K8s.PodName, container.K8s.ContainerName = "test", "pod", "app"
	rm.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeRemoveContainer, Container: container})

	// The object cache of this rule manager holds no shared container data, as
	// after the removal.
	rm.ReportEnrichedEvent(&events.EnrichedEvent{Event: profileGateEvent{}, ContainerID: "cid"})

	details, raw := alertDetails(t, exporter)
	assert.Equal(t, "Job", details.WorkloadKind)
	assert.Equal(t, "step", details.WorkloadName)
	assert.Equal(t, labels, details.WorkloadLabels)
	assert.Contains(t, raw, `"workloadLabels":{"runner-pod":"runner-1"}`)
}

// expiringFailureCreator unbinds the pod while the alert is created: after the
// event loaded the binding, and before the labels are put on the alert.
type expiringFailureCreator struct {
	rm *RuleManager
}

func (c expiringFailureCreator) CreateRuleFailure(typesv1.Rule, *events.EnrichedEvent, objectcache.ObjectCache, string, string, string, map[string]any) types.RuleFailure {
	c.rm.unbindPodWorkload("test/pod")
	return &types.GenericRuleFailure{}
}

// The binding of a pod can expire while an event of the pod is evaluated. The
// event loaded the binding once, so its alert still gets the identity and the
// labels of the same binding.
func TestWorkloadLabelsOnAlertWhenTheBindingExpiresDuringTheEvent(t *testing.T) {
	rm, exporter := newAlertingRuleManager()
	rm.ruleFailureCreator = expiringFailureCreator{rm: rm}
	labels := map[string]string{"runner-pod": "runner-1"}
	require.True(t, rm.bindPodWorkload("test/pod", &objectcache.WatchedContainerData{Wlid: stepJobWlid, WorkloadLabels: labels}))

	rm.ReportEnrichedEvent(&events.EnrichedEvent{Event: profileGateEvent{}, ContainerID: "cid"})

	assert.False(t, rm.podToWorkload.Has("test/pod"), "the binding expired during the event")
	details, raw := alertDetails(t, exporter)
	assert.Equal(t, "Job", details.WorkloadKind)
	assert.Equal(t, "step", details.WorkloadName)
	assert.Equal(t, labels, details.WorkloadLabels)
	assert.Contains(t, raw, `"workloadLabels":{"runner-pod":"runner-1"}`)
}

// The identity and the labels of a pod are one binding: published together by
// the pod's first container, and forgotten together.
func TestBindPodWorkload(t *testing.T) {
	rm, _ := newAlertingRuleManager()

	assert.False(t, rm.bindPodWorkload("test/pod", &objectcache.WatchedContainerData{WorkloadLabels: map[string]string{"a": "b"}}),
		"no identity, so nothing is bound")
	assert.False(t, rm.podToWorkload.Has("test/pod"), "labels are never kept without the identity")

	require.True(t, rm.bindPodWorkload("test/pod", &objectcache.WatchedContainerData{Wlid: stepJobWlid, WorkloadLabels: map[string]string{"a": "b"}}))
	first, _ := rm.podToWorkload.Load("test/pod")
	// A later container of the same pod does not replace the binding.
	require.True(t, rm.bindPodWorkload("test/pod", &objectcache.WatchedContainerData{Wlid: "wlid://cluster-test/namespace-test/job-other", WorkloadLabels: map[string]string{"c": "d"}}))
	binding, _ := rm.podToWorkload.Load("test/pod")
	assert.Same(t, first, binding)
	assert.Equal(t, stepJobWlid, binding.wlid)
	assert.Equal(t, map[string]string{"a": "b"}, binding.workloadLabels)

	rm.unbindPodWorkload("test/pod")
	assert.False(t, rm.podToWorkload.Has("test/pod"))
}
