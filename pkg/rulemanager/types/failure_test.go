package types

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/contextdetection"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenericRuleFailure_GettersAndSetters(t *testing.T) {
	failure := &GenericRuleFailure{
		RuleID:    "R0001",
		AlertType: armotypes.AlertTypeRule,
	}

	assert.Equal(t, "R0001", failure.GetRuleId())
	assert.Equal(t, armotypes.AlertTypeRule, failure.GetAlertType())

	baseAlert := armotypes.BaseRuntimeAlert{
		AlertName: "Unexpected process launched",
		Severity:  8,
	}
	failure.SetBaseRuntimeAlert(baseAlert)
	assert.Equal(t, baseAlert, failure.GetBaseRuntimeAlert())

	procDetails := armotypes.ProcessTree{
		ProcessTree: armotypes.Process{
			PID:  1234,
			Comm: "curl",
		},
		ContainerID: "cid-123",
	}
	failure.SetRuntimeProcessDetails(procDetails)
	assert.Equal(t, procDetails, failure.GetRuntimeProcessDetails())

	triggerEv := &utils.StructEvent{ContainerID: "cid-123", Comm: "curl"}
	failure.SetTriggerEvent(triggerEv)
	require.NotNil(t, failure.GetTriggerEvent())
	assert.Equal(t, "cid-123", failure.GetTriggerEvent().GetContainerID())

	ruleAlert := armotypes.RuleAlert{RuleDescription: "Process curl executed"}
	failure.SetRuleAlert(ruleAlert)
	assert.Equal(t, ruleAlert, failure.GetRuleAlert())

	k8sDetails := armotypes.RuntimeAlertK8sDetails{
		Namespace: "default",
		PodName:   "web-0",
	}
	failure.SetRuntimeAlertK8sDetails(k8sDetails)
	assert.Equal(t, k8sDetails, failure.GetRuntimeAlertK8sDetails())

	ecsDetails := armotypes.RuntimeAlertECSDetails{
		ClusterName: "ecs-prod",
	}
	failure.SetRuntimeAlertEcsDetails(ecsDetails)
	assert.Equal(t, ecsDetails, failure.GetRuntimeAlertEcsDetails())

	failure.SetCloudServices([]string{"aws-s3", "aws-dynamodb"})
	assert.Equal(t, []string{"aws-s3", "aws-dynamodb"}, failure.GetCloudServices())

	failure.SetAlertPlatform(armotypes.AlertSourcePlatformK8sAgent)
	assert.Equal(t, armotypes.AlertSourcePlatformK8sAgent, failure.GetAlertPlatform())

	failure.SetExtra(map[string]string{"key": "val"})
	assert.Equal(t, map[string]string{"key": "val"}, failure.GetExtra())

	failure.SetIsTriggerAlert(true)
	assert.True(t, failure.GetIsTriggerAlert())

	failure.SetSourceContext(contextdetection.Kubernetes)
	assert.Equal(t, contextdetection.Kubernetes, failure.GetSourceContext())

	httpAlert := armotypes.HttpRuleAlert{
		SourcePodInfo: armotypes.PodInfo{
			ClusterName: "prod-cluster",
		},
	}
	failure.SetHttpRuleAlert(httpAlert)
	assert.Equal(t, httpAlert, failure.GetHttpRuleAlert())
	assert.Equal(t, armotypes.AlertTypeHttpRule, failure.GetAlertType())
}

func TestGenericRuleFailure_SetWorkloadDetails(t *testing.T) {
	t.Run("empty workload details is a no-op", func(t *testing.T) {
		failure := &GenericRuleFailure{
			RuntimeAlertK8sDetails: armotypes.RuntimeAlertK8sDetails{
				ClusterName:       "orig-cluster",
				WorkloadKind:      "orig-kind",
				WorkloadNamespace: "orig-ns",
				WorkloadName:      "orig-name",
			},
		}
		failure.SetWorkloadDetails("")
		assert.Equal(t, "orig-cluster", failure.RuntimeAlertK8sDetails.ClusterName)
		assert.Equal(t, "orig-kind", failure.RuntimeAlertK8sDetails.WorkloadKind)
		assert.Equal(t, "orig-ns", failure.RuntimeAlertK8sDetails.WorkloadNamespace)
		assert.Equal(t, "orig-name", failure.RuntimeAlertK8sDetails.WorkloadName)
	})

	t.Run("valid wlid populates cluster, kind, namespace and name", func(t *testing.T) {
		failure := &GenericRuleFailure{}
		failure.SetWorkloadDetails("wlid://cluster-prod/namespace-payments/deployment-api")
		assert.Equal(t, "prod", failure.RuntimeAlertK8sDetails.ClusterName)
		assert.Equal(t, "Deployment", failure.RuntimeAlertK8sDetails.WorkloadKind)
		assert.Equal(t, "payments", failure.RuntimeAlertK8sDetails.WorkloadNamespace)
		assert.Equal(t, "api", failure.RuntimeAlertK8sDetails.WorkloadName)
	})
}
