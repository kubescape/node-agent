package metricsmanager

import (
	"context"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetricsNoop(t *testing.T) {
	m := NewMetricsNoop()
	require.NotNil(t, m)

	assert.NotPanics(t, func() {
		m.Start()
		m.Destroy()
		m.ReportEvent(utils.ExecveEventType)
		m.ReportFailedEvent()
		m.ReportRuleProcessed("R0001")
		m.ReportRulePrefiltered("R0001")
		m.ReportRuleAlert("R0001")
		m.ReportRuleEvaluationTime(context.Background(), "R0001", utils.ExecveEventType, time.Millisecond)
		m.ReportContainerStart()
		m.ReportContainerStop()
		m.ReportDedupEvent(utils.OpenEventType, true)
		m.ReportContainerProfileLegacyLoad("default", "cp-1")
		m.SetContainerProfileCacheEntries("active", 10)
		m.ReportContainerProfileCacheHit(true)
		m.ReportContainerProfileReconcilerDuration("reconcile", time.Second)
		m.ReportContainerProfileReconcilerEviction("expired")
		m.ReportContainerProfileConditionalFetchRequest("get")
		m.ReportContainerProfileConditionalFetchResponse("unchanged")
		m.ReportContainerProfileSplit()
		m.ReportContainerProfileChunkDropped("full")
		m.IncMissingProfileDataRequired("R0001")
		m.IncProjectionUndeclaredLiteral("R0001")
		m.SetProjectionStaleEntries(0)
		m.SetProjectionUndeclaredRules(0)
		m.IncProjectionSpecCompile()
		m.IncProjectionSpecHashChange()
		m.SetProjectionSpecPatterns("exec", "prefix", 5)
		m.SetProjectionSpecAllField("open", false)
		m.ObserveProjectionApplyDuration(time.Millisecond)
		m.IncProjectionReconcileTriggered("rule_update")
		m.IncHelperCall("was_executed")
		m.IncUserDefinedProfileUnresolved("default")
		m.IncUserDefinedProfileAdopted("default")
		m.SetProjectionUndeclaredRulesDetail([]string{"R0001"})
		m.ObserveProfileRawSize(1024)
		m.ObserveProfileProjectedSize(512)
		m.ObserveProfileEntriesRaw("execs", 10)
		m.ObserveProfileEntriesRetained("execs", 5)
		m.ObserveProfileRetentionRatio("execs", 0.5)
		m.ReportSBOMScan("success", "image")
		m.ObserveSBOMScanDuration("success", "image", time.Second)
		m.ReportSBOMScannerRestart()
		m.SetSBOMScannerReady(true)
		m.ReportAlertSuppressed("R0001", "policy")
		m.ReportSandboxPolicyExporterEvents("exec", 1)
		m.ReportSandboxPolicyKernelEvents("exec", 1)
		m.ReportSandboxPolicyDecodeErrors(0)
		m.SetSandboxPolicyKernelStatsComplete(true)
	})
}
