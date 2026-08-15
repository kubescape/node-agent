package metricsmanager

import (
	"context"
	"time"

	"github.com/kubescape/node-agent/pkg/utils"
)

// MetricsManager is an interface for reporting metrics
type MetricsManager interface {
	Start()
	Destroy()
	ReportEvent(eventType utils.EventType)
	ReportFailedEvent()
	ReportRuleProcessed(ruleID string)
	ReportRulePrefiltered(ruleName string)
	ReportRuleAlert(ruleID string)
	ReportRuleEvaluationTime(ctx context.Context, ruleID string, eventType utils.EventType, duration time.Duration)
	//ReportEbpfStats(stats *top.Event[toptypes.Stats])
	ReportContainerStart()
	ReportContainerStop()
	ReportDedupEvent(eventType utils.EventType, duplicate bool)
	ReportContainerProfileLegacyLoad(kind, completeness string)
	SetContainerProfileCacheEntries(kind string, count float64)
	ReportContainerProfileCacheHit(hit bool)
	ReportContainerProfileReconcilerDuration(phase string, duration time.Duration)
	ReportContainerProfileReconcilerEviction(reason string)
	// ReportContainerProfileSplit counts chunks halved after a transport-level size rejection.
	ReportContainerProfileSplit()
	// ReportContainerProfileChunkDropped counts chunks discarded because they could not be
	// split further, labeled by the queue's closed set of drop reasons.
	ReportContainerProfileChunkDropped(reason string)

	// Profile-projection metrics — always-on.
	IncMissingProfileDataRequired(ruleID string)  // rule has profileDependency>0 but no profileDataRequired
	IncProjectionUndeclaredLiteral(helper string) // literal evaluated against a projected field not in spec
	SetProjectionStaleEntries(count float64)      // cache entries whose SpecHash != currentSpecHash
	SetProjectionUndeclaredRules(count float64)   // rules loaded with no profileDataRequired

	// Profile-projection metrics — detailed (gated by profileProjection.detailedMetricsEnabled).
	IncProjectionSpecCompile()
	IncProjectionSpecHashChange()
	SetProjectionSpecPatterns(field, kind string, count float64)
	SetProjectionSpecAllField(field string, isAll bool)
	ObserveProjectionApplyDuration(d time.Duration)
	IncProjectionReconcileTriggered(trigger string)
	IncHelperCall(helper string)
	IncUserDefinedProfileUnresolved(namespace string) // user-defined-profile label set but no ContainerProfile resolved (silent-upgrade visibility)
	IncUserDefinedProfileAdopted(namespace string)    // an authored ContainerProfile was adopted as the authoritative base for a container
	SetProjectionUndeclaredRulesDetail(ruleIDs []string)

	// Memory-savings metrics — detailed (gated by profileProjection.detailedMetricsEnabled).
	ObserveProfileRawSize(bytes float64)
	ObserveProfileProjectedSize(bytes float64)
	ObserveProfileEntriesRaw(field string, count float64)
	ObserveProfileEntriesRetained(field string, count float64)
	ObserveProfileRetentionRatio(field string, ratio float64)

	// SBOM scan metrics.
	ReportSBOMScan(status string)
	ObserveSBOMScanDuration(status string, d time.Duration)
	ReportSBOMScannerRestart()
	SetSBOMScannerReady(ready bool)

	// Alert suppression funnel — counts how many alerts were dropped and why.
	ReportAlertSuppressed(ruleID, reason string)
}
