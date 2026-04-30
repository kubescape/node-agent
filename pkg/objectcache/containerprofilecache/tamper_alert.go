// Tamper detection for user-supplied profile overlays loaded into the
// ContainerProfileCache.
//
// When a user references a signed ApplicationProfile or NetworkNeighborhood
// via the `kubescape.io/user-defined-profile` pod label, this code path
// re-verifies the signature on every cache load and emits an R1016
// "Signed profile tampered" alert via the rule-alert exporter when the
// signature is present but no longer valid.
//
// This is the new home of the legacy applicationprofilecache's tamper
// detection (originally introduced in fork commit c2d681e0 — "Feat/
// tamperalert"). Upstream PR #788 deleted the legacy cache; this re-wires
// the same behavior onto containerprofilecache without changing the alert
// shape so existing component tests (Test_31_TamperDetectionAlert) keep
// working.
package containerprofilecache

import (
	"fmt"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// SetTamperAlertExporter wires the rule-alert exporter used to emit R1016.
// Optional — when nil, signature verification still runs (and is logged)
// but no alert is emitted. Production wiring lives in cmd/main.go after the
// alert exporter is constructed.
func (c *ContainerProfileCacheImpl) SetTamperAlertExporter(e exporters.Exporter) {
	c.tamperAlertExporter = e
}

// verifyUserApplicationProfile re-verifies the signature of a user-supplied
// ApplicationProfile overlay and emits R1016 if the signature is present
// but no longer valid (i.e. the profile was tampered after signing).
//
// Returns true iff the profile is acceptable for further use:
//   - profile is signed and verifies → true
//   - profile is not signed → true (signing is opt-in; the empty-signature
//     case is handled by the caller's normal not-signed flow)
//   - profile is signed but verification fails → false (and R1016 emitted)
//
// The boolean lets the caller decide whether to project the overlay into
// the cache. Today we always proceed (the legacy semantics don't actually
// gate loading on verification unless EnableSignatureVerification is true),
// but having the return value keeps the door open for stricter modes.
func (c *ContainerProfileCacheImpl) verifyUserApplicationProfile(profile *v1beta1.ApplicationProfile, containerID string) bool {
	if profile == nil {
		return true
	}
	adapter := profiles.NewApplicationProfileAdapter(profile)
	if !signature.IsSigned(adapter) {
		return true
	}
	if err := signature.VerifyObject(adapter); err != nil {
		logger.L().Warning("user-defined ApplicationProfile signature verification failed (tamper detected)",
			helpers.String("profile", profile.Name),
			helpers.String("namespace", profile.Namespace),
			helpers.String("containerID", containerID),
			helpers.Error(err))
		c.emitTamperAlert(profile.Name, profile.Namespace, containerID, "ApplicationProfile", err)
		return !c.cfg.EnableSignatureVerification
	}
	return true
}

// verifyUserNetworkNeighborhood is the NN-side counterpart to
// verifyUserApplicationProfile. Same contract, different object kind in
// the alert description.
func (c *ContainerProfileCacheImpl) verifyUserNetworkNeighborhood(nn *v1beta1.NetworkNeighborhood, containerID string) bool {
	if nn == nil {
		return true
	}
	adapter := profiles.NewNetworkNeighborhoodAdapter(nn)
	if !signature.IsSigned(adapter) {
		return true
	}
	if err := signature.VerifyObject(adapter); err != nil {
		logger.L().Warning("user-defined NetworkNeighborhood signature verification failed (tamper detected)",
			helpers.String("profile", nn.Name),
			helpers.String("namespace", nn.Namespace),
			helpers.String("containerID", containerID),
			helpers.Error(err))
		c.emitTamperAlert(nn.Name, nn.Namespace, containerID, "NetworkNeighborhood", err)
		return !c.cfg.EnableSignatureVerification
	}
	return true
}

// emitTamperAlert sends a single R1016 "Signed profile tampered" alert
// through the rule-alert exporter. No-op when the exporter is unset.
//
// Alert shape mirrors the legacy applicationprofilecache.emitTamperAlert
// (fork commit c2d681e0) so dashboards and component tests keep matching.
func (c *ContainerProfileCacheImpl) emitTamperAlert(profileName, namespace, containerID, objectKind string, verifyErr error) {
	if c.tamperAlertExporter == nil {
		return
	}

	ruleFailure := &types.GenericRuleFailure{
		BaseRuntimeAlert: armotypes.BaseRuntimeAlert{
			AlertName:      "Signed profile tampered",
			InfectedPID:    1,
			Severity:       10,
			FixSuggestions: "Investigate who modified the " + objectKind + " '" + profileName + "' in namespace '" + namespace + "'. Re-sign the profile after verifying its contents.",
		},
		AlertType: armotypes.AlertTypeRule,
		RuntimeProcessDetails: armotypes.ProcessTree{
			ProcessTree: armotypes.Process{
				PID:  1,
				Comm: "node-agent",
			},
		},
		RuleAlert: armotypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Signed %s '%s' in namespace '%s' has been tampered with: %v",
				objectKind, profileName, namespace, verifyErr),
		},
		RuntimeAlertK8sDetails: armotypes.RuntimeAlertK8sDetails{
			Namespace: namespace,
		},
		RuleID: "R1016",
	}

	// Best-effort workload identifier. The legacy cache used a wlid string;
	// this cache is keyed on containerID, so we just stash that as the
	// workload reference. Downstream consumers (Alertmanager, exporter
	// pipelines) don't structurally depend on the wlid prefix.
	ruleFailure.SetWorkloadDetails(extractWlidFromContainerID(containerID))

	c.tamperAlertExporter.SendRuleAlert(ruleFailure)
}

// extractWlidFromContainerID is a placeholder that returns the containerID
// as-is. The legacy cache had a richer "wlid://<cluster>/<namespace>/<kind>/
// <name>/<templateHash>" string available; the new cache is keyed on
// containerID so callers that consume wlid get an opaque identifier here.
// Retained as a separate function so the alert path can be upgraded to a
// proper wlid lookup later without touching emitTamperAlert.
func extractWlidFromContainerID(containerID string) string {
	if idx := strings.LastIndex(containerID, "/"); idx > 0 {
		return containerID[:idx]
	}
	return containerID
}
