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
	"errors"
	"fmt"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// tamperKey uniquely identifies a tampered profile occurrence. ResourceVersion
// is included so that an attacker editing the resource (which changes RV) is
// re-flagged on the next reconcile cycle, while a long-lived broken profile
// only emits one R1016 across the cache's lifetime.
func tamperKey(kind, namespace, name, resourceVersion string) string {
	return kind + "|" + namespace + "/" + name + "@" + resourceVersion
}

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
func (c *ContainerProfileCacheImpl) verifyUserApplicationProfile(profile *v1beta1.ApplicationProfile, wlid string) bool {
	if profile == nil {
		return true
	}
	adapter := profiles.NewApplicationProfileAdapter(profile)
	if !signature.IsSigned(adapter) {
		return true
	}
	key := tamperKey("ApplicationProfile", profile.Namespace, profile.Name, profile.ResourceVersion)
	// AllowUntrusted: accept self-signed/local-CA signatures as long as the
	// signature itself verifies against the cert in the annotations. We only
	// want to flag actual tampering, not the absence of a Sigstore Fulcio
	// trust chain. Matches `cmd/sign-object`'s default verifier.
	err := signature.VerifyObjectAllowUntrusted(adapter)
	if err == nil {
		// Verified clean — clear any prior emit so future tampers re-alert.
		c.tamperEmitted.Delete(key)
		return true
	}
	// Classify the error: only ErrSignatureMismatch indicates an actual
	// tamper event. Hash-computation, verifier-construction, and malformed-
	// annotation errors are operational and MUST NOT raise R1016 — that
	// would cause false alerts and, with EnableSignatureVerification=true,
	// drop a valid overlay because of a transient operational failure.
	if !errors.Is(err, signature.ErrSignatureMismatch) {
		logger.L().Warning("user-defined ApplicationProfile signature verification operational error (NOT tamper)",
			helpers.String("profile", profile.Name),
			helpers.String("namespace", profile.Namespace),
			helpers.String("wlid", wlid),
			helpers.Error(err))
		// Honour strict-mode: refuse to load on any verification failure,
		// but do NOT touch the dedup map or emit R1016.
		return !c.cfg.EnableSignatureVerification
	}
	// Real tamper.
	logger.L().Warning("user-defined ApplicationProfile signature mismatch (tamper detected)",
		helpers.String("profile", profile.Name),
		helpers.String("namespace", profile.Namespace),
		helpers.String("wlid", wlid),
		helpers.Error(err))
	// Dedup: emit R1016 only on first transition to invalid for this
	// (kind, ns, name, resourceVersion). Otherwise the refresh loop would
	// alert every reconcile cycle, once per container ref.
	if _, alreadyEmitted := c.tamperEmitted.LoadOrStore(key, struct{}{}); !alreadyEmitted {
		c.emitTamperAlert(profile.Name, profile.Namespace, wlid, "ApplicationProfile", err)
	}
	return !c.cfg.EnableSignatureVerification
}

// verifyUserNetworkNeighborhood is the NN-side counterpart to
// verifyUserApplicationProfile. Same contract, different object kind in
// the alert description.
func (c *ContainerProfileCacheImpl) verifyUserNetworkNeighborhood(nn *v1beta1.NetworkNeighborhood, wlid string) bool {
	if nn == nil {
		return true
	}
	adapter := profiles.NewNetworkNeighborhoodAdapter(nn)
	if !signature.IsSigned(adapter) {
		return true
	}
	key := tamperKey("NetworkNeighborhood", nn.Namespace, nn.Name, nn.ResourceVersion)
	err := signature.VerifyObjectAllowUntrusted(adapter)
	if err == nil {
		c.tamperEmitted.Delete(key)
		return true
	}
	// Same classification as the AP path — only ErrSignatureMismatch is a
	// tamper; everything else is operational and must NOT trigger R1016.
	if !errors.Is(err, signature.ErrSignatureMismatch) {
		logger.L().Warning("user-defined NetworkNeighborhood signature verification operational error (NOT tamper)",
			helpers.String("profile", nn.Name),
			helpers.String("namespace", nn.Namespace),
			helpers.String("wlid", wlid),
			helpers.Error(err))
		return !c.cfg.EnableSignatureVerification
	}
	logger.L().Warning("user-defined NetworkNeighborhood signature mismatch (tamper detected)",
		helpers.String("profile", nn.Name),
		helpers.String("namespace", nn.Namespace),
		helpers.String("wlid", wlid),
		helpers.Error(err))
	if _, alreadyEmitted := c.tamperEmitted.LoadOrStore(key, struct{}{}); !alreadyEmitted {
		c.emitTamperAlert(nn.Name, nn.Namespace, wlid, "NetworkNeighborhood", err)
	}
	return !c.cfg.EnableSignatureVerification
}

// emitTamperAlert sends a single R1016 "Signed profile tampered" alert
// through the rule-alert exporter. No-op when the exporter is unset.
//
// Alert shape mirrors the legacy applicationprofilecache.emitTamperAlert
// (fork commit c2d681e0) so dashboards and component tests keep matching.
// `wlid` should be the authoritative workload identifier the caller has on
// hand (e.g. sharedData.Wlid in containerprofilecache.go) — using the
// runtime containerID instead loses workload kind/name/cluster attribution
// because GenericRuleFailure.SetWorkloadDetails() parses it as a WLID.
func (c *ContainerProfileCacheImpl) emitTamperAlert(profileName, namespace, wlid, objectKind string, verifyErr error) {
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

	ruleFailure.SetWorkloadDetails(wlid)

	c.tamperAlertExporter.SendRuleAlert(ruleFailure)
}
