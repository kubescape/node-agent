//go:build experimental_signing

// Tamper detection for user-supplied ContainerProfile overlays loaded into the
// ContainerProfileCache.
//
// When a pod references a signed ContainerProfile via the
// `kubescape.io/user-defined-profile` label, this path re-verifies the
// signature on every cache load and emits an R1016 "Signed profile tampered"
// alert via the rule-alert exporter when the signature is present but no longer
// valid (the profile was modified after signing).
//
// AP/NN → ContainerProfile note: this replaces the legacy pair of verify
// methods (verifyUserApplicationProfile + verifyUserNetworkNeighborhood) with a
// single verifyUserContainerProfile — one fetch, one verify, one R1016 site —
// because a ContainerProfile is the unified successor to the AP+NN overlay
// pair. The R1016 alert shape is unchanged so existing component tests
// (Test_31_TamperDetectionAlert) keep matching.
package containerprofilecache

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

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
// Optional — when nil, signature verification still runs (and is logged) but no
// alert is emitted. Production wiring lives in cmd/main.go after the alert
// exporter is constructed.
func (c *ContainerProfileCacheImpl) SetTamperAlertExporter(e exporters.Exporter) {
	c.tamperAlertExporter = e
}

// verifyVerdict maps a signature check to its truth-table state (A5-A8).
type verifyVerdict int

const (
	verifyOK              verifyVerdict = iota // signed+verifies, or unsigned handled by caller mode
	verifyUnsigned                             // no signature present (A5)
	verifyTampered                             // signature mismatch — real tamper (A7)
	verifyOperational                          // verification machinery failed — NOT tamper (A8)
	verifyInvalidEmbedded                      // signed content cannot be interpreted; never use the mutable live spec
)

// Invalid verified embedded content is refused in every mode. Other verdicts
// follow the configured enforcement mode.
func (c *ContainerProfileCacheImpl) verifyUserContainerProfile(profile *v1beta1.ContainerProfile, wlid string) bool {
	verdict := c.verifyUserContainerProfileVerdict(profile, wlid)
	return verdict != verifyInvalidEmbedded && (verdict == verifyOK || !c.signingEnforced())
}

// Verdict never gates by mode; R1016 emitted (deduped per RV) on real tamper.
func (c *ContainerProfileCacheImpl) verifyUserContainerProfileVerdict(profile *v1beta1.ContainerProfile, wlid string) verifyVerdict {
	if profile == nil {
		return verifyOK
	}
	adapter := profiles.NewContainerProfileAdapter(profile)
	if !signature.IsSigned(adapter) {
		if c.signingEnforced() {
			logger.L().Warning("user-defined ContainerProfile refused: signature verification is required and the profile is unsigned",
				helpers.String("profile", profile.Name),
				helpers.String("namespace", profile.Namespace),
				helpers.String("wlid", wlid))
		}
		return verifyUnsigned
	}
	key := tamperKey("ContainerProfile", profile.Namespace, profile.Name, profile.ResourceVersion)
	// AllowUntrusted: accept self-signed/local-CA signatures as long as the
	// signature itself verifies against the cert in the annotations. We only
	// want to flag actual tampering, not the absence of a Sigstore Fulcio trust
	// chain. Matches `cmd/sign-object`'s default verifier.
	err := signature.VerifyObjectAllowUntrusted(adapter)
	if err == nil {
		// Verified clean — clear any prior emit so future tampers re-alert.
		c.tamperEmitted.Delete(key)
		// Enforce the VERIFIED content: if the signature covers embedded content
		// (server-normalised spec differs from what was signed), replace the live
		// spec with the embedded one so what's enforced is exactly what was
		// signed — never the mutable live spec. Verification already bound the
		// embedded content to this object's name/namespace, so this is safe.
		embSpec, present, decodeErr := embeddedContainerProfileSpec(profile)
		if decodeErr != nil {
			logger.L().Warning("signed ContainerProfile embedded spec is invalid; refusing mutable stored spec",
				helpers.String("profile", profile.Name), helpers.String("namespace", profile.Namespace), helpers.Error(decodeErr))
			return verifyInvalidEmbedded
		}
		if present {
			c.reportSpecDivergence("flat/"+profile.Namespace+"/"+profile.Name, profile, "", profile.Namespace)
			profile.Spec = embSpec
		}
		return verifyOK
	}
	// Invalid signatures, including malformed signature annotations, raise R1016.
	// Hash-computation and verifier-construction failures are operational errors
	// and do not indicate tampering.
	if !errors.Is(err, signature.ErrSignatureMismatch) {
		logger.L().Warning("user-defined ContainerProfile signature verification operational error (NOT tamper)",
			helpers.String("profile", profile.Name),
			helpers.String("namespace", profile.Namespace),
			helpers.String("wlid", wlid),
			helpers.Error(err))
		// A8: transient.
		return verifyOperational
	}
	// Real tamper.
	logger.L().Warning("user-defined ContainerProfile signature mismatch (tamper detected)",
		helpers.String("profile", profile.Name),
		helpers.String("namespace", profile.Namespace),
		helpers.String("wlid", wlid),
		helpers.Error(err))
	// Dedup: emit R1016 only on first transition to invalid for this
	// (kind, ns, name, resourceVersion). Otherwise the refresh loop would alert
	// every reconcile cycle, once per container ref.
	if _, alreadyEmitted := c.tamperEmitted.LoadOrStore(key, struct{}{}); !alreadyEmitted {
		c.emitTamperAlert(profile.Name, profile.Namespace, wlid, "ContainerProfile", err)
	}
	return verifyTampered
}

// emitTamperAlert sends a single R1016 "Signed profile tampered" alert through
// the rule-alert exporter. No-op when the exporter is unset.
//
// `wlid` should be the authoritative workload identifier the caller has on hand
// (sharedData.Wlid) — using the runtime containerID instead loses workload
// kind/name/cluster attribution because GenericRuleFailure.SetWorkloadDetails()
// parses it as a WLID.
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
			// No kernel event backs a tamper verdict.
			Timestamp: time.Now(),
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

func unsignedKey(profile *v1beta1.ContainerProfile) string {
	return "unsigned|" + tamperKey("ContainerProfile", profile.Namespace, profile.Name, "")
}

func (c *ContainerProfileCacheImpl) noteUnsignedGoverns(verdict verifyVerdict, profile *v1beta1.ContainerProfile, wlid string) {
	if verdict != verifyUnsigned || c.signingEnforced() || profile == nil || c.tamperAlertExporter == nil {
		return
	}
	key := unsignedKey(profile)
	if _, already := c.tamperEmitted.LoadOrStore(key, struct{}{}); already {
		return
	}
	ruleFailure := &types.GenericRuleFailure{
		BaseRuntimeAlert: armotypes.BaseRuntimeAlert{
			AlertName:      "Unsigned profile governs",
			InfectedPID:    1,
			Severity:       1,
			FixSuggestions: "ContainerProfile '" + profile.Name + "' in namespace '" + profile.Namespace + "' governs its workload without a signature. Sign it with a trusted key before enforcement is turned on.",
			Timestamp:      time.Now(),
		},
		AlertType: armotypes.AlertTypeRule,
		RuntimeProcessDetails: armotypes.ProcessTree{
			ProcessTree: armotypes.Process{PID: 1, Comm: "node-agent"},
		},
		RuleAlert: armotypes.RuleAlert{
			RuleDescription: fmt.Sprintf("ContainerProfile '%s' in namespace '%s' governs while unsigned; signature verification is not enforced", profile.Name, profile.Namespace),
		},
		RuntimeAlertK8sDetails: armotypes.RuntimeAlertK8sDetails{Namespace: profile.Namespace},
		RuleID:                 "R1018",
	}
	ruleFailure.SetWorkloadDetails(wlid)
	c.tamperAlertExporter.SendRuleAlert(ruleFailure)
}

// embeddedContainerProfileSpec returns the ContainerProfileSpec from a signed
// CP's embedded content (signature.kubescape.io/content), when present. The
// embedded content is the verified source of truth — enforcing it (rather than
// the mutable live spec) closes the gap where a validly-signed embedded blob is
// stapled onto an object whose live spec was then tampered. Returns present=false
// when there is no embedded content (legacy sign-after-roundtrip artifacts,
// where the live spec IS the signed spec).
func embeddedContainerProfileSpec(profile *v1beta1.ContainerProfile) (v1beta1.ContainerProfileSpec, bool, error) {
	adapter := profiles.NewContainerProfileAdapter(profile)
	embedded, present, err := signature.EmbeddedContent(adapter)
	if !present || err != nil {
		return v1beta1.ContainerProfileSpec{}, present, err
	}
	var view struct {
		Spec *v1beta1.ContainerProfileSpec `json:"spec"`
	}
	if err := json.Unmarshal(embedded, &view); err != nil {
		return v1beta1.ContainerProfileSpec{}, true, err
	}
	if view.Spec == nil {
		return v1beta1.ContainerProfileSpec{}, true, fmt.Errorf("embedded content has no profile spec")
	}
	return *view.Spec, true, nil
}
