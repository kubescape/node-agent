//go:build experimental_signing

package ruleswatcher

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/Masterminds/semver/v3"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/kubescape/node-agent/pkg/watcher"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
)

var _ RulesWatcher = (*RulesWatcherImpl)(nil)

type RulesWatcherImpl struct {
	ruleCreator    rulecreator.RuleCreator
	k8sClient      k8sclient.K8sClientInterface
	callback       RulesWatcherCallback
	watchResources []watcher.WatchResource
	specDivergence sync.Map

	// trustPolicy governs signed Rules fragments. It is written once during
	// startup wiring but read from watch-event goroutines, so it is guarded by
	// policyMutex (the write also happens before dWatcher.Start, but the lock
	// keeps the field safe if that ordering ever changes).
	policyMutex sync.RWMutex
	trustPolicy *bundle.TrustPolicy
}

func NewRulesWatcher(k8sClient k8sclient.K8sClientInterface, ruleCreator rulecreator.RuleCreator, callback RulesWatcherCallback) *RulesWatcherImpl {
	return &RulesWatcherImpl{
		ruleCreator: ruleCreator,
		k8sClient:   k8sClient,
		callback:    callback,
		watchResources: []watcher.WatchResource{
			watcher.NewWatchResource(typesv1.RuleGvr, metav1.ListOptions{}),
		},
	}
}

func (w *RulesWatcherImpl) WatchResources() []watcher.WatchResource {
	return w.watchResources
}

// SetTrustPolicy enables signed, bundle-scoped rule fragments. Passing a
// policy without ruleClasses (or nil) leaves rule signing disabled.
func (w *RulesWatcherImpl) SetTrustPolicy(p *bundle.TrustPolicy) {
	w.policyMutex.Lock()
	defer w.policyMutex.Unlock()
	w.trustPolicy = p
}

// trustPolicySnapshot returns the currently configured policy and whether rule
// signing is enabled with it.
func (w *RulesWatcherImpl) trustPolicySnapshot() (*bundle.TrustPolicy, bool) {
	w.policyMutex.RLock()
	defer w.policyMutex.RUnlock()
	if w.trustPolicy == nil || !w.trustPolicy.RuleSigningEnabled() {
		return nil, false
	}
	return w.trustPolicy, true
}

// ruleSigningEnabled reports whether a trust policy with rule classes is set.
func (w *RulesWatcherImpl) ruleSigningEnabled() bool {
	_, ok := w.trustPolicySnapshot()
	return ok
}

// ResyncNow re-evaluates every Rules object under the policy currently set.
// Called after a policy reload so admission changes apply within one reload
// interval instead of waiting for the next Rules watch event.
func (w *RulesWatcherImpl) ResyncNow(ctx context.Context) {
	w.syncAllRulesAndNotify(ctx)
}

// reportRulesDivergence warns when an admitted Rules object's STORED rules
// list no longer matches its embedded signed one: kubectl shows rules that are
// not enforced (or hides ones that are). Observability only; counts only,
// never rule content; one warning per distinct stored content.
func (w *RulesWatcherImpl) reportRulesDivergence(rules *typesv1.Rules) {
	diverged, storedCount, signedCount, storedHash, ok := bundle.RulesStoredDivergence(rules)
	if !ok {
		return
	}
	key := rules.Namespace + "/" + rules.Name
	if !diverged {
		w.specDivergence.Delete(key)
		return
	}
	if prev, loaded := w.specDivergence.Load(key); loaded && prev.(string) == storedHash {
		return
	}
	w.specDivergence.Store(key, storedHash)
	logger.L().Warning("signed Rules stored spec diverges from the signed content: the stored rules are display-only and are NOT enforced; enforcement uses the signed content",
		helpers.String("name", rules.Name),
		helpers.String("namespace", rules.Namespace),
		helpers.Int("storedRules", storedCount),
		helpers.Int("signedRules", signedCount),
		helpers.String("hint", "the object was edited after signing; re-apply the signed artifact to realign what kubectl shows with what is enforced"))
}

func (w *RulesWatcherImpl) AddHandler(ctx context.Context, obj runtime.Object) {
	logger.L().Debug("RulesWatcher - rule added, syncing all rules")
	w.syncAllRulesAndNotify(ctx)
}

func (w *RulesWatcherImpl) ModifyHandler(ctx context.Context, obj runtime.Object) {
	logger.L().Debug("RulesWatcher - rule modified, syncing all rules")
	w.syncAllRulesAndNotify(ctx)
}

func (w *RulesWatcherImpl) DeleteHandler(ctx context.Context, obj runtime.Object) {
	logger.L().Debug("RulesWatcher - rule deleted, syncing all rules")
	w.syncAllRulesAndNotify(ctx)
}

func (w *RulesWatcherImpl) syncAllRulesAndNotify(ctx context.Context) {
	if err := w.syncAllRulesFromCluster(ctx); err != nil {
		logger.L().Warning("RulesWatcher - failed to sync all rules from cluster", helpers.Error(err))
		return
	}

	if w.callback != nil {
		w.callback()
		logger.L().Debug("RulesWatcher - notified callback with updated rules")
	}
}

// syncAllRulesFromCluster fetches all rules from the cluster and syncs them with the rule creator.
// Rules are filtered by:
//  1. Signature admissibility - when a trust policy with rule classes is configured, every
//     Rules object must be signed by a class-trusted signer and may only carry rule IDs its
//     class allows. A Rules object that fails admission is dropped WHOLE (fail closed), so an
//     attacker who can create a Rules object in some namespace cannot disable detections.
//  2. Enabled status - only enabled rules are considered
//  3. Agent version compatibility - rules with AgentVersionRequirement are checked against AGENT_VERSION env var using semver
func (w *RulesWatcherImpl) syncAllRulesFromCluster(ctx context.Context) error {
	unstructuredList, err := w.k8sClient.GetDynamicClient().Resource(typesv1.RuleGvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	policy, signingEnabled := w.trustPolicySnapshot()

	fragments := make([]*typesv1.Rules, 0, len(unstructuredList.Items))
	for _, item := range unstructuredList.Items {
		rules, err := unstructuredToRules(&item)
		if err != nil {
			logger.L().Warning("RulesWatcher - failed to convert rule during sync", helpers.Error(err))
			continue
		}
		fragments = append(fragments, rules)
	}

	enabledRules, tally := admitFragments(fragments, policy, signingEnabled, w.reportRulesDivergence)

	w.ruleCreator.SyncRules(enabledRules)

	logger.L().Info("RulesWatcher - synced rules from cluster",
		helpers.Int("enabledRules", len(enabledRules)),
		helpers.Int("totalRules", len(unstructuredList.Items)),
		helpers.Int("skippedByVersion", tally.skippedVersion))
	if signingEnabled {
		bundle.RecordRuleAdmission(tally.admitted, tally.rejected, len(enabledRules))
		logger.L().Info("RulesWatcher - signed rule fragments",
			helpers.Int("admitted", tally.admitted),
			helpers.Int("rejected", tally.rejected))
		// Backstop against a silent detection outage: signing is on and rules
		// objects exist, but none were admitted, so the effective ruleset is
		// empty and nothing will alert. Enforce fails rules closed to "no rules",
		// which is safe from tampered detections but is NOT silent — scream every
		// sync (persistent signal) rather than crash-loop (which would keep the
		// operator from signing the baseline to fix it).
		if tally.admitted == 0 && len(unstructuredList.Items) > 0 {
			logger.L().Error("RulesWatcher - signing enabled but NO rule fragment admitted while rules objects exist: detection is effectively OFF; sign the baseline ruleset as a base-class fragment or correct the trust policy",
				helpers.Int("rulesObjects", len(unstructuredList.Items)),
				helpers.Int("rejected", tally.rejected))
		}
	}
	return nil
}

func (w *RulesWatcherImpl) InitialSync(ctx context.Context) error {
	return w.syncAllRulesFromCluster(ctx)
}

func unstructuredToRules(obj *unstructured.Unstructured) (*typesv1.Rules, error) {
	if err := validateRawProfileDataInUnstructured(obj); err != nil {
		return nil, err
	}

	rule := &typesv1.Rules{}
	if err := k8sruntime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &rule); err != nil {
		return nil, err
	}

	for _, r := range rule.Spec.Rules {
		if r.ProfileDataRequired != nil {
			if err := r.ProfileDataRequired.Validate(); err != nil {
				return nil, fmt.Errorf("rule %q invalid profileDataRequired: %w", r.ID, err)
			}
		}
	}

	return rule, nil
}

func validateRawProfileDataInUnstructured(obj *unstructured.Unstructured) error {
	if obj == nil || obj.Object == nil {
		return nil
	}
	spec, ok := obj.Object["spec"].(map[string]any)
	if !ok {
		return nil
	}
	rulesRaw, ok := spec["rules"].([]any)
	if !ok {
		return nil
	}
	for i, r := range rulesRaw {
		ruleMap, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if pdr, exists := ruleMap["profileDataRequired"]; exists && pdr != nil {
			if err := typesv1.ValidateRawProfileDataRequired(pdr); err != nil {
				ruleID, _ := ruleMap["id"].(string)
				if ruleID != "" {
					return fmt.Errorf("rule %q: %w", ruleID, err)
				}
				return fmt.Errorf("rule[%d]: %w", i, err)
			}
		}
	}
	return nil
}

// isAgentVersionCompatible checks if the current agent version satisfies the given requirement
// using semantic versioning constraints. Returns true if compatible, false otherwise.
func isAgentVersionCompatible(requirement string) bool {
	agentVersion := os.Getenv("AGENT_VERSION")
	if agentVersion == "" {
		// If AGENT_VERSION is not set, log a warning and allow all rules for backward compatibility
		logger.L().Warning("RulesWatcher - AGENT_VERSION environment variable not set, allowing all rules")
		return true
	}

	// Parse the agent version
	currentVersion, err := semver.NewVersion(agentVersion)
	if err != nil {
		logger.L().Warning("RulesWatcher - invalid agent version format",
			helpers.String("agentVersion", agentVersion),
			helpers.Error(err))
		return true // Allow rule if we can't parse current version
	}

	// Parse the requirement constraint
	constraint, err := semver.NewConstraint(requirement)
	if err != nil {
		logger.L().Warning("RulesWatcher - invalid version constraint in rule",
			helpers.String("constraint", requirement),
			helpers.Error(err))
		return true // Allow rule if we can't parse the constraint
	}

	// Check if current version satisfies the constraint
	compatible := constraint.Check(currentVersion)

	logger.L().Debug("RulesWatcher - version compatibility check",
		helpers.String("agentVersion", agentVersion),
		helpers.String("requirement", requirement),
		helpers.Interface("compatible", compatible))

	return compatible
}
