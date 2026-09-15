package ruleswatcher

import (
	"context"
	"fmt"
	"os"

	"github.com/Masterminds/semver/v3"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
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
// 1. Enabled status - only enabled rules are considered
// 2. Agent version compatibility - rules with AgentVersionRequirement are checked against AGENT_VERSION env var using semver
func (w *RulesWatcherImpl) syncAllRulesFromCluster(ctx context.Context) error {
	unstructuredList, err := w.k8sClient.GetDynamicClient().Resource(typesv1.RuleGvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	var enabledRules []typesv1.Rule
	var skippedVersionCount int
	for _, item := range unstructuredList.Items {
		rules, err := unstructuredToRules(&item)
		if err != nil {
			logger.L().Warning("RulesWatcher - failed to convert rule during sync", helpers.Error(err))
			continue
		}
		for _, rule := range rules.Spec.Rules {
			if rule.Enabled {
				// Check agent version requirement if specified
				if rule.AgentVersionRequirement != "" {
					if !isAgentVersionCompatible(rule.AgentVersionRequirement) {
						logger.L().Debug("RulesWatcher - skipping rule due to agent version requirement",
							helpers.String("ruleID", rule.ID),
							helpers.String("requirement", rule.AgentVersionRequirement),
							helpers.String("agentVersion", os.Getenv("AGENT_VERSION")))
						skippedVersionCount++
						continue
					}
				}
				enabledRules = append(enabledRules, rule)
			}
		}
	}

	w.ruleCreator.SyncRules(enabledRules)

	logger.L().Info("RulesWatcher - synced rules from cluster",
		helpers.Int("enabledRules", len(enabledRules)),
		helpers.Int("totalRules", len(unstructuredList.Items)),
		helpers.Int("skippedByVersion", skippedVersionCount))
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
