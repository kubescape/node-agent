package auditrule

import (
	"context"
	"fmt"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/auditmanager"
	"github.com/kubescape/node-agent/pkg/auditmanager/crd"
	"github.com/kubescape/node-agent/pkg/watcher"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// AuditRuleWatcher watches for AuditRule CRD changes and updates the audit manager
type AuditRuleWatcher struct {
	auditManager auditmanager.AuditManagerClient
	nodeName     string
	nodeLabels   map[string]string // Current node labels for selector matching
}

// NewAuditRuleWatcher creates a new audit rule watcher
func NewAuditRuleWatcher(auditManager auditmanager.AuditManagerClient, nodeName string, nodeLabels map[string]string) *AuditRuleWatcher {
	if nodeLabels == nil {
		nodeLabels = make(map[string]string)
	}

	// Ensure hostname label is present
	if _, exists := nodeLabels["kubernetes.io/hostname"]; !exists {
		nodeLabels["kubernetes.io/hostname"] = nodeName
	}

	return &AuditRuleWatcher{
		auditManager: auditManager,
		nodeName:     nodeName,
		nodeLabels:   nodeLabels,
	}
}

// Ensure AuditRuleWatcher implements the Adaptor interface
var _ watcher.Adaptor = (*AuditRuleWatcher)(nil)

// convertToAuditRule converts a runtime.Object to a LinuxAuditRule
// Handles both typed and unstructured objects
func (w *AuditRuleWatcher) convertToAuditRule(obj runtime.Object) (*crd.LinuxAuditRule, error) {
	// Handle already typed objects
	if auditRule, ok := obj.(*crd.LinuxAuditRule); ok {
		return auditRule, nil
	}

	// Handle unstructured objects (from dynamic client)
	if unstructuredObj, ok := obj.(*unstructured.Unstructured); ok {
		var auditRule crd.LinuxAuditRule
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
			unstructuredObj.Object, &auditRule); err != nil {
			return nil, fmt.Errorf("failed to convert unstructured to LinuxAuditRule: %w", err)
		}
		return &auditRule, nil
	}

	return nil, fmt.Errorf("unsupported object type: %T", obj)
}

// WatchResources returns the resources to watch
func (w *AuditRuleWatcher) WatchResources() []watcher.WatchResource {
	// Watch LinuxAuditRule CRDs
	return []watcher.WatchResource{
		watcher.NewWatchResource(schema.GroupVersionResource{
			Group:    "kubescape.io",
			Version:  "v1",
			Resource: "linuxauditrules",
		}, metav1.ListOptions{}),
	}
}

// AddHandler processes new LinuxAuditRule CRDs
func (w *AuditRuleWatcher) AddHandler(ctx context.Context, obj runtime.Object) {
	auditRule, err := w.convertToAuditRule(obj)
	if err != nil {
		logger.L().Warning("AddHandler: failed to convert object to LinuxAuditRule",
			helpers.Error(err),
			helpers.String("objectType", fmt.Sprintf("%T", obj)))
		return
	}

	logger.L().Info("processing new audit rule CRD",
		helpers.String("name", auditRule.Name),
		helpers.String("namespace", auditRule.Namespace),
		helpers.String("enabled", fmt.Sprintf("%t", auditRule.Spec.Enabled)),
		helpers.Int("ruleCount", len(auditRule.Spec.Rules)))

	w.processAuditRule(ctx, auditRule, "add")
}

// ModifyHandler processes updated LinuxAuditRule CRDs
func (w *AuditRuleWatcher) ModifyHandler(ctx context.Context, obj runtime.Object) {
	auditRule, err := w.convertToAuditRule(obj)
	if err != nil {
		logger.L().Warning("ModifyHandler: failed to convert object to LinuxAuditRule",
			helpers.Error(err),
			helpers.String("objectType", fmt.Sprintf("%T", obj)))
		return
	}

	logger.L().Info("processing updated audit rule CRD",
		helpers.String("name", auditRule.Name),
		helpers.String("namespace", auditRule.Namespace),
		helpers.String("enabled", fmt.Sprintf("%t", auditRule.Spec.Enabled)),
		helpers.Int("ruleCount", len(auditRule.Spec.Rules)))

	w.processAuditRule(ctx, auditRule, "modify")
}

// DeleteHandler processes deleted LinuxAuditRule CRDs
func (w *AuditRuleWatcher) DeleteHandler(ctx context.Context, obj runtime.Object) {
	auditRule, err := w.convertToAuditRule(obj)
	if err != nil {
		logger.L().Warning("DeleteHandler: failed to convert object to LinuxAuditRule",
			helpers.Error(err),
			helpers.String("objectType", fmt.Sprintf("%T", obj)))
		return
	}

	logger.L().Info("processing deleted audit rule CRD",
		helpers.String("name", auditRule.Name),
		helpers.String("namespace", auditRule.Namespace))

	crdName := w.getCRDIdentifier(auditRule)
	if err := w.auditManager.RemoveRules(ctx, crdName); err != nil {
		logger.L().Warning("failed to remove audit rules",
			helpers.Error(err),
			helpers.String("crdName", crdName))
	} else {
		logger.L().Info("successfully removed audit rules",
			helpers.String("crdName", crdName))
	}
}

// processAuditRule handles the common logic for add/modify operations
func (w *AuditRuleWatcher) processAuditRule(ctx context.Context, auditRule *crd.LinuxAuditRule, operation string) {
	// Check if this rule should be processed by this node
	if !w.shouldProcessRule(auditRule) {
		logger.L().Debug("skipping audit rule not targeted for this node",
			helpers.String("ruleName", auditRule.Name),
			helpers.String("nodeName", w.nodeName),
			helpers.String("operation", operation))

		// If this was a modify operation and we previously processed this rule,
		// we need to remove it since it no longer targets this node
		if operation == "modify" {
			crdName := w.getCRDIdentifier(auditRule)
			if err := w.auditManager.RemoveRules(ctx, crdName); err != nil {
				logger.L().Warning("failed to remove audit rules after node selector change",
					helpers.Error(err),
					helpers.String("crdName", crdName))
			}
		}
		return
	}

	// Check if the CRD is enabled
	if !auditRule.Spec.Enabled {
		logger.L().Debug("processing disabled audit rule - removing any existing rules",
			helpers.String("ruleName", auditRule.Name),
			helpers.String("operation", operation))

		// Always remove rules for disabled CRDs, regardless of operation type
		// This ensures rules are removed even if the node-agent restarts with disabled CRDs
		crdName := w.getCRDIdentifier(auditRule)
		if err := w.auditManager.RemoveRules(ctx, crdName); err != nil {
			logger.L().Warning("failed to remove disabled audit rules",
				helpers.Error(err),
				helpers.String("crdName", crdName),
				helpers.String("operation", operation))
		} else {
			logger.L().Info("successfully removed rules for disabled CRD",
				helpers.String("crdName", crdName),
				helpers.String("operation", operation))
		}
		return
	}

	// Validate rules before processing
	validationErrors := w.auditManager.ValidateRules(auditRule)
	if len(validationErrors) > 0 {
		logger.L().Warning("audit rule validation failed",
			helpers.String("ruleName", auditRule.Name),
			helpers.Int("errorCount", len(validationErrors)))

		for _, err := range validationErrors {
			logger.L().Warning("rule validation error",
				helpers.String("ruleName", err.RuleName),
				helpers.String("field", err.Field),
				helpers.String("error", err.Error))
		}

		// TODO: Update CRD status with validation errors
		return
	}

	// Update rules in audit manager
	crdName := w.getCRDIdentifier(auditRule)
	if err := w.auditManager.UpdateRules(ctx, crdName, auditRule); err != nil {
		logger.L().Warning("failed to update audit rules",
			helpers.Error(err),
			helpers.String("crdName", crdName))

		// TODO: Update CRD status with error
		return
	}

	logger.L().Info("successfully processed audit rule",
		helpers.String("crdName", crdName),
		helpers.String("operation", operation),
		helpers.Int("ruleCount", len(auditRule.Spec.Rules)))

	// TODO: Update CRD status with success
}

// shouldProcessRule determines if this audit rule should be processed by this node
func (w *AuditRuleWatcher) shouldProcessRule(auditRule *crd.LinuxAuditRule) bool {
	// If no node selector is specified, apply to all nodes
	if len(auditRule.Spec.NodeSelector) == 0 {
		logger.L().Debug("audit rule has no node selector, applying to all nodes",
			helpers.String("ruleName", auditRule.Name))
		return true
	}

	// Check if all selector requirements are met
	for selectorKey, selectorValue := range auditRule.Spec.NodeSelector {
		nodeValue, exists := w.nodeLabels[selectorKey]
		if !exists {
			logger.L().Debug("node missing required label",
				helpers.String("ruleName", auditRule.Name),
				helpers.String("requiredLabel", selectorKey),
				helpers.String("nodeName", w.nodeName))
			return false
		}

		if !w.matchesSelector(nodeValue, selectorValue) {
			logger.L().Debug("node label value doesn't match selector",
				helpers.String("ruleName", auditRule.Name),
				helpers.String("labelKey", selectorKey),
				helpers.String("nodeValue", nodeValue),
				helpers.String("selectorValue", selectorValue),
				helpers.String("nodeName", w.nodeName))
			return false
		}
	}

	logger.L().Debug("audit rule matches node selector",
		helpers.String("ruleName", auditRule.Name),
		helpers.String("nodeName", w.nodeName))
	return true
}

// matchesSelector checks if a node label value matches a selector value
// This implements basic string matching and could be extended to support
// more complex selector expressions in the future
func (w *AuditRuleWatcher) matchesSelector(nodeValue, selectorValue string) bool {
	// Exact match
	if nodeValue == selectorValue {
		return true
	}

	// Support comma-separated values (OR logic)
	if strings.Contains(selectorValue, ",") {
		values := strings.Split(selectorValue, ",")
		for _, value := range values {
			if strings.TrimSpace(value) == nodeValue {
				return true
			}
		}
	}

	// Support simple wildcards (basic implementation)
	if selectorValue == "*" {
		return true
	}

	// Support prefix matching with *
	if strings.HasSuffix(selectorValue, "*") {
		prefix := strings.TrimSuffix(selectorValue, "*")
		return strings.HasPrefix(nodeValue, prefix)
	}

	// Support suffix matching with *
	if strings.HasPrefix(selectorValue, "*") {
		suffix := strings.TrimPrefix(selectorValue, "*")
		return strings.HasSuffix(nodeValue, suffix)
	}

	return false
}

// getCRDIdentifier returns a unique identifier for the CRD
func (w *AuditRuleWatcher) getCRDIdentifier(auditRule *crd.LinuxAuditRule) string {
	if auditRule.Namespace != "" {
		return fmt.Sprintf("%s/%s", auditRule.Namespace, auditRule.Name)
	}
	return auditRule.Name
}

// UpdateNodeLabels updates the node labels used for selector matching
// This should be called when node labels change
func (w *AuditRuleWatcher) UpdateNodeLabels(newLabels map[string]string) {
	if newLabels == nil {
		newLabels = make(map[string]string)
	}

	// Ensure hostname label is present
	if _, exists := newLabels["kubernetes.io/hostname"]; !exists {
		newLabels["kubernetes.io/hostname"] = w.nodeName
	}

	w.nodeLabels = newLabels

	logger.L().Info("updated node labels for audit rule selector matching",
		helpers.String("nodeName", w.nodeName),
		helpers.Int("labelCount", len(newLabels)))
}

// GetNodeLabels returns the current node labels
func (w *AuditRuleWatcher) GetNodeLabels() map[string]string {
	// Return a copy to prevent external modification
	labelsCopy := make(map[string]string)
	for k, v := range w.nodeLabels {
		labelsCopy[k] = v
	}
	return labelsCopy
}

// ListMatchingRules returns information about which rules would match this node
// This is useful for debugging and monitoring
func (w *AuditRuleWatcher) ListMatchingRules(auditRules []*crd.LinuxAuditRule) []MatchingRuleInfo {
	var matchingRules []MatchingRuleInfo

	for _, auditRule := range auditRules {
		info := MatchingRuleInfo{
			CRDName:      w.getCRDIdentifier(auditRule),
			Namespace:    auditRule.Namespace,
			Name:         auditRule.Name,
			Enabled:      auditRule.Spec.Enabled,
			RuleCount:    len(auditRule.Spec.Rules),
			NodeSelector: auditRule.Spec.NodeSelector,
			Matches:      w.shouldProcessRule(auditRule),
		}

		if !info.Matches && len(auditRule.Spec.NodeSelector) > 0 {
			info.MismatchReason = w.getMismatchReason(auditRule)
		}

		matchingRules = append(matchingRules, info)
	}

	return matchingRules
}

// getMismatchReason returns a human-readable reason why a rule doesn't match
func (w *AuditRuleWatcher) getMismatchReason(auditRule *crd.LinuxAuditRule) string {
	for selectorKey, selectorValue := range auditRule.Spec.NodeSelector {
		nodeValue, exists := w.nodeLabels[selectorKey]
		if !exists {
			return fmt.Sprintf("node missing label '%s'", selectorKey)
		}

		if !w.matchesSelector(nodeValue, selectorValue) {
			return fmt.Sprintf("label '%s' value '%s' doesn't match selector '%s'",
				selectorKey, nodeValue, selectorValue)
		}
	}
	return "unknown reason"
}

// MatchingRuleInfo provides information about rule matching for debugging
type MatchingRuleInfo struct {
	CRDName        string            `json:"crdName"`
	Namespace      string            `json:"namespace"`
	Name           string            `json:"name"`
	Enabled        bool              `json:"enabled"`
	RuleCount      int               `json:"ruleCount"`
	NodeSelector   map[string]string `json:"nodeSelector"`
	Matches        bool              `json:"matches"`
	MismatchReason string            `json:"mismatchReason,omitempty"`
}
