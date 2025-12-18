# Rule CRD Watcher

This package implements a watcher for the Rule Custom Resource Definition (CRD) that automatically synchronizes rule definitions from Kubernetes CRDs with the RuleCreator component.

## Overview

The Rule CRD watcher provides the following functionality:

1. **Full Sync Approach**: On any rule change (add/modify/delete), fetches all rules from cluster and syncs the complete set
2. **Enabled/Disabled Support**: Only processes rules that are marked as enabled
3. **Initial Sync**: Loads all existing rules from the cluster on startup
4. **Callback Notifications**: Notifies other components when rules are updated

## Components

### RulesWatcher Interface

```go
type RulesWatcher interface {
    watcher.Adaptor
    InitialSync(ctx context.Context) error
}
```

### RulesWatcherImpl

The main implementation that:
- Watches Rule CRDs for any changes (add/modify/delete)
- On any change, fetches ALL rules from the cluster
- Replaces all rules in RuleCreator with enabled rules from cluster
- Provides callback notifications

## Usage

```go
// Create a rule creator
ruleCreator := rulecreator.NewRuleCreator()

// Define callback for rule updates
callback := func(rules []typesv1.Rule) {
    // Handle rule updates
    log.Printf("Updated %d rules", len(rules))
}

// Create the watcher
rulesWatcher := NewRulesWatcher(k8sClient, ruleCreator, callback)

// Perform initial sync
if err := rulesWatcher.InitialSync(ctx); err != nil {
    return err
}

// Register with dynamic watcher
watchHandler.AddAdaptor(rulesWatcher)
```

## Rule CRD Structure

The watcher expects Rule CRDs with the following structure:

```yaml
apiVersion: kubescape.io/v1
kind: Rule
metadata:
  name: example-rule
  namespace: default
spec:
  enabled: true
  id: "rule-001" 
  name: "Example Rule"
  description: "An example security rule"
  expressions:
    message: "Security violation detected"
    uniqueId: "example-rule-001"
    ruleExpression:
      - eventType: "exec"
        expression: "process.name == 'suspicious'"
  profileDependency:
    required: 0
  severity: 5
  supportPolicy: true
  tags: ["security", "example"]
  state: {}
```

## Features

### Simple Full Sync Strategy

Instead of tracking individual rule changes, the watcher uses a simple and reliable approach:

1. **Any Change Detected** → Fetch all rules from cluster
2. **Filter Enabled Rules** → Only include rules with `enabled: true`
3. **Replace All Rules** → Use `SyncRules()` to replace the complete rule set in RuleCreator

This approach is:
- **Simple**: No complex change tracking logic
- **Reliable**: Always consistent with cluster state
- **Safe**: No risk of missing updates or partial states

### Thread Safety

The RuleCreator implementation includes proper mutex locking to handle concurrent access safely.

### Extended RuleCreator Interface

Key method used for dynamic rule management:

```go
type RuleCreator interface {
    // ... existing methods ...
    
    // Dynamic rule management
    SyncRules(newRules []typesv1.Rule)  // Replaces all rules with new set
    // ... other helper methods ...
}
```

## Integration

The watcher integrates with the existing dynamic watcher system and can be used alongside other watchers like the RuleBinding cache.

### Event Flow

```
Rule CRD Change → AddHandler/ModifyHandler/DeleteHandler → 
Fetch All Rules from Cluster → Filter Enabled Rules → 
SyncRules() → Callback Notification
```

This ensures that any rule change (including enable/disable) is immediately reflected in the RuleCreator. 