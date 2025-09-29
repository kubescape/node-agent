package crd

import (
	"fmt"
	"strings"
)

// RuleConverter handles conversion from structured rule definitions to auditctl format
type RuleConverter struct{}

// NewRuleConverter creates a new rule converter instance
func NewRuleConverter() *RuleConverter {
	return &RuleConverter{}
}

// ConvertRule converts a structured AuditRuleDefinition to auditctl format
func (rc *RuleConverter) ConvertRule(ruleDef AuditRuleDefinition) ([]string, error) {
	// Validate that exactly one rule type is specified
	ruleTypes := 0
	if ruleDef.FileWatch != nil {
		ruleTypes++
	}
	if ruleDef.Syscall != nil {
		ruleTypes++
	}
	if ruleDef.Network != nil {
		ruleTypes++
	}
	if ruleDef.Process != nil {
		ruleTypes++
	}
	if ruleDef.RawRule != "" {
		ruleTypes++
	}

	if ruleTypes == 0 {
		return nil, fmt.Errorf("no rule definition provided for rule %s", ruleDef.Name)
	}
	if ruleTypes > 1 {
		return nil, fmt.Errorf("multiple rule types specified for rule %s, only one is allowed", ruleDef.Name)
	}

	// Convert based on rule type
	switch {
	case ruleDef.RawRule != "":
		return rc.convertRawRule(ruleDef.RawRule)
	case ruleDef.FileWatch != nil:
		return rc.convertFileWatchRule(ruleDef.FileWatch)
	case ruleDef.Syscall != nil:
		return rc.convertSyscallRule(ruleDef.Syscall)
	case ruleDef.Network != nil:
		return rc.convertNetworkRule(ruleDef.Network)
	case ruleDef.Process != nil:
		return rc.convertProcessRule(ruleDef.Process)
	default:
		return nil, fmt.Errorf("internal error: no rule type matched for rule %s", ruleDef.Name)
	}
}

// convertRawRule handles raw auditctl format rules
func (rc *RuleConverter) convertRawRule(rawRule string) ([]string, error) {
	if rawRule == "" {
		return nil, fmt.Errorf("raw rule cannot be empty")
	}

	// Split multi-line raw rules
	rules := strings.Split(strings.TrimSpace(rawRule), "\n")
	var cleanedRules []string

	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule != "" {
			cleanedRules = append(cleanedRules, rule)
		}
	}

	if len(cleanedRules) == 0 {
		return nil, fmt.Errorf("no valid rules found in raw rule")
	}

	return cleanedRules, nil
}

// convertFileWatchRule converts FileWatchRule to auditctl format
func (rc *RuleConverter) convertFileWatchRule(fw *FileWatchRule) ([]string, error) {
	if len(fw.Paths) == 0 {
		return nil, fmt.Errorf("file watch rule must specify at least one path")
	}
	if len(fw.Permissions) == 0 {
		return nil, fmt.Errorf("file watch rule must specify at least one permission")
	}
	if fw.Key == "" {
		return nil, fmt.Errorf("file watch rule must specify a key")
	}

	// Map permissions to auditctl format
	permMap := map[string]string{
		"read":      "r",
		"write":     "w",
		"attr":      "a",
		"attribute": "a", // Support both "attr" and "attribute"
		"execute":   "x",
	}

	var permStr string
	for _, perm := range fw.Permissions {
		if p, ok := permMap[perm]; ok {
			permStr += p
		} else {
			return nil, fmt.Errorf("invalid permission '%s', valid options: read, write, attr, attribute, execute", perm)
		}
	}

	var rules []string
	for _, path := range fw.Paths {
		if path == "" {
			continue
		}

		// Check if path should be excluded
		excluded := false
		for _, exclude := range fw.Exclude {
			if rc.matchesPattern(path, exclude) {
				excluded = true
				break
			}
		}

		if !excluded {
			rule := fmt.Sprintf("-w %s -p %s -k %s", path, permStr, fw.Key)
			rules = append(rules, rule)
		}
	}

	if len(rules) == 0 {
		return nil, fmt.Errorf("all paths were excluded, no rules generated")
	}

	return rules, nil
}

// convertSyscallRule converts SyscallRule to auditctl format
func (rc *RuleConverter) convertSyscallRule(sc *SyscallRule) ([]string, error) {
	if len(sc.Syscalls) == 0 {
		return nil, fmt.Errorf("syscall rule must specify at least one syscall")
	}

	// Set defaults
	action := sc.Action
	if action == "" {
		action = "always"
	}
	list := sc.List
	if list == "" {
		list = "exit"
	}

	// Validate action and list
	validActions := map[string]bool{"always": true, "never": true}
	validLists := map[string]bool{"task": true, "exit": true, "user": true, "exclude": true}

	if !validActions[action] {
		return nil, fmt.Errorf("invalid action '%s', valid options: always, never", action)
	}
	if !validLists[list] {
		return nil, fmt.Errorf("invalid list '%s', valid options: task, exit, user, exclude", list)
	}

	syscallList := strings.Join(sc.Syscalls, ",")

	// Build architecture filters
	var archFilters []string
	for _, arch := range sc.Architecture {
		if arch != "b64" && arch != "b32" {
			return nil, fmt.Errorf("invalid architecture '%s', valid options: b64, b32", arch)
		}
		archFilters = append(archFilters, fmt.Sprintf("-F arch=%s", arch))
	}

	// Build field filters
	var fieldFilters []string
	for _, filter := range sc.Filters {
		if err := rc.validateSyscallFilter(filter); err != nil {
			return nil, fmt.Errorf("invalid filter: %w", err)
		}
		fieldFilters = append(fieldFilters, fmt.Sprintf("-F %s%s%s", filter.Field, filter.Operator, filter.Value))
	}

	// Combine all parts
	var parts []string
	parts = append(parts, fmt.Sprintf("-a %s,%s", action, list))
	parts = append(parts, archFilters...)
	parts = append(parts, fieldFilters...)
	parts = append(parts, fmt.Sprintf("-S %s", syscallList))
	if sc.Key != "" {
		parts = append(parts, fmt.Sprintf("-k %s", sc.Key))
	}

	rule := strings.Join(parts, " ")
	return []string{rule}, nil
}

// convertNetworkRule converts NetworkRule to auditctl format (placeholder)
func (rc *RuleConverter) convertNetworkRule(nr *NetworkRule) ([]string, error) {
	// Network rules are not directly supported by Linux audit subsystem
	// This is a placeholder for future extension or custom handling
	return nil, fmt.Errorf("network rules are not yet supported")
}

// convertProcessRule converts ProcessRule to auditctl format
func (rc *RuleConverter) convertProcessRule(pr *ProcessRule) ([]string, error) {
	if pr.Key == "" {
		return nil, fmt.Errorf("process rule must specify a key")
	}

	// Process rules are typically implemented as execve syscall rules with filters
	var rules []string

	// Base execve rule
	var parts []string
	parts = append(parts, "-a always,exit")

	// Add architecture filters (default to b64 if not specified)
	parts = append(parts, "-F arch=b64")

	// Add execve syscall
	parts = append(parts, "-S execve")

	// Add executable filters
	if len(pr.Executables) > 0 {
		for _, exe := range pr.Executables {
			if exe != "" {
				parts = append(parts, fmt.Sprintf("-F exe=%s", exe))
			}
		}
	}

	// Add user filters
	if len(pr.Users) > 0 {
		for _, user := range pr.Users {
			if user != "" {
				// Try to convert user name to UID, but for now just use as-is
				parts = append(parts, fmt.Sprintf("-F uid=%s", user))
			}
		}
	}

	// Add group filters
	if len(pr.Groups) > 0 {
		for _, group := range pr.Groups {
			if group != "" {
				// Try to convert group name to GID, but for now just use as-is
				parts = append(parts, fmt.Sprintf("-F gid=%s", group))
			}
		}
	}

	// Add additional filters
	for _, filter := range pr.Filters {
		if err := rc.validateSyscallFilter(filter); err != nil {
			return nil, fmt.Errorf("invalid filter: %w", err)
		}
		parts = append(parts, fmt.Sprintf("-F %s%s%s", filter.Field, filter.Operator, filter.Value))
	}

	// Add key
	parts = append(parts, fmt.Sprintf("-k %s", pr.Key))

	rule := strings.Join(parts, " ")
	rules = append(rules, rule)

	// Add argument monitoring if specified
	if len(pr.Arguments) > 0 {
		// This is complex and would require multiple rules or advanced filtering
		// For now, we'll add a comment rule (not a real audit rule)
		// In a real implementation, this might require eBPF or other mechanisms
		for _, arg := range pr.Arguments {
			if arg != "" {
				// This is a placeholder - argument filtering is complex in audit
				comment := fmt.Sprintf("# Argument filter '%s' not directly supported by audit", arg)
				rules = append(rules, comment)
			}
		}
	}

	return rules, nil
}

// validateSyscallFilter validates a syscall filter
func (rc *RuleConverter) validateSyscallFilter(filter SyscallFilter) error {
	if filter.Field == "" {
		return fmt.Errorf("filter field cannot be empty")
	}
	if filter.Operator == "" {
		return fmt.Errorf("filter operator cannot be empty")
	}
	if filter.Value == "" {
		return fmt.Errorf("filter value cannot be empty")
	}

	// Validate operator
	validOperators := map[string]bool{
		"=": true, "!=": true, "<": true, ">": true, "<=": true, ">=": true,
	}
	if !validOperators[filter.Operator] {
		return fmt.Errorf("invalid operator '%s', valid options: =, !=, <, >, <=, >=", filter.Operator)
	}

	// Validate common field names (not exhaustive)
	validFields := map[string]bool{
		"pid": true, "ppid": true, "uid": true, "gid": true, "euid": true, "egid": true,
		"auid": true, "exe": true, "comm": true, "key": true, "exit": true, "success": true,
		"a0": true, "a1": true, "a2": true, "a3": true, // syscall arguments
	}

	// Allow field names that start with "a" followed by digits (syscall arguments)
	if !validFields[filter.Field] && !rc.isValidArgField(filter.Field) {
		// This is just a warning - we'll allow unknown fields but log them
		// In a real implementation, you might want to be more restrictive
	}

	return nil
}

// isValidArgField checks if a field is a valid syscall argument field (a0, a1, a2, etc.)
func (rc *RuleConverter) isValidArgField(field string) bool {
	if len(field) < 2 || field[0] != 'a' {
		return false
	}

	for _, c := range field[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}

	return true
}

// matchesPattern performs simple glob-style pattern matching
func (rc *RuleConverter) matchesPattern(path, pattern string) bool {
	// This is a simplified pattern matcher
	// In a real implementation, you'd want a proper glob library

	// For now, just support exact matches and simple wildcards
	if pattern == "*" {
		return true
	}
	if pattern == path {
		return true
	}

	// Support patterns ending with /*
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(path, prefix)
	}

	return false
}

// ValidateRuleDefinition validates a rule definition without converting it
func (rc *RuleConverter) ValidateRuleDefinition(ruleDef AuditRuleDefinition) []RuleValidationError {
	var errors []RuleValidationError

	// Validate rule name
	if ruleDef.Name == "" {
		errors = append(errors, RuleValidationError{
			RuleName: ruleDef.Name,
			Field:    "name",
			Error:    "rule name cannot be empty",
		})
	}

	// Try to convert the rule to catch validation errors
	_, err := rc.ConvertRule(ruleDef)
	if err != nil {
		errors = append(errors, RuleValidationError{
			RuleName: ruleDef.Name,
			Field:    "rule",
			Error:    err.Error(),
		})
	}

	return errors
}

// RuleValidationError represents a validation error for a rule
type RuleValidationError struct {
	RuleName string // Name of the rule that failed validation
	Field    string // Field that caused the error
	Error    string // Error message
}
