package v1

import (
	"fmt"
	"strings"

	"github.com/elastic/go-libaudit/v2/rule"
)

// HardcodedRules contains the audit rules for the POC
// These rules will be loaded at startup
var HardcodedRules = []string{
	// File watch rules
	"-w /etc/passwd -p wa -k identity",
	"-w /etc/shadow -p wa -k identity",
	"-w /etc/group -p wa -k identity",
	"-w /etc/sudoers -p wa -k privileged",
	"-w /etc/ssh/sshd_config -p wa -k ssh_config",

	// Syscall monitoring rules
	"-a always,exit -F arch=b64 -S execve -k exec",
	"-a always,exit -F arch=b32 -S execve -k exec",
	"-a always,exit -F arch=b64 -S open,openat -k file_access",
	"-a always,exit -F arch=b32 -S open,openat -k file_access",
}

// AuditRule represents a parsed audit rule
type AuditRule struct {
	RawRule    string
	RuleType   string // "file_watch" or "syscall"
	Keys       []string
	WatchPath  string   // for single path file watch rules (backward compatibility)
	WatchPaths []string // for multiple path file watch rules
	Syscalls   []string // for syscall rules
	Arch       string   // for syscall rules
	Filters    []string // additional filters
}

// LoadHardcodedRules parses the hardcoded rules and returns them as AuditRule structs
func LoadHardcodedRules() ([]*AuditRule, error) {
	var auditRules []*AuditRule

	for _, ruleStr := range HardcodedRules {
		auditRule, err := parseAuditRule(ruleStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse rule '%s': %w", ruleStr, err)
		}
		auditRules = append(auditRules, auditRule)
	}

	return auditRules, nil
}

// ParseAuditRule parses a string audit rule into an AuditRule struct (public function)
func ParseAuditRule(ruleStr string) (*AuditRule, error) {
	return parseAuditRule(ruleStr)
}

// parseAuditRule parses a string audit rule into an AuditRule struct
func parseAuditRule(ruleStr string) (*AuditRule, error) {
	auditRule := &AuditRule{
		RawRule: ruleStr,
	}

	// Simple parsing - for POC we'll do basic string matching
	// In production, this would use a proper parser

	if ruleStr[0] == '-' && ruleStr[1] == 'w' {
		// File watch rule: -w /path -p permissions -k key
		auditRule.RuleType = "file_watch"

		// Extract path (after -w and before -p)
		parts := parseRuleParts(ruleStr)
		for i, part := range parts {
			switch part {
			case "-w":
				if i+1 < len(parts) {
					path := parts[i+1]
					auditRule.WatchPath = path            // backward compatibility
					auditRule.WatchPaths = []string{path} // new multi-path support
				}
			case "-k":
				if i+1 < len(parts) {
					auditRule.Keys = append(auditRule.Keys, parts[i+1])
				}
			}
		}
	} else if ruleStr[0] == '-' && ruleStr[1] == 'a' {
		// Syscall rule: -a action,list -F filters -S syscalls -k key
		auditRule.RuleType = "syscall"

		parts := parseRuleParts(ruleStr)
		for i, part := range parts {
			switch part {
			case "-S":
				if i+1 < len(parts) {
					// Syscalls can be comma-separated
					auditRule.Syscalls = []string{parts[i+1]}
				}
			case "-k":
				if i+1 < len(parts) {
					auditRule.Keys = append(auditRule.Keys, parts[i+1])
				}
			case "-F":
				if i+1 < len(parts) {
					auditRule.Filters = append(auditRule.Filters, parts[i+1])
					// Extract arch from arch= filter
					if len(parts[i+1]) > 5 && parts[i+1][:5] == "arch=" {
						auditRule.Arch = parts[i+1][5:]
					}
				}
			}
		}
	} else {
		return nil, fmt.Errorf("unsupported rule format: %s", ruleStr)
	}

	return auditRule, nil
}

// parseRuleParts splits a rule string into parts, respecting quotes
func parseRuleParts(ruleStr string) []string {
	var parts []string
	var current string
	inQuotes := false

	for _, char := range ruleStr {
		if char == '"' {
			inQuotes = !inQuotes
		} else if char == ' ' && !inQuotes {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(char)
		}
	}

	if current != "" {
		parts = append(parts, current)
	}

	return parts
}

// ConvertToLibauditRule converts our AuditRule to go-libaudit rule format
func (ar *AuditRule) ConvertToLibauditRule() (*rule.Rule, error) {
	// For POC, we'll return nil since we're not actually loading rules into kernel yet
	// This is just for demonstration of the interface
	// In production, this would need proper rule type constants and more robust conversion

	if ar.RuleType == "file_watch" {
		// File watch rule - would need proper rule construction from go-libaudit
		return nil, fmt.Errorf("rule conversion not implemented in POC: %s", ar.RuleType)
	} else if ar.RuleType == "syscall" {
		// Syscall rule - would need proper rule construction from go-libaudit
		return nil, fmt.Errorf("rule conversion not implemented in POC: %s", ar.RuleType)
	}

	return nil, fmt.Errorf("unsupported rule type: %s", ar.RuleType)
}

// GetRuleDescription returns a human-readable description of the rule
func (ar *AuditRule) GetRuleDescription() string {
	if ar.RuleType == "file_watch" {
		// Use WatchPaths if available, otherwise fall back to WatchPath
		paths := ar.WatchPaths
		if len(paths) == 0 && ar.WatchPath != "" {
			paths = []string{ar.WatchPath}
		}

		keysStr := strings.Join(ar.Keys, ", ")
		if len(paths) == 1 {
			return fmt.Sprintf("File watch on %s (keys: %s)", paths[0], keysStr)
		} else if len(paths) > 1 {
			return fmt.Sprintf("File watch on %d paths: %v (keys: %s)", len(paths), paths, keysStr)
		} else {
			return fmt.Sprintf("File watch rule (keys: %s)", keysStr)
		}
	} else if ar.RuleType == "syscall" {
		keysStr := strings.Join(ar.Keys, ", ")
		return fmt.Sprintf("Syscall monitoring for %v (keys: %s)", ar.Syscalls, keysStr)
	}
	return fmt.Sprintf("Unknown rule type: %s", ar.RuleType)
}
