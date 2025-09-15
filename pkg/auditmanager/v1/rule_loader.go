package v1

import (
	"fmt"

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
	RawRule   string
	RuleType  string // "file_watch" or "syscall"
	Key       string
	WatchPath string   // for file watch rules
	Syscalls  []string // for syscall rules
	Arch      string   // for syscall rules
	Filters   []string // additional filters
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
					auditRule.WatchPath = parts[i+1]
				}
			case "-k":
				if i+1 < len(parts) {
					auditRule.Key = parts[i+1]
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
					auditRule.Key = parts[i+1]
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
		return fmt.Sprintf("File watch on %s (key: %s)", ar.WatchPath, ar.Key)
	} else if ar.RuleType == "syscall" {
		return fmt.Sprintf("Syscall monitoring for %v (key: %s)", ar.Syscalls, ar.Key)
	}
	return fmt.Sprintf("Unknown rule type: %s", ar.RuleType)
}
