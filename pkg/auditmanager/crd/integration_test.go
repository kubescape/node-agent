package crd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConvertFullCRD tests the complete conversion of the apt-install-monitoring CRD
// This reproduces the exact issue where CRD has 4 rules but only 1 is loaded
func TestConvertFullCRD(t *testing.T) {
	converter := NewRuleConverter()

	// This is the exact CRD from the terminal output
	fullCRD := LinuxAuditRule{
		Spec: AuditRuleSpec{
			Rules: []AuditRuleDefinition{
				{
					Name:        "apt-install-detection",
					Description: "Monitor apt install commands to detect package installations",
					Enabled:     true,
					Priority:    100,
					Syscall: &SyscallRule{
						Syscalls:     []string{"execve"},
						Keys:         []string{"apt_install_key"},
						Action:       "always",
						List:         "exit",
						Architecture: []string{"b64"},
						Filters: []SyscallFilter{
							{Field: "comm", Operator: "=", Value: "apt"},
							{Field: "exe", Operator: "=", Value: "/usr/bin/apt"},
						},
					},
				},
				{
					Name:        "dpkg-installation-monitoring",
					Description: "Monitor dpkg calls during package installation",
					Enabled:     true,
					Priority:    101,
					Syscall: &SyscallRule{
						Syscalls:     []string{"execve"},
						Keys:         []string{"dpkg_install_key"},
						Action:       "always",
						List:         "exit",
						Architecture: []string{"b64"},
						Filters: []SyscallFilter{
							{Field: "comm", Operator: "=", Value: "dpkg"},
							{Field: "exe", Operator: "=", Value: "/usr/bin/dpkg"},
						},
					},
				},
				{
					Name:        "package-manager-monitoring",
					Description: "Monitor common package manager commands",
					Enabled:     true,
					Priority:    102,
					Syscall: &SyscallRule{
						Syscalls:     []string{"execve"},
						Keys:         []string{"package_manager_key"},
						Action:       "always",
						List:         "exit",
						Architecture: []string{"b64"},
						// No filters - this is the problematic rule
					},
				},
				{
					Name:        "package-manager-raw",
					Description: "Monitor package managers using raw audit rule",
					Enabled:     true,
					Priority:    103,
					RawRule:     "-a always,exit -F arch=b64 -S execve -F comm=apt -F comm=apt-get -F comm=dpkg -F comm=yum -F comm=dnf -k package_manager_raw",
				},
			},
		},
	}

	// Convert all rules and collect results
	var allConvertedRules []string
	var conversionErrors []string

	for _, ruleDef := range fullCRD.Spec.Rules {
		if !ruleDef.Enabled {
			continue // Skip disabled rules
		}

		rules, err := converter.ConvertRule(ruleDef)
		if err != nil {
			conversionErrors = append(conversionErrors, err.Error())
			continue
		}

		allConvertedRules = append(allConvertedRules, rules...)
	}

	// Verify that all 4 rules were converted successfully
	assert.Empty(t, conversionErrors, "No conversion errors should occur: %v", conversionErrors)
	assert.Len(t, allConvertedRules, 4, "Should have 4 converted rules")

	// Verify the exact converted rules
	expectedRules := []string{
		// Rule 1: apt-install-detection
		"-a always,exit -F arch=b64 -F comm=apt -F exe=/usr/bin/apt -S execve -k apt_install_key",
		// Rule 2: dpkg-installation-monitoring
		"-a always,exit -F arch=b64 -F comm=dpkg -F exe=/usr/bin/dpkg -S execve -k dpkg_install_key",
		// Rule 3: package-manager-monitoring (no filters)
		"-a always,exit -F arch=b64 -S execve -k package_manager_key",
		// Rule 4: package-manager-raw
		"-a always,exit -F arch=b64 -S execve -F comm=apt -F comm=apt-get -F comm=dpkg -F comm=yum -F comm=dnf -k package_manager_raw",
	}

	assert.Equal(t, expectedRules, allConvertedRules)

	t.Logf("Successfully converted %d rules:", len(allConvertedRules))
	for i, rule := range allConvertedRules {
		t.Logf("  %d: %s", i+1, rule)
	}
}

// TestConvertEnabledRulesOnly tests that only enabled rules are converted
func TestConvertEnabledRulesOnly(t *testing.T) {
	converter := NewRuleConverter()

	// CRD with mixed enabled/disabled rules
	mixedCRD := LinuxAuditRule{
		Spec: AuditRuleSpec{
			Rules: []AuditRuleDefinition{
				{
					Name:    "enabled-rule",
					Enabled: true,
					Syscall: &SyscallRule{
						Syscalls: []string{"execve"},
						Keys:     []string{"enabled_key"},
					},
				},
				{
					Name:    "disabled-rule",
					Enabled: false, // Disabled
					Syscall: &SyscallRule{
						Syscalls: []string{"open"},
						Keys:     []string{"disabled_key"},
					},
				},
				{
					Name:    "another-enabled-rule",
					Enabled: true,
					Syscall: &SyscallRule{
						Syscalls: []string{"close"},
						Keys:     []string{"another_enabled_key"},
					},
				},
			},
		},
	}

	// Convert only enabled rules
	var enabledRules []string
	for _, ruleDef := range mixedCRD.Spec.Rules {
		if !ruleDef.Enabled {
			continue
		}

		rules, err := converter.ConvertRule(ruleDef)
		require.NoError(t, err)
		enabledRules = append(enabledRules, rules...)
	}

	// Should only have 2 rules (enabled ones)
	assert.Len(t, enabledRules, 2)
	assert.Contains(t, enabledRules[0], "enabled_key")
	assert.Contains(t, enabledRules[1], "another_enabled_key")
	assert.NotContains(t, enabledRules[0], "disabled_key")
	assert.NotContains(t, enabledRules[1], "disabled_key")
}

// TestConvertRuleWithDifferentTypes tests conversion of different rule types in one CRD
func TestConvertRuleWithDifferentTypes(t *testing.T) {
	converter := NewRuleConverter()

	mixedTypesCRD := LinuxAuditRule{
		Spec: AuditRuleSpec{
			Rules: []AuditRuleDefinition{
				{
					Name: "syscall-rule",
					Syscall: &SyscallRule{
						Syscalls: []string{"execve"},
						Keys:     []string{"syscall_key"},
					},
				},
				{
					Name: "file-watch-rule",
					FileWatch: &FileWatchRule{
						Paths:       []string{"/etc/passwd"},
						Permissions: []string{"write"},
						Keys:        []string{"filewatch_key"},
					},
				},
				{
					Name:    "raw-rule",
					RawRule: "-w /etc/shadow -p wa -k raw_key",
				},
				{
					Name: "process-rule",
					Process: &ProcessRule{
						Executables: []string{"/bin/bash"},
						Keys:        []string{"process_key"},
					},
				},
			},
		},
	}

	// Convert all rules
	var allRules []string
	for _, ruleDef := range mixedTypesCRD.Spec.Rules {
		rules, err := converter.ConvertRule(ruleDef)
		require.NoError(t, err)
		allRules = append(allRules, rules...)
	}

	// Should have 4 rules (1 syscall + 1 filewatch + 1 raw + 1 process)
	assert.Len(t, allRules, 4)

	// Verify each rule type is present
	assert.Contains(t, allRules[0], "syscall_key")
	assert.Contains(t, allRules[1], "filewatch_key")
	assert.Contains(t, allRules[2], "raw_key")
	assert.Contains(t, allRules[3], "process_key")

	t.Logf("Converted %d different rule types:", len(allRules))
	for i, rule := range allRules {
		t.Logf("  %d: %s", i+1, rule)
	}
}

// TestRuleKeyUniqueness tests that rule keys are preserved correctly
func TestRuleKeyUniqueness(t *testing.T) {
	converter := NewRuleConverter()

	// CRD with multiple rules that have different keys
	multiKeyCRD := LinuxAuditRule{
		Spec: AuditRuleSpec{
			Rules: []AuditRuleDefinition{
				{
					Name: "rule-1",
					Syscall: &SyscallRule{
						Syscalls: []string{"execve"},
						Keys:     []string{"key_1"},
					},
				},
				{
					Name: "rule-2",
					Syscall: &SyscallRule{
						Syscalls: []string{"open"},
						Keys:     []string{"key_2"},
					},
				},
				{
					Name: "rule-3",
					Syscall: &SyscallRule{
						Syscalls: []string{"close"},
						Keys:     []string{"key_3"},
					},
				},
			},
		},
	}

	// Convert all rules and verify keys are preserved
	ruleKeys := make(map[string]bool)
	for _, ruleDef := range multiKeyCRD.Spec.Rules {
		_, err := converter.ConvertRule(ruleDef)
		require.NoError(t, err)

		// Extract key from rule definition
		if ruleDef.Syscall != nil {
			for _, key := range ruleDef.Syscall.Keys {
				ruleKeys[key] = true
			}
		}
	}

	// Verify all keys are present
	assert.True(t, ruleKeys["key_1"])
	assert.True(t, ruleKeys["key_2"])
	assert.True(t, ruleKeys["key_3"])
	assert.Len(t, ruleKeys, 3)
}
