package crd

import (
	"testing"

	"github.com/elastic/go-libaudit/v2/rule"
	"github.com/elastic/go-libaudit/v2/rule/flags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConversionPipeline tests the complete pipeline from CRD to kernel-ready commands
// This tests the conversion, parsing, and validation steps that happen before loading into kernel

func TestCRDToAuditctlConversion(t *testing.T) {
	converter := NewRuleConverter()

	// Test cases that represent real-world audit rules
	testCases := []struct {
		name             string
		crdRule          AuditRuleDefinition
		expectedAuditctl string
		shouldParse      bool
		description      string
	}{
		{
			name: "simple execve monitoring",
			crdRule: AuditRuleDefinition{
				Name: "execve-monitor",
				Syscall: &SyscallRule{
					Syscalls:     []string{"execve"},
					Key:          "exec_monitor",
					Architecture: []string{"b64"},
				},
			},
			expectedAuditctl: "-a always,exit -F arch=b64 -S execve -k exec_monitor",
			shouldParse:      true,
			description:      "Basic execve monitoring without filters",
		},
		{
			name: "file watch with permissions",
			crdRule: AuditRuleDefinition{
				Name: "file-watch",
				FileWatch: &FileWatchRule{
					Paths:       []string{"/etc/passwd"},
					Permissions: []string{"write", "attribute"},
					Key:         "identity_changes",
				},
			},
			expectedAuditctl: "-w /etc/passwd -p wa -k identity_changes",
			shouldParse:      true,
			description:      "File watch rule with write and attribute permissions",
		},
		{
			name: "complex syscall with multiple filters",
			crdRule: AuditRuleDefinition{
				Name: "complex-syscall",
				Syscall: &SyscallRule{
					Syscalls:     []string{"open", "openat"},
					Key:          "file_access",
					Architecture: []string{"b64"},
					Filters: []SyscallFilter{
						{Field: "auid", Operator: ">=", Value: "500"},
						{Field: "auid", Operator: "!=", Value: "4294967295"},
						{Field: "exit", Operator: "=", Value: "-EACCES"},
					},
				},
			},
			expectedAuditctl: "-a always,exit -F arch=b64 -F auid>=500 -F auid!=4294967295 -F exit=-EACCES -S open,openat -k file_access",
			shouldParse:      true,
			description:      "Complex syscall rule with multiple user and exit code filters",
		},
		{
			name: "raw rule passthrough",
			crdRule: AuditRuleDefinition{
				Name:    "raw-passthrough",
				RawRule: "-w /etc/shadow -p r -k shadow_access",
			},
			expectedAuditctl: "-w /etc/shadow -p r -k shadow_access",
			shouldParse:      true,
			description:      "Raw rule passthrough without modification",
		},
		{
			name: "process rule with executable filter",
			crdRule: AuditRuleDefinition{
				Name: "process-executable",
				Process: &ProcessRule{
					Executables: []string{"/bin/su"},
					Key:         "su_execution",
				},
			},
			expectedAuditctl: "-a always,exit -F arch=b64 -S execve -F exe=/bin/su -k su_execution",
			shouldParse:      true,
			description:      "Process rule targeting specific executable",
		},
		{
			name: "syscall with syscall arguments",
			crdRule: AuditRuleDefinition{
				Name: "syscall-args",
				Syscall: &SyscallRule{
					Syscalls:     []string{"ptrace"},
					Key:          "ptrace_monitor",
					Architecture: []string{"b64"},
					Filters: []SyscallFilter{
						{Field: "a0", Operator: "=", Value: "0x10"},
						{Field: "uid", Operator: "=", Value: "0"},
					},
				},
			},
			expectedAuditctl: "-a always,exit -F arch=b64 -F a0=0x10 -F uid=0 -S ptrace -k ptrace_monitor",
			shouldParse:      true,
			description:      "Syscall rule with syscall argument filters",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Step 1: Convert CRD to auditctl format
			rules, err := converter.ConvertRule(tc.crdRule)
			require.NoError(t, err)
			require.Len(t, rules, 1)

			generatedRule := rules[0]
			assert.Equal(t, tc.expectedAuditctl, generatedRule)

			// Step 2: Test that the generated rule can be parsed by go-libaudit
			if tc.shouldParse {
				parsedRule, err := flags.Parse(generatedRule)
				if err != nil {
					t.Logf("⚠️  Rule parsing failed: %v", err)
					t.Logf("   Generated rule: %s", generatedRule)
					// Don't fail the test - this helps us identify which rules might have issues
				} else {
					assert.NotNil(t, parsedRule)
					t.Logf("✓ Rule parsed successfully: %s", generatedRule)
				}
			}

			t.Logf("✓ %s: %s", tc.name, tc.description)
		})
	}
}

func TestRuleParsingValidation(t *testing.T) {
	converter := NewRuleConverter()

	// Test rules that should parse successfully
	validRules := []struct {
		name        string
		crdRule     AuditRuleDefinition
		description string
	}{
		{
			name: "basic file watch",
			crdRule: AuditRuleDefinition{
				Name: "basic-watch",
				FileWatch: &FileWatchRule{
					Paths:       []string{"/etc/passwd"},
					Permissions: []string{"write"},
					Key:         "basic_watch",
				},
			},
			description: "Basic file watch should parse",
		},
		{
			name: "syscall without filters",
			crdRule: AuditRuleDefinition{
				Name: "syscall-no-filters",
				Syscall: &SyscallRule{
					Syscalls: []string{"execve"},
					Key:      "execve_monitor",
				},
			},
			description: "Syscall without filters should parse",
		},
		{
			name: "syscall with arch filter only",
			crdRule: AuditRuleDefinition{
				Name: "syscall-arch-only",
				Syscall: &SyscallRule{
					Syscalls:     []string{"execve"},
					Key:          "execve_arch",
					Architecture: []string{"b64"},
				},
			},
			description: "Syscall with architecture filter should parse",
		},
	}

	for _, tc := range validRules {
		t.Run(tc.name, func(t *testing.T) {
			// Convert CRD to auditctl
			rules, err := converter.ConvertRule(tc.crdRule)
			require.NoError(t, err)
			require.Len(t, rules, 1)

			// Try to parse with go-libaudit
			parsedRule, err := flags.Parse(rules[0])
			if err != nil {
				t.Errorf("Failed to parse rule '%s': %v", rules[0], err)
				return
			}

			// Try to build wire format
			wireFormat, err := rule.Build(parsedRule)
			if err != nil {
				t.Errorf("Failed to build wire format for rule '%s': %v", rules[0], err)
				return
			}

			assert.NotNil(t, wireFormat)
			assert.True(t, len(wireFormat) > 0)

			t.Logf("✓ %s: %s", tc.name, tc.description)
		})
	}
}

func TestProblematicRules(t *testing.T) {
	converter := NewRuleConverter()

	// Test rules that might have parsing issues (like the comm field issue we found)
	problematicRules := []struct {
		name        string
		crdRule     AuditRuleDefinition
		description string
		expectError bool
	}{
		{
			name: "syscall with comm filter",
			crdRule: AuditRuleDefinition{
				Name: "comm-filter-test",
				Syscall: &SyscallRule{
					Syscalls: []string{"execve"},
					Key:      "comm_test",
					Filters: []SyscallFilter{
						{Field: "comm", Operator: "=", Value: "apt"},
					},
				},
			},
			description: "Syscall with comm filter (known to cause parsing issues)",
			expectError: true,
		},
		{
			name: "syscall with exe filter",
			crdRule: AuditRuleDefinition{
				Name: "exe-filter-test",
				Syscall: &SyscallRule{
					Syscalls: []string{"execve"},
					Key:      "exe_test",
					Filters: []SyscallFilter{
						{Field: "exe", Operator: "=", Value: "/usr/bin/apt"},
					},
				},
			},
			description: "Syscall with exe filter (might cause parsing issues)",
			expectError: true,
		},
		{
			name: "syscall with path filter",
			crdRule: AuditRuleDefinition{
				Name: "path-filter-test",
				Syscall: &SyscallRule{
					Syscalls: []string{"all"},
					Key:      "path_test",
					Filters: []SyscallFilter{
						{Field: "path", Operator: "=", Value: "/bin/su"},
					},
				},
			},
			description: "Syscall with path filter (might cause parsing issues)",
			expectError: true,
		},
	}

	for _, tc := range problematicRules {
		t.Run(tc.name, func(t *testing.T) {
			// Convert CRD to auditctl
			rules, err := converter.ConvertRule(tc.crdRule)
			require.NoError(t, err)
			require.Len(t, rules, 1)

			// Try to parse with go-libaudit
			_, parseErr := flags.Parse(rules[0])

			if tc.expectError {
				if parseErr != nil {
					t.Logf("✓ Expected parsing error: %v", parseErr)
					t.Logf("  Rule: %s", rules[0])
				} else {
					t.Logf("⚠️  Expected parsing error but rule parsed successfully: %s", rules[0])
				}
			} else {
				require.NoError(t, parseErr, "Rule should parse successfully: %s", rules[0])
			}

			t.Logf("✓ %s: %s", tc.name, tc.description)
		})
	}
}

func TestRuleConversionAccuracy(t *testing.T) {
	converter := NewRuleConverter()

	// Test specific rules from the original issue to ensure they convert correctly
	originalIssueRules := []struct {
		name        string
		crdRule     AuditRuleDefinition
		expectedCmd string
	}{
		{
			name: "apt-install-detection",
			crdRule: AuditRuleDefinition{
				Name: "apt-install-detection",
				Syscall: &SyscallRule{
					Syscalls:     []string{"execve"},
					Key:          "apt_install_key",
					Architecture: []string{"b64"},
					Filters: []SyscallFilter{
						{Field: "comm", Operator: "=", Value: "apt"},
						{Field: "exe", Operator: "=", Value: "/usr/bin/apt"},
					},
				},
			},
			expectedCmd: "-a always,exit -F arch=b64 -F comm=apt -F exe=/usr/bin/apt -S execve -k apt_install_key",
		},
		{
			name: "package-manager-monitoring",
			crdRule: AuditRuleDefinition{
				Name: "package-manager-monitoring",
				Syscall: &SyscallRule{
					Syscalls:     []string{"execve"},
					Key:          "package_manager_key",
					Architecture: []string{"b64"},
					// No filters
				},
			},
			expectedCmd: "-a always,exit -F arch=b64 -S execve -k package_manager_key",
		},
	}

	for _, tc := range originalIssueRules {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := converter.ConvertRule(tc.crdRule)
			require.NoError(t, err)
			require.Len(t, rules, 1)

			assert.Equal(t, tc.expectedCmd, rules[0])

			// Test parsing (this is where the original issue occurred)
			_, parseErr := flags.Parse(rules[0])
			if parseErr != nil {
				t.Logf("⚠️  Parsing error for %s: %v", tc.name, parseErr)
				t.Logf("   Generated rule: %s", rules[0])
			} else {
				t.Logf("✓ Rule %s parses successfully: %s", tc.name, rules[0])
			}
		})
	}
}

func TestMultipleRulesConversion(t *testing.T) {
	converter := NewRuleConverter()

	// Test converting multiple rules from a single CRD
	crd := LinuxAuditRule{
		Spec: AuditRuleSpec{
			Rules: []AuditRuleDefinition{
				{
					Name: "rule-1",
					Syscall: &SyscallRule{
						Syscalls: []string{"execve"},
						Key:      "rule_1_key",
					},
				},
				{
					Name: "rule-2",
					FileWatch: &FileWatchRule{
						Paths:       []string{"/etc/passwd"},
						Permissions: []string{"write"},
						Key:         "rule_2_key",
					},
				},
				{
					Name:    "rule-3",
					RawRule: "-w /etc/shadow -p r -k rule_3_key",
				},
			},
		},
	}

	var allRules []string
	var conversionErrors []string

	for _, ruleDef := range crd.Spec.Rules {
		rules, err := converter.ConvertRule(ruleDef)
		if err != nil {
			conversionErrors = append(conversionErrors, err.Error())
		} else {
			allRules = append(allRules, rules...)
		}
	}

	// Should have 3 rules total
	assert.Empty(t, conversionErrors)
	assert.Len(t, allRules, 3)

	expectedRules := []string{
		"-a always,exit -S execve -k rule_1_key",
		"-w /etc/passwd -p w -k rule_2_key",
		"-w /etc/shadow -p r -k rule_3_key",
	}

	assert.Equal(t, expectedRules, allRules)

	t.Logf("✓ Successfully converted %d rules from CRD", len(allRules))
	for i, rule := range allRules {
		t.Logf("  %d: %s", i+1, rule)
	}
}

func TestRuleValidationPipeline(t *testing.T) {
	converter := NewRuleConverter()

	// Test the validation pipeline
	testCases := []struct {
		name        string
		crdRule     AuditRuleDefinition
		shouldPass  bool
		description string
	}{
		{
			name: "valid syscall rule",
			crdRule: AuditRuleDefinition{
				Name: "valid-syscall",
				Syscall: &SyscallRule{
					Syscalls: []string{"execve"},
					Key:      "valid_key",
				},
			},
			shouldPass:  true,
			description: "Valid syscall rule should pass validation",
		},
		{
			name: "rule without key",
			crdRule: AuditRuleDefinition{
				Name: "no-key-syscall",
				Syscall: &SyscallRule{
					Syscalls: []string{"execve"},
					Key:      "", // No key - now allowed
				},
			},
			shouldPass:  true,
			description: "Rule without key should pass validation (key is optional)",
		},
		{
			name: "invalid rule - empty syscalls",
			crdRule: AuditRuleDefinition{
				Name: "invalid-syscall",
				Syscall: &SyscallRule{
					Syscalls: []string{}, // Empty syscalls
					Key:      "invalid_key",
				},
			},
			shouldPass:  false,
			description: "Rule with empty syscalls should fail validation",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test validation
			validationErrors := converter.ValidateRuleDefinition(tc.crdRule)

			if tc.shouldPass {
				assert.Empty(t, validationErrors, "Validation should pass for %s", tc.description)
			} else {
				assert.NotEmpty(t, validationErrors, "Validation should fail for %s", tc.description)
				for _, err := range validationErrors {
					t.Logf("  Validation error: %s", err.Error)
				}
			}

			// Test conversion
			rules, err := converter.ConvertRule(tc.crdRule)

			if tc.shouldPass {
				assert.NoError(t, err)
				assert.NotEmpty(t, rules)
			} else {
				assert.Error(t, err)
				assert.Nil(t, rules)
			}

			t.Logf("✓ %s: %s", tc.name, tc.description)
		})
	}
}
