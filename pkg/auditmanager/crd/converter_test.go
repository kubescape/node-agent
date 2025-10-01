package crd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertSyscallRule(t *testing.T) {
	converter := NewRuleConverter()

	tests := []struct {
		name          string
		rule          AuditRuleDefinition
		expectedRules []string
		expectedError bool
		errorContains string
	}{
		{
			name: "apt-install-detection with filters",
			rule: AuditRuleDefinition{
				Name: "apt-install-detection",
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
			expectedRules: []string{
				"-a always,exit -F arch=b64 -F comm=apt -F exe=/usr/bin/apt -S execve -k apt_install_key",
			},
			expectedError: false,
		},
		{
			name: "dpkg-installation-monitoring with filters",
			rule: AuditRuleDefinition{
				Name: "dpkg-installation-monitoring",
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
			expectedRules: []string{
				"-a always,exit -F arch=b64 -F comm=dpkg -F exe=/usr/bin/dpkg -S execve -k dpkg_install_key",
			},
			expectedError: false,
		},
		{
			name: "package-manager-monitoring without filters",
			rule: AuditRuleDefinition{
				Name: "package-manager-monitoring",
				Syscall: &SyscallRule{
					Syscalls:     []string{"execve"},
					Keys:         []string{"package_manager_key"},
					Action:       "always",
					List:         "exit",
					Architecture: []string{"b64"},
					// No filters - this is the problematic rule
				},
			},
			expectedRules: []string{
				"-a always,exit -F arch=b64 -S execve -k package_manager_key",
			},
			expectedError: false,
		},
		{
			name: "multiple syscalls",
			rule: AuditRuleDefinition{
				Name: "multi-syscall-rule",
				Syscall: &SyscallRule{
					Syscalls:     []string{"open", "openat"},
					Keys:         []string{"file_access_key"},
					Action:       "always",
					List:         "exit",
					Architecture: []string{"b64"},
					Filters: []SyscallFilter{
						{Field: "uid", Operator: "=", Value: "1000"},
					},
				},
			},
			expectedRules: []string{
				"-a always,exit -F arch=b64 -F uid=1000 -S open,openat -k file_access_key",
			},
			expectedError: false,
		},
		{
			name: "default values",
			rule: AuditRuleDefinition{
				Name: "default-values-rule",
				Syscall: &SyscallRule{
					Syscalls: []string{"execve"},
					Keys:     []string{"default_key"},
					// Action defaults to "always", List defaults to "exit"
				},
			},
			expectedRules: []string{
				"-a always,exit -S execve -k default_key",
			},
			expectedError: false,
		},
		{
			name: "multiple architectures",
			rule: AuditRuleDefinition{
				Name: "multi-arch-rule",
				Syscall: &SyscallRule{
					Syscalls:     []string{"execve"},
					Keys:         []string{"multi_arch_key"},
					Architecture: []string{"b64", "b32"},
					Filters: []SyscallFilter{
						{Field: "pid", Operator: "=", Value: "1234"},
					},
				},
			},
			expectedRules: []string{
				"-a always,exit -F arch=b64 -F arch=b32 -F pid=1234 -S execve -k multi_arch_key",
			},
			expectedError: false,
		},
		{
			name: "invalid architecture",
			rule: AuditRuleDefinition{
				Name: "invalid-arch-rule",
				Syscall: &SyscallRule{
					Syscalls:     []string{"execve"},
					Keys:         []string{"invalid_arch_key"},
					Architecture: []string{"invalid"},
				},
			},
			expectedError: true,
			errorContains: "invalid architecture",
		},
		{
			name: "invalid action",
			rule: AuditRuleDefinition{
				Name: "invalid-action-rule",
				Syscall: &SyscallRule{
					Syscalls: []string{"execve"},
					Keys:     []string{"invalid_action_key"},
					Action:   "invalid",
				},
			},
			expectedError: true,
			errorContains: "invalid action",
		},
		{
			name: "invalid list",
			rule: AuditRuleDefinition{
				Name: "invalid-list-rule",
				Syscall: &SyscallRule{
					Syscalls: []string{"execve"},
					Keys:     []string{"invalid_list_key"},
					List:     "invalid",
				},
			},
			expectedError: true,
			errorContains: "invalid list",
		},
		{
			name: "missing syscalls",
			rule: AuditRuleDefinition{
				Name: "missing-syscalls-rule",
				Syscall: &SyscallRule{
					Syscalls: []string{}, // Empty syscalls
					Keys:     []string{"missing_syscalls_key"},
				},
			},
			expectedError: true,
			errorContains: "syscall rule must specify at least one syscall",
		},
		{
			name: "missing key",
			rule: AuditRuleDefinition{
				Name: "missing-key-rule",
				Syscall: &SyscallRule{
					Syscalls: []string{"execve"},
					Keys:     nil, // Empty key - now allowed
				},
			},
			expectedRules: []string{"-a always,exit -S execve"},
			expectedError: false, // Key is now optional
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := converter.ConvertRule(tt.rule)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, rules)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, rules)
			assert.Equal(t, tt.expectedRules, rules)
		})
	}
}

func TestConvertFileWatchRule(t *testing.T) {
	converter := NewRuleConverter()

	tests := []struct {
		name          string
		rule          AuditRuleDefinition
		expectedRules []string
		expectedError bool
		errorContains string
	}{
		{
			name: "single path file watch",
			rule: AuditRuleDefinition{
				Name: "passwd-monitoring",
				FileWatch: &FileWatchRule{
					Paths:       []string{"/etc/passwd"},
					Permissions: []string{"write", "attribute"},
					Keys:        []string{"passwd_changes"},
				},
			},
			expectedRules: []string{
				"-w /etc/passwd -p wa -k passwd_changes",
			},
			expectedError: false,
		},
		{
			name: "multiple paths file watch",
			rule: AuditRuleDefinition{
				Name: "multiple-files-monitoring",
				FileWatch: &FileWatchRule{
					Paths:       []string{"/etc/passwd", "/etc/shadow", "/etc/group"},
					Permissions: []string{"read", "write"},
					Keys:        []string{"identity_files"},
				},
			},
			expectedRules: []string{
				"-w /etc/passwd -p rw -k identity_files",
				"-w /etc/shadow -p rw -k identity_files",
				"-w /etc/group -p rw -k identity_files",
			},
			expectedError: false,
		},
		{
			name: "all permissions",
			rule: AuditRuleDefinition{
				Name: "all-permissions-rule",
				FileWatch: &FileWatchRule{
					Paths:       []string{"/var/log"},
					Permissions: []string{"read", "write", "execute", "attribute"},
					Keys:        []string{"log_directory_access"},
				},
			},
			expectedRules: []string{
				"-w /var/log -p rwxa -k log_directory_access",
			},
			expectedError: false,
		},
		{
			name: "with exclusions",
			rule: AuditRuleDefinition{
				Name: "exclusion-rule",
				FileWatch: &FileWatchRule{
					Paths:       []string{"/tmp", "/tmp/exclude"},
					Permissions: []string{"write"},
					Keys:        []string{"tmp_monitoring"},
					Exclude:     []string{"/tmp/exclude"},
				},
			},
			expectedRules: []string{
				"-w /tmp -p w -k tmp_monitoring",
				// /tmp/exclude should be excluded
			},
			expectedError: false,
		},
		{
			name: "invalid permission",
			rule: AuditRuleDefinition{
				Name: "invalid-permission-rule",
				FileWatch: &FileWatchRule{
					Paths:       []string{"/etc/passwd"},
					Permissions: []string{"invalid"},
					Keys:        []string{"invalid_permission_key"},
				},
			},
			expectedError: true,
			errorContains: "invalid permission",
		},
		{
			name: "missing paths",
			rule: AuditRuleDefinition{
				Name: "missing-paths-rule",
				FileWatch: &FileWatchRule{
					Paths:       []string{}, // Empty paths
					Permissions: []string{"write"},
					Keys:        []string{"missing_paths_key"},
				},
			},
			expectedError: true,
			errorContains: "file watch rule must specify at least one path",
		},
		{
			name: "missing permissions",
			rule: AuditRuleDefinition{
				Name: "missing-permissions-rule",
				FileWatch: &FileWatchRule{
					Paths:       []string{"/etc/passwd"},
					Permissions: []string{}, // Empty permissions
					Keys:        []string{"missing_permissions_key"},
				},
			},
			expectedError: true,
			errorContains: "file watch rule must specify at least one permission",
		},
		{
			name: "missing key",
			rule: AuditRuleDefinition{
				Name: "missing-key-rule",
				FileWatch: &FileWatchRule{
					Paths:       []string{"/etc/passwd"},
					Permissions: []string{"write"},
					Keys:        nil, // Empty key
				},
			},
			expectedError: true,
			errorContains: "file watch rule must specify at least one key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := converter.ConvertRule(tt.rule)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, rules)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, rules)
			assert.Equal(t, tt.expectedRules, rules)
		})
	}
}

func TestConvertRawRule(t *testing.T) {
	converter := NewRuleConverter()

	tests := []struct {
		name          string
		rule          AuditRuleDefinition
		expectedRules []string
		expectedError bool
		errorContains string
	}{
		{
			name: "single raw rule",
			rule: AuditRuleDefinition{
				Name:    "package-manager-raw",
				RawRule: "-a always,exit -F arch=b64 -S execve -F comm=apt -F comm=apt-get -F comm=dpkg -F comm=yum -F comm=dnf -k package_manager_raw",
			},
			expectedRules: []string{
				"-a always,exit -F arch=b64 -S execve -F comm=apt -F comm=apt-get -F comm=dpkg -F comm=yum -F comm=dnf -k package_manager_raw",
			},
			expectedError: false,
		},
		{
			name: "multiple raw rules",
			rule: AuditRuleDefinition{
				Name: "multiple-raw-rules",
				RawRule: `-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-a always,exit -F arch=b64 -S execve -k exec`,
			},
			expectedRules: []string{
				"-w /etc/passwd -p wa -k identity",
				"-w /etc/shadow -p wa -k identity",
				"-a always,exit -F arch=b64 -S execve -k exec",
			},
			expectedError: false,
		},
		{
			name: "empty raw rule",
			rule: AuditRuleDefinition{
				Name:    "empty-raw-rule",
				RawRule: "",
			},
			expectedError: true,
			errorContains: "no rule definition provided",
		},
		{
			name: "whitespace only raw rule",
			rule: AuditRuleDefinition{
				Name:    "whitespace-raw-rule",
				RawRule: "   \n  \t  ",
			},
			expectedError: true,
			errorContains: "no valid rules found in raw rule",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := converter.ConvertRule(tt.rule)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, rules)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, rules)
			assert.Equal(t, tt.expectedRules, rules)
		})
	}
}

func TestConvertProcessRule(t *testing.T) {
	converter := NewRuleConverter()

	tests := []struct {
		name          string
		rule          AuditRuleDefinition
		expectedRules []string
		expectedError bool
		errorContains string
	}{
		{
			name: "process rule with executables",
			rule: AuditRuleDefinition{
				Name: "suspicious-commands",
				Process: &ProcessRule{
					Executables: []string{"/bin/nc", "/usr/bin/wget", "/usr/bin/curl"},
					Keys:        []string{"suspicious_exec"},
				},
			},
			expectedRules: []string{
				"-a always,exit -F arch=b64 -S execve -F exe=/bin/nc -F exe=/usr/bin/wget -F exe=/usr/bin/curl -k suspicious_exec",
			},
			expectedError: false,
		},
		{
			name: "process rule with users",
			rule: AuditRuleDefinition{
				Name: "user-specific-process",
				Process: &ProcessRule{
					Users: []string{"root", "admin"},
					Keys:  []string{"privileged_user_exec"},
				},
			},
			expectedRules: []string{
				"-a always,exit -F arch=b64 -S execve -F uid=root -F uid=admin -k privileged_user_exec",
			},
			expectedError: false,
		},
		{
			name: "process rule with groups",
			rule: AuditRuleDefinition{
				Name: "group-specific-process",
				Process: &ProcessRule{
					Groups: []string{"wheel", "sudo"},
					Keys:   []string{"privileged_group_exec"},
				},
			},
			expectedRules: []string{
				"-a always,exit -F arch=b64 -S execve -F gid=wheel -F gid=sudo -k privileged_group_exec",
			},
			expectedError: false,
		},
		{
			name: "process rule with additional filters",
			rule: AuditRuleDefinition{
				Name: "filtered-process",
				Process: &ProcessRule{
					Executables: []string{"/bin/bash"},
					Keys:        []string{"bash_exec"},
					Filters: []SyscallFilter{
						{Field: "pid", Operator: "=", Value: "1234"},
						{Field: "uid", Operator: "!=", Value: "1000"},
					},
				},
			},
			expectedRules: []string{
				"-a always,exit -F arch=b64 -S execve -F exe=/bin/bash -F pid=1234 -F uid!=1000 -k bash_exec",
			},
			expectedError: false,
		},
		{
			name: "process rule with arguments (placeholder)",
			rule: AuditRuleDefinition{
				Name: "argument-process",
				Process: &ProcessRule{
					Executables: []string{"/bin/rm"},
					Arguments:   []string{"-rf", "/"},
					Keys:        []string{"dangerous_rm"},
				},
			},
			expectedRules: []string{
				"-a always,exit -F arch=b64 -S execve -F exe=/bin/rm -k dangerous_rm",
				"# Argument filter '-rf' not directly supported by audit",
				"# Argument filter '/' not directly supported by audit",
			},
			expectedError: false,
		},
		{
			name: "missing key",
			rule: AuditRuleDefinition{
				Name: "missing-key-process",
				Process: &ProcessRule{
					Executables: []string{"/bin/bash"},
					Keys:        nil, // Empty key
				},
			},
			expectedError: true,
			errorContains: "process rule must specify at least one key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := converter.ConvertRule(tt.rule)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, rules)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, rules)
			assert.Equal(t, tt.expectedRules, rules)
		})
	}
}

func TestConvertRuleValidation(t *testing.T) {
	converter := NewRuleConverter()

	tests := []struct {
		name          string
		rule          AuditRuleDefinition
		expectedError bool
		errorContains string
	}{
		{
			name: "no rule definition",
			rule: AuditRuleDefinition{
				Name: "no-rule",
				// No rule type specified
			},
			expectedError: true,
			errorContains: "no rule definition provided",
		},
		{
			name: "multiple rule types",
			rule: AuditRuleDefinition{
				Name: "multiple-rules",
				Syscall: &SyscallRule{
					Syscalls: []string{"execve"},
					Keys:     []string{"syscall_key"},
				},
				FileWatch: &FileWatchRule{
					Paths:       []string{"/etc/passwd"},
					Permissions: []string{"write"},
					Keys:        []string{"filewatch_key"},
				},
			},
			expectedError: true,
			errorContains: "multiple rule types specified",
		},
		{
			name: "invalid filter operator",
			rule: AuditRuleDefinition{
				Name: "invalid-filter-rule",
				Syscall: &SyscallRule{
					Syscalls: []string{"execve"},
					Keys:     []string{"invalid_filter_key"},
					Filters: []SyscallFilter{
						{Field: "pid", Operator: "invalid", Value: "1234"},
					},
				},
			},
			expectedError: true,
			errorContains: "invalid operator",
		},
		{
			name: "empty filter field",
			rule: AuditRuleDefinition{
				Name: "empty-filter-field",
				Syscall: &SyscallRule{
					Syscalls: []string{"execve"},
					Keys:     []string{"empty_field_key"},
					Filters: []SyscallFilter{
						{Field: "", Operator: "=", Value: "1234"},
					},
				},
			},
			expectedError: true,
			errorContains: "filter field cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := converter.ConvertRule(tt.rule)

			assert.Error(t, err)
			if tt.errorContains != "" {
				assert.Contains(t, err.Error(), tt.errorContains)
			}
			assert.Nil(t, rules)
		})
	}
}

func TestValidateRuleDefinition(t *testing.T) {
	converter := NewRuleConverter()

	tests := []struct {
		name           string
		rule           AuditRuleDefinition
		expectedErrors []string
	}{
		{
			name: "valid rule",
			rule: AuditRuleDefinition{
				Name: "valid-rule",
				Syscall: &SyscallRule{
					Syscalls: []string{"execve"},
					Keys:     []string{"valid_key"},
				},
			},
			expectedErrors: []string{},
		},
		{
			name: "empty name",
			rule: AuditRuleDefinition{
				Name: "", // Empty name
				Syscall: &SyscallRule{
					Syscalls: []string{"execve"},
					Keys:     []string{"empty_name_key"},
				},
			},
			expectedErrors: []string{"rule name cannot be empty"},
		},
		{
			name: "invalid rule definition",
			rule: AuditRuleDefinition{
				Name: "invalid-rule",
				Syscall: &SyscallRule{
					Syscalls: []string{}, // Empty syscalls
					Keys:     []string{"invalid_key"},
				},
			},
			expectedErrors: []string{"syscall rule must specify at least one syscall"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := converter.ValidateRuleDefinition(tt.rule)

			if len(tt.expectedErrors) == 0 {
				assert.Empty(t, errors)
			} else {
				assert.Len(t, errors, len(tt.expectedErrors))
				for i, expectedError := range tt.expectedErrors {
					assert.Contains(t, errors[i].Error, expectedError)
				}
			}
		})
	}
}

func TestMatchesPattern(t *testing.T) {
	converter := NewRuleConverter()

	tests := []struct {
		name     string
		path     string
		pattern  string
		expected bool
	}{
		{
			name:     "exact match",
			path:     "/etc/passwd",
			pattern:  "/etc/passwd",
			expected: true,
		},
		{
			name:     "wildcard match",
			path:     "/etc/passwd",
			pattern:  "*",
			expected: true,
		},
		{
			name:     "directory wildcard match",
			path:     "/etc/passwd",
			pattern:  "/etc/*",
			expected: true,
		},
		{
			name:     "directory wildcard no match",
			path:     "/home/user/file",
			pattern:  "/etc/*",
			expected: false,
		},
		{
			name:     "no match",
			path:     "/etc/passwd",
			pattern:  "/etc/shadow",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := converter.matchesPattern(tt.path, tt.pattern)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidArgField(t *testing.T) {
	converter := NewRuleConverter()

	tests := []struct {
		name     string
		field    string
		expected bool
	}{
		{"valid a0", "a0", true},
		{"valid a1", "a1", true},
		{"valid a15", "a15", true},
		{"invalid a", "a", false},
		{"invalid a1a", "a1a", false},
		{"invalid 1a", "1a", false},
		{"invalid empty", "", false},
		{"invalid b0", "b0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := converter.isValidArgField(tt.field)
			assert.Equal(t, tt.expected, result)
		})
	}
}
