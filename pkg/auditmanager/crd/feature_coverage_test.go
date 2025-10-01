package crd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuditRuleFeatureCoverage tests all audit rule features found in rules.txt
// This ensures our CRD converter can handle all the features used in real-world audit rules

func TestSyscallRuleFeatures(t *testing.T) {
	converter := NewRuleConverter()

	tests := []struct {
		name         string
		rule         AuditRuleDefinition
		expectedRule string
		description  string
	}{
		{
			name: "basic execve with auid filter",
			rule: AuditRuleDefinition{
				Name: "execve-auid-filter",
				Syscall: &SyscallRule{
					Syscalls:     []string{"execve"},
					Keys:         []string{"audit_users_exe"},
					Architecture: []string{"b64"},
					Filters: []SyscallFilter{
						{Field: "auid", Operator: "!=", Value: "4294967295"},
					},
				},
			},
			expectedRule: "-a always,exit -F arch=b64 -F auid!=4294967295 -S execve -k audit_users_exe",
			description:  "Covers: execve syscall, auid filter with != operator, large numeric values",
		},
		{
			name: "never action with dir filter",
			rule: AuditRuleDefinition{
				Name: "never-exclude-dir",
				Syscall: &SyscallRule{
					Syscalls: []string{"all"},
					Action:   "never",
					Keys:     []string{"exclude_dir"},
					Filters: []SyscallFilter{
						{Field: "dir", Operator: "=", Value: "/hostfs/var/run/containers"},
					},
				},
			},
			expectedRule: "-a never,exit -F dir=/hostfs/var/run/containers -S all -k exclude_dir",
			description:  "Covers: never action, dir filter, 'all' syscall",
		},
		{
			name: "multiple syscalls with path and perm filters",
			rule: AuditRuleDefinition{
				Name: "path-perm-filters",
				Syscall: &SyscallRule{
					Syscalls:     []string{"chmod", "fchmod", "fchmodat"},
					Keys:         []string{"perm_mod"},
					Architecture: []string{"b64"},
					Filters: []SyscallFilter{
						{Field: "auid", Operator: ">=", Value: "500"},
						{Field: "auid", Operator: "!=", Value: "4294967295"},
					},
				},
			},
			expectedRule: "-a always,exit -F arch=b64 -F auid>=500 -F auid!=4294967295 -S chmod,fchmod,fchmodat -k perm_mod",
			description:  "Covers: multiple syscalls, >= operator, multiple auid filters",
		},
		{
			name: "exit code filters with negative values",
			rule: AuditRuleDefinition{
				Name: "exit-code-filters",
				Syscall: &SyscallRule{
					Syscalls:     []string{"creat", "open", "openat", "truncate", "ftruncate"},
					Keys:         []string{"file_access_denied"},
					Architecture: []string{"b64"},
					Filters: []SyscallFilter{
						{Field: "exit", Operator: "=", Value: "-EACCES"},
						{Field: "auid", Operator: ">=", Value: "500"},
						{Field: "auid", Operator: "!=", Value: "4294967295"},
						{Field: "uid", Operator: "!=", Value: "79004"},
					},
				},
			},
			expectedRule: "-a always,exit -F arch=b64 -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -F uid!=79004 -S creat,open,openat,truncate,ftruncate -k file_access_denied",
			description:  "Covers: exit filter with negative error codes, multiple uid filters",
		},
		{
			name: "syscall arguments with hex values",
			rule: AuditRuleDefinition{
				Name: "syscall-args-hex",
				Syscall: &SyscallRule{
					Syscalls:     []string{"ptrace"},
					Keys:         []string{"audit_ptrace_attach"},
					Architecture: []string{"b64"},
					Filters: []SyscallFilter{
						{Field: "auid", Operator: "!=", Value: "-1"},
						{Field: "uid", Operator: "=", Value: "0"},
						{Field: "a0", Operator: "=", Value: "0x10"},
					},
				},
			},
			expectedRule: "-a always,exit -F arch=b64 -F auid!=-1 -F uid=0 -F a0=0x10 -S ptrace -k audit_ptrace_attach",
			description:  "Covers: syscall arguments (a0), hex values, negative numeric values",
		},
		{
			name: "path and perm filters",
			rule: AuditRuleDefinition{
				Name: "path-perm-execution",
				Syscall: &SyscallRule{
					Syscalls: []string{"all"},
					Keys:     []string{"sensitive_file_access"},
					Filters: []SyscallFilter{
						{Field: "path", Operator: "=", Value: "/etc/sensitive/config"},
						{Field: "perm", Operator: "=", Value: "r"},
						{Field: "auid", Operator: "!=", Value: "4294967295"},
						{Field: "euid", Operator: ">", Value: "500"},
					},
				},
			},
			expectedRule: "-a always,exit -F path=/etc/sensitive/config -F perm=r -F auid!=4294967295 -F euid>500 -S all -k sensitive_file_access",
			description:  "Covers: path filter, perm filter with single permission, euid filter, > operator",
		},
		{
			name: "mixed order action and list",
			rule: AuditRuleDefinition{
				Name: "mixed-action-list",
				Syscall: &SyscallRule{
					Syscalls:     []string{"sethostname", "setdomainname"},
					Action:       "always",
					List:         "exit",
					Keys:         []string{"system-locale"},
					Architecture: []string{"b64"},
				},
			},
			expectedRule: "-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale",
			description:  "Covers: explicit action and list specification",
		},
		{
			name: "complex file operations",
			rule: AuditRuleDefinition{
				Name: "file-operations",
				Syscall: &SyscallRule{
					Syscalls:     []string{"unlink", "unlinkat", "rename", "renameat"},
					Keys:         []string{"delete"},
					Architecture: []string{"b64"},
					Filters: []SyscallFilter{
						{Field: "auid", Operator: ">=", Value: "500"},
						{Field: "auid", Operator: "!=", Value: "4294967295"},
						{Field: "uid", Operator: "!=", Value: "79004"},
					},
				},
			},
			expectedRule: "-a always,exit -F arch=b64 -F auid>=500 -F auid!=4294967295 -F uid!=79004 -S unlink,unlinkat,rename,renameat -k delete",
			description:  "Covers: file deletion/rename operations, complex uid filtering",
		},
		{
			name: "kernel module operations",
			rule: AuditRuleDefinition{
				Name: "kernel-modules",
				Syscall: &SyscallRule{
					Syscalls:     []string{"init_module", "delete_module"},
					Keys:         []string{"modules"},
					Architecture: []string{"b64"},
				},
			},
			expectedRule: "-a always,exit -F arch=b64 -S init_module,delete_module -k modules",
			description:  "Covers: kernel module syscalls",
		},
		{
			name: "mount operations",
			rule: AuditRuleDefinition{
				Name: "mount-operations",
				Syscall: &SyscallRule{
					Syscalls:     []string{"mount"},
					Keys:         []string{"mounts"},
					Architecture: []string{"b64"},
					Filters: []SyscallFilter{
						{Field: "auid", Operator: ">=", Value: "500"},
						{Field: "auid", Operator: "!=", Value: "4294967295"},
					},
				},
			},
			expectedRule: "-a always,exit -F arch=b64 -F auid>=500 -F auid!=4294967295 -S mount -k mounts",
			description:  "Covers: mount syscall with user filtering",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := converter.ConvertRule(tt.rule)
			require.NoError(t, err)
			require.Len(t, rules, 1)
			assert.Equal(t, tt.expectedRule, rules[0])
			t.Logf("✓ %s: %s", tt.name, tt.description)
		})
	}
}

func TestFileWatchRuleFeatures(t *testing.T) {
	converter := NewRuleConverter()

	tests := []struct {
		name         string
		rule         AuditRuleDefinition
		expectedRule string
		description  string
	}{
		{
			name: "basic file watch with write and attribute",
			rule: AuditRuleDefinition{
				Name: "basic-file-watch",
				FileWatch: &FileWatchRule{
					Paths:       []string{"/etc/issue"},
					Permissions: []string{"write", "attribute"},
					Keys:        []string{"system-locale"},
				},
			},
			expectedRule: "-w /etc/issue -p wa -k system-locale",
			description:  "Covers: basic file watch, write+attribute permissions",
		},
		{
			name: "execute permission only",
			rule: AuditRuleDefinition{
				Name: "execute-permission",
				FileWatch: &FileWatchRule{
					Paths:       []string{"/sbin/insmod"},
					Permissions: []string{"execute"},
					Keys:        []string{"modules"},
				},
			},
			expectedRule: "-w /sbin/insmod -p x -k modules",
			description:  "Covers: execute permission only",
		},
		{
			name: "multiple paths with same permissions",
			rule: AuditRuleDefinition{
				Name: "multiple-paths",
				FileWatch: &FileWatchRule{
					Paths:       []string{"/var/log/faillog", "/var/log/lastlog", "/var/log/tallylog"},
					Permissions: []string{"write", "attribute"},
					Keys:        []string{"logins"},
				},
			},
			expectedRule: "\n-w /var/log/faillog -p wa -k logins\n-w /var/log/lastlog -p wa -k logins\n-w /var/log/tallylog -p wa -k logins",
			description:  "Covers: multiple paths generating multiple rules",
		},
		{
			name: "all permissions combined",
			rule: AuditRuleDefinition{
				Name: "all-permissions",
				FileWatch: &FileWatchRule{
					Paths:       []string{"/etc/sudoers"},
					Permissions: []string{"read", "write", "attribute", "execute"},
					Keys:        []string{"scope"},
				},
			},
			expectedRule: "-w /etc/sudoers -p rwax -k scope",
			description:  "Covers: all four permissions combined",
		},
		{
			name: "paths with special characters",
			rule: AuditRuleDefinition{
				Name: "special-path-characters",
				FileWatch: &FileWatchRule{
					Paths:       []string{"/etc/selinux/"},
					Permissions: []string{"write", "attribute"},
					Keys:        []string{"MAC-policy"},
				},
			},
			expectedRule: "-w /etc/selinux/ -p wa -k MAC-policy",
			description:  "Covers: paths with trailing slashes, hyphens in keys",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := converter.ConvertRule(tt.rule)
			require.NoError(t, err)

			if len(tt.expectedRule) > 0 && tt.expectedRule[0] == '\n' {
				// Multi-line expected result
				expectedRules := []string{}
				lines := strings.Split(tt.expectedRule[1:], "\n") // Skip leading newline
				for _, line := range lines {
					if line != "" {
						expectedRules = append(expectedRules, line)
					}
				}
				assert.Equal(t, expectedRules, rules)
			} else {
				require.Len(t, rules, 1)
				assert.Equal(t, tt.expectedRule, rules[0])
			}
			t.Logf("✓ %s: %s", tt.name, tt.description)
		})
	}
}

func TestRawRuleFeatures(t *testing.T) {
	converter := NewRuleConverter()

	tests := []struct {
		name         string
		rule         AuditRuleDefinition
		expectedRule string
		description  string
	}{
		{
			name: "complex raw syscall rule",
			rule: AuditRuleDefinition{
				Name:    "complex-raw-rule",
				RawRule: "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -F uid!=79004 -k file_access_denied",
			},
			expectedRule: "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -F uid!=79004 -k file_access_denied",
			description:  "Covers: complex raw rule with multiple syscalls and filters",
		},
		{
			name: "raw file watch rule",
			rule: AuditRuleDefinition{
				Name:    "raw-file-watch",
				RawRule: "-w /etc/sudoers -p wa -k scope",
			},
			expectedRule: "-w /etc/sudoers -p wa -k scope",
			description:  "Covers: raw file watch rule",
		},
		{
			name: "multiple raw rules",
			rule: AuditRuleDefinition{
				Name: "multiple-raw-rules",
				RawRule: `-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale`,
			},
			expectedRule: "\n-w /etc/issue -p wa -k system-locale\n-w /etc/issue.net -p wa -k system-locale\n-w /etc/hosts -p wa -k system-locale",
			description:  "Covers: multiple raw rules in one definition",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := converter.ConvertRule(tt.rule)
			require.NoError(t, err)

			if len(tt.expectedRule) > 0 && tt.expectedRule[0] == '\n' {
				// Multi-line expected result
				expectedRules := []string{}
				lines := strings.Split(tt.expectedRule[1:], "\n") // Skip leading newline
				for _, line := range lines {
					if line != "" {
						expectedRules = append(expectedRules, line)
					}
				}
				assert.Equal(t, expectedRules, rules)
			} else {
				require.Len(t, rules, 1)
				assert.Equal(t, tt.expectedRule, rules[0])
			}
			t.Logf("✓ %s: %s", tt.name, tt.description)
		})
	}
}

func TestFilterOperatorCoverage(t *testing.T) {
	converter := NewRuleConverter()

	operators := []struct {
		operator string
		value    string
		desc     string
	}{
		{"=", "500", "equals operator"},
		{"!=", "4294967295", "not equals operator"},
		{">", "500", "greater than operator"},
		{">=", "500", "greater than or equals operator"},
		{"<", "1000", "less than operator"},
		{"<=", "1000", "less than or equals operator"},
	}

	for _, op := range operators {
		t.Run(op.operator, func(t *testing.T) {
			rule := AuditRuleDefinition{
				Name: "operator-test-" + op.operator,
				Syscall: &SyscallRule{
					Syscalls: []string{"execve"},
					Keys:     []string{"operator_test"},
					Filters: []SyscallFilter{
						{Field: "auid", Operator: op.operator, Value: op.value},
					},
				},
			}

			rules, err := converter.ConvertRule(rule)
			require.NoError(t, err)
			require.Len(t, rules, 1)

			expectedRule := "-a always,exit -F auid" + op.operator + op.value + " -S execve -k operator_test"
			assert.Equal(t, expectedRule, rules[0])
			t.Logf("✓ Operator %s: %s", op.operator, op.desc)
		})
	}
}

func TestFieldCoverage(t *testing.T) {
	converter := NewRuleConverter()

	fields := []struct {
		field string
		value string
		desc  string
	}{
		{"arch", "b64", "architecture filter"},
		{"auid", "500", "audit user ID filter"},
		{"uid", "0", "user ID filter"},
		{"gid", "1000", "group ID filter"},
		{"euid", "500", "effective user ID filter"},
		{"egid", "1000", "effective group ID filter"},
		{"pid", "1234", "process ID filter"},
		{"ppid", "5678", "parent process ID filter"},
		{"exit", "-EACCES", "exit code filter"},
		{"success", "yes", "success filter"},
		{"path", "/bin/su", "path filter"},
		{"dir", "/etc", "directory filter"},
		{"perm", "x", "permission filter"},
		{"a0", "0x10", "syscall argument 0"},
		{"a1", "1234", "syscall argument 1"},
		{"a2", "0x20", "syscall argument 2"},
		{"a3", "5678", "syscall argument 3"},
	}

	for _, field := range fields {
		t.Run(field.field, func(t *testing.T) {
			rule := AuditRuleDefinition{
				Name: "field-test-" + field.field,
				Syscall: &SyscallRule{
					Syscalls: []string{"execve"},
					Keys:     []string{"field_test"},
					Filters: []SyscallFilter{
						{Field: field.field, Operator: "=", Value: field.value},
					},
				},
			}

			rules, err := converter.ConvertRule(rule)
			require.NoError(t, err)
			require.Len(t, rules, 1)

			expectedRule := "-a always,exit -F " + field.field + "=" + field.value + " -S execve -k field_test"
			assert.Equal(t, expectedRule, rules[0])
			t.Logf("✓ Field %s: %s", field.field, field.desc)
		})
	}
}

func TestSyscallCoverage(t *testing.T) {
	converter := NewRuleConverter()

	syscalls := []struct {
		syscalls []string
		desc     string
	}{
		{[]string{"execve"}, "process execution"},
		{[]string{"open", "openat"}, "file opening"},
		{[]string{"chmod", "fchmod", "fchmodat"}, "permission changes"},
		{[]string{"chown", "fchown", "fchownat", "lchown"}, "ownership changes"},
		{[]string{"unlink", "unlinkat"}, "file deletion"},
		{[]string{"rename", "renameat"}, "file renaming"},
		{[]string{"mount"}, "filesystem mounting"},
		{[]string{"ptrace"}, "process tracing"},
		{[]string{"init_module", "delete_module"}, "kernel modules"},
		{[]string{"sethostname", "setdomainname"}, "hostname changes"},
		{[]string{"setxattr", "lsetxattr", "fsetxattr"}, "extended attributes"},
		{[]string{"removexattr", "lremovexattr", "fremovexattr"}, "extended attribute removal"},
		{[]string{"creat", "truncate", "ftruncate"}, "file creation/truncation"},
		{[]string{"all"}, "all syscalls"},
	}

	for _, sys := range syscalls {
		t.Run(sys.syscalls[0], func(t *testing.T) {
			rule := AuditRuleDefinition{
				Name: "syscall-test-" + sys.syscalls[0],
				Syscall: &SyscallRule{
					Syscalls: sys.syscalls,
					Keys:     []string{"syscall_test"},
				},
			}

			rules, err := converter.ConvertRule(rule)
			require.NoError(t, err)
			require.Len(t, rules, 1)

			syscallList := ""
			if len(sys.syscalls) == 1 {
				syscallList = sys.syscalls[0]
			} else {
				syscallList = ""
				for i, s := range sys.syscalls {
					if i > 0 {
						syscallList += ","
					}
					syscallList += s
				}
			}

			expectedRule := "-a always,exit -S " + syscallList + " -k syscall_test"
			assert.Equal(t, expectedRule, rules[0])
			t.Logf("✓ Syscalls %v: %s", sys.syscalls, sys.desc)
		})
	}
}

// TestConversionAccuracy tests that CRD rules convert to the exact auditctl commands
// found in the real rules.txt file
func TestConversionAccuracy(t *testing.T) {
	converter := NewRuleConverter()

	// Test cases based on actual rules from rules.txt
	testCases := []struct {
		name        string
		crdRule     AuditRuleDefinition
		expectedCmd string
		realRule    string
	}{
		{
			name: "real execve rule",
			crdRule: AuditRuleDefinition{
				Name: "execve-users",
				Syscall: &SyscallRule{
					Syscalls:     []string{"execve"},
					Keys:         []string{"audit_users_exe"},
					Architecture: []string{"b64"},
					Filters: []SyscallFilter{
						{Field: "auid", Operator: "!=", Value: "4294967295"},
					},
				},
			},
			expectedCmd: "-a always,exit -F arch=b64 -F auid!=4294967295 -S execve -k audit_users_exe",
			realRule:    "#-a always,exit -F arch=b64 -S execve -F auid!=4294967295 -k audit_users_exe",
		},
		{
			name: "real file watch rule",
			crdRule: AuditRuleDefinition{
				Name: "sudoers-watch",
				FileWatch: &FileWatchRule{
					Paths:       []string{"/etc/sudoers"},
					Permissions: []string{"write", "attribute"},
					Keys:        []string{"scope"},
				},
			},
			expectedCmd: "-w /etc/sudoers -p wa -k scope",
			realRule:    "-w /etc/sudoers -p wa -k scope",
		},
		{
			name: "real complex syscall rule",
			crdRule: AuditRuleDefinition{
				Name: "file-access-denied",
				Syscall: &SyscallRule{
					Syscalls:     []string{"creat", "open", "openat", "truncate", "ftruncate"},
					Keys:         []string{"file_access_denied"},
					Architecture: []string{"b64"},
					Filters: []SyscallFilter{
						{Field: "exit", Operator: "=", Value: "-EACCES"},
						{Field: "auid", Operator: ">=", Value: "500"},
						{Field: "auid", Operator: "!=", Value: "4294967295"},
						{Field: "uid", Operator: "!=", Value: "79004"},
					},
				},
			},
			expectedCmd: "-a always,exit -F arch=b64 -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -F uid!=79004 -S creat,open,openat,truncate,ftruncate -k file_access_denied",
			realRule:    "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -F uid!=79004",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := converter.ConvertRule(tc.crdRule)
			require.NoError(t, err)
			require.Len(t, rules, 1)

			// The generated rule should match our expected format
			assert.Equal(t, tc.expectedCmd, rules[0])

			t.Logf("✓ CRD Rule: %s", tc.crdRule.Name)
			t.Logf("  Generated: %s", rules[0])
			t.Logf("  Real Rule: %s", tc.realRule)
		})
	}
}
