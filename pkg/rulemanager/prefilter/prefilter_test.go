package prefilter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseWithDefaults(t *testing.T) {
	tests := []struct {
		name          string
		ruleState     map[string]any
		bindingParams map[string]any
		expect        *Params
	}{
		{
			name:   "both nil",
			expect: nil,
		},
		{
			name:          "binding params only — ignorePrefixes",
			bindingParams: map[string]any{"ignorePrefixes": []interface{}{"/tmp", "/var/log"}},
			expect:        &Params{IgnorePrefixes: []string{"/tmp", "/var/log"}},
		},
		{
			name:          "trailing slash stripped from prefix",
			bindingParams: map[string]any{"ignorePrefixes": []interface{}{"/tmp/", "/var/log/"}},
			expect:        &Params{IgnorePrefixes: []string{"/tmp", "/var/log"}},
		},
		{
			name:      "rule state only — direction and methods",
			ruleState: map[string]any{"direction": "inbound", "methods": []interface{}{"POST", "PUT"}},
			expect:    &Params{Dir: DirInbound, MethodMask: MethodPOST | MethodPUT},
		},
		{
			name:          "binding overrides rule state",
			ruleState:     map[string]any{"direction": "inbound"},
			bindingParams: map[string]any{"direction": "outbound"},
			expect:        &Params{Dir: DirOutbound},
		},
		{
			name:          "merge: state has direction, binding has prefixes",
			ruleState:     map[string]any{"direction": "inbound", "methods": []interface{}{"POST"}},
			bindingParams: map[string]any{"ignorePrefixes": []interface{}{"/tmp"}},
			expect:        &Params{Dir: DirInbound, MethodMask: MethodPOST, IgnorePrefixes: []string{"/tmp"}},
		},
		{
			name:          "ports (float64 from JSON)",
			bindingParams: map[string]any{"ports": []interface{}{float64(22), float64(2222)}},
			expect:        &Params{Ports: []uint16{22, 2222}},
		},
		{
			name:          "file path prefix not broken by trailing-slash normalization",
			bindingParams: map[string]any{"ignorePrefixes": []interface{}{"/etc/passwd"}},
			expect:        &Params{IgnorePrefixes: []string{"/etc/passwd"}},
		},
		{
			name:      "direction normalized to lowercase",
			ruleState: map[string]any{"direction": "Inbound"},
			expect:    &Params{Dir: DirInbound},
		},
		{
			name:          "non-filterable keys only",
			bindingParams: map[string]any{"enforceArgs": true, "additionalPaths": []interface{}{"/etc/shadow"}},
			expect:        nil,
		},
		{
			name:          "non-filterable in state, filterable in binding",
			ruleState:     map[string]any{"enforceArgs": true},
			bindingParams: map[string]any{"ignorePrefixes": []interface{}{"/tmp"}},
			expect:        &Params{IgnorePrefixes: []string{"/tmp"}},
		},
		{
			name: "excludeProcesses parsed",
			bindingParams: map[string]any{
				"excludeProcesses": []interface{}{
					map[string]interface{}{"name": "dockerd", "path": "/usr/bin/dockerd"},
				},
			},
			expect: &Params{
				ExcludeProcesses: map[processKey]struct{}{
					{Name: "dockerd", Path: "/usr/bin/dockerd"}: {},
				},
			},
		},
		{
			name: "excludeParentProcesses parsed with multiple entries",
			bindingParams: map[string]any{
				"excludeParentProcesses": []interface{}{
					map[string]interface{}{"name": "inspectorssmplu", "path": "/usr/bin/inspector-ssm-plugin"},
					map[string]interface{}{"name": "ssm-agent-worke", "path": "/usr/bin/ssm-agent-worker"},
				},
			},
			expect: &Params{
				ExcludeParentProcesses: map[processKey]struct{}{
					{Name: "inspectorssmplu", Path: "/usr/bin/inspector-ssm-plugin"}: {},
					{Name: "ssm-agent-worke", Path: "/usr/bin/ssm-agent-worker"}:     {},
				},
			},
		},
		{
			name: "excludeProcesses mixed valid and invalid entries",
			bindingParams: map[string]any{
				"excludeProcesses": []interface{}{
					map[string]interface{}{"name": "", "path": "/usr/bin/foo"},
					map[string]interface{}{"name": "dockerd", "path": "/usr/bin/dockerd"},
				},
			},
			expect: &Params{
				ExcludeProcesses: map[processKey]struct{}{
					{Name: "dockerd", Path: "/usr/bin/dockerd"}: {},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseWithDefaults(tt.ruleState, tt.bindingParams)
			if tt.expect == nil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, tt.expect, got)
			}
		})
	}
}

func TestShouldSkip(t *testing.T) {
	tests := []struct {
		name   string
		params *Params
		event  EventFields
		want   bool
	}{
		// --- nil / empty ---
		{"nil params", nil, EventFields{}, false},
		{"empty params", &Params{}, EventFields{Path: "/etc/passwd"}, false},

		// --- ignorePrefixes ---
		{"ignore match /tmp", &Params{IgnorePrefixes: []string{"/tmp", "/var/log"}}, EventFields{Path: "/tmp/foo.txt"}, true},
		{"ignore match /var/log", &Params{IgnorePrefixes: []string{"/tmp", "/var/log"}}, EventFields{Path: "/var/log/syslog"}, true},
		{"ignore exact match", &Params{IgnorePrefixes: []string{"/etc/passwd"}}, EventFields{Path: "/etc/passwd"}, true},
		{"ignore no match", &Params{IgnorePrefixes: []string{"/tmp", "/var/log"}}, EventFields{Path: "/etc/passwd"}, false},
		{"ignore directory boundary", &Params{IgnorePrefixes: []string{"/tmp"}}, EventFields{Path: "/tmpfiles/secret"}, false},
		{"ignore empty path skipped", &Params{IgnorePrefixes: []string{"/tmp"}}, EventFields{}, false},
		{"ignore exact file path not broken by slash append", &Params{IgnorePrefixes: []string{"/etc/passwd"}}, EventFields{Path: "/etc/passwd"}, true},

		// --- includePrefixes ---
		{"include match", &Params{IncludePrefixes: []string{"/etc", "/usr"}}, EventFields{Path: "/etc/passwd"}, false},
		{"include exact match", &Params{IncludePrefixes: []string{"/etc/passwd"}}, EventFields{Path: "/etc/passwd"}, false},
		{"include no match", &Params{IncludePrefixes: []string{"/etc", "/usr"}}, EventFields{Path: "/tmp/foo.txt"}, true},

		// --- both prefixes (ignore wins) ---
		{"both: ignored subdir", &Params{IncludePrefixes: []string{"/etc"}, IgnorePrefixes: []string{"/etc/default"}}, EventFields{Path: "/etc/default/grub"}, true},
		{"both: included not ignored", &Params{IncludePrefixes: []string{"/etc"}, IgnorePrefixes: []string{"/etc/default"}}, EventFields{Path: "/etc/passwd"}, false},

		// --- direction ---
		{"direction match", &Params{Dir: DirInbound}, EventFields{Dir: DirInbound}, false},
		{"direction mismatch", &Params{Dir: DirInbound}, EventFields{Dir: DirOutbound}, true},
		{"direction empty event (non-HTTP)", &Params{Dir: DirInbound}, EventFields{}, false},

		// --- methods ---
		{"method match POST", &Params{MethodMask: MethodPOST | MethodPUT}, EventFields{MethodBit: MethodPOST}, false},
		{"method match PUT", &Params{MethodMask: MethodPOST | MethodPUT}, EventFields{MethodBit: MethodPUT}, false},
		{"method mismatch GET", &Params{MethodMask: MethodPOST | MethodPUT}, EventFields{MethodBit: MethodGET}, true},
		{"method empty event (non-HTTP)", &Params{MethodMask: MethodPOST}, EventFields{}, false},

		// --- ports (scoped to SSH/network via PortEligible) ---
		{"port in monitored list (keep)", &Params{Ports: []uint16{22, 2222}}, EventFields{DstPort: 22, PortEligible: true}, false},
		{"port in monitored list single (keep)", &Params{Ports: []uint16{22}}, EventFields{DstPort: 22, PortEligible: true}, false},
		{"port not in monitored list (skip)", &Params{Ports: []uint16{22, 2222}}, EventFields{DstPort: 8080, PortEligible: true}, true},
		{"port zero (non-network)", &Params{Ports: []uint16{22}}, EventFields{}, false},
		{"HTTP port not filtered by ports", &Params{Ports: []uint16{22}}, EventFields{DstPort: 22, PortEligible: false}, false},

		// --- combined: HTTP direction + method ---
		{"HTTP direction mismatch skips", &Params{Dir: DirInbound, MethodMask: MethodPOST | MethodPUT}, EventFields{Dir: DirOutbound, MethodBit: MethodPOST}, true},
		{"HTTP method mismatch skips", &Params{Dir: DirInbound, MethodMask: MethodPOST | MethodPUT}, EventFields{Dir: DirInbound, MethodBit: MethodGET}, true},
		{"HTTP both pass", &Params{Dir: DirInbound, MethodMask: MethodPOST | MethodPUT}, EventFields{Dir: DirInbound, MethodBit: MethodPOST}, false},

		// --- combined: file path include + ignore ---
		{"file: not in include", &Params{IncludePrefixes: []string{"/etc"}, IgnorePrefixes: []string{"/etc/default"}}, EventFields{Path: "/tmp/foo"}, true},
		{"file: in include but ignored", &Params{IncludePrefixes: []string{"/etc"}, IgnorePrefixes: []string{"/etc/default"}}, EventFields{Path: "/etc/default/grub"}, true},
		{"file: in include not ignored", &Params{IncludePrefixes: []string{"/etc"}, IgnorePrefixes: []string{"/etc/default"}}, EventFields{Path: "/etc/shadow"}, false},

		// --- excludeProcesses (comm + exepath pair) ---
		{
			"excludeProcesses: both match",
			&Params{ExcludeProcesses: map[processKey]struct{}{{Name: "dockerd", Path: "/usr/bin/dockerd"}: {}}},
			EventFields{Comm: "dockerd", Path: "/usr/bin/dockerd"},
			true,
		},
		{
			"excludeProcesses: comm matches but path differs (anti-spoof)",
			&Params{ExcludeProcesses: map[processKey]struct{}{{Name: "dockerd", Path: "/usr/bin/dockerd"}: {}}},
			EventFields{Comm: "dockerd", Path: "/tmp/attacker/dockerd"},
			false,
		},
		{
			"excludeProcesses: path matches but comm differs",
			&Params{ExcludeProcesses: map[processKey]struct{}{{Name: "dockerd", Path: "/usr/bin/dockerd"}: {}}},
			EventFields{Comm: "rpm", Path: "/usr/bin/dockerd"},
			false,
		},
		{
			"excludeProcesses: empty comm on event (no skip)",
			&Params{ExcludeProcesses: map[processKey]struct{}{{Name: "dockerd", Path: "/usr/bin/dockerd"}: {}}},
			EventFields{Path: "/usr/bin/dockerd"},
			false,
		},
		{
			"excludeProcesses: empty path on event (no skip)",
			&Params{ExcludeProcesses: map[processKey]struct{}{{Name: "dockerd", Path: "/usr/bin/dockerd"}: {}}},
			EventFields{Comm: "dockerd"},
			false,
		},

		// --- excludeParentProcesses (pcomm + parent_exepath pair) ---
		{
			"excludeParentProcesses: both match (R1058 ssm-agent-worker)",
			&Params{ExcludeParentProcesses: map[processKey]struct{}{{Name: "ssm-agent-worke", Path: "/usr/bin/ssm-agent-worker"}: {}}},
			EventFields{Pcomm: "ssm-agent-worke", ParentExePath: "/usr/bin/ssm-agent-worker"},
			true,
		},
		{
			"excludeParentProcesses: pcomm matches but parent path differs",
			&Params{ExcludeParentProcesses: map[processKey]struct{}{{Name: "ssm-agent-worke", Path: "/usr/bin/ssm-agent-worker"}: {}}},
			EventFields{Pcomm: "ssm-agent-worke", ParentExePath: "/tmp/fake"},
			false,
		},
		{
			"excludeParentProcesses: empty pcomm on event (no skip)",
			&Params{ExcludeParentProcesses: map[processKey]struct{}{{Name: "ssm-agent-worke", Path: "/usr/bin/ssm-agent-worker"}: {}}},
			EventFields{ParentExePath: "/usr/bin/ssm-agent-worker"},
			false,
		},
		{
			"excludeProcesses and excludeParentProcesses: neither matches",
			&Params{
				ExcludeProcesses:       map[processKey]struct{}{{Name: "dockerd", Path: "/usr/bin/dockerd"}: {}},
				ExcludeParentProcesses: map[processKey]struct{}{{Name: "ssm-agent-worke", Path: "/usr/bin/ssm-agent-worker"}: {}},
			},
			EventFields{Comm: "rpm", Path: "/usr/bin/rpm", Pcomm: "bash", ParentExePath: "/bin/bash"},
			false,
		},
		{
			"excludeProcesses does not fire when path is an unrelated file (open event shape)",
			&Params{
				IgnorePrefixes:   []string{"/tmp"},
				ExcludeProcesses: map[processKey]struct{}{{Name: "dockerd", Path: "/usr/bin/dockerd"}: {}},
			},
			EventFields{Path: "/etc/passwd", Comm: "rpm"},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.params.ShouldSkip(tt.event))
		})
	}
}

func BenchmarkShouldSkip_EarlyExit(b *testing.B) {
	p := &Params{
		Dir:            DirInbound,
		MethodMask:     MethodPOST | MethodPUT,
		IgnorePrefixes: []string{"/tmp", "/var/log"},
	}
	e := EventFields{Path: "/etc/passwd", Dir: DirOutbound, MethodBit: MethodGET}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.ShouldSkip(e)
	}
}

func BenchmarkShouldSkip_FullScan(b *testing.B) {
	p := &Params{
		Dir:            DirInbound,
		MethodMask:     MethodPOST | MethodPUT,
		IgnorePrefixes: []string{"/tmp", "/var/log"},
	}
	e := EventFields{Path: "/etc/passwd", Dir: DirInbound, MethodBit: MethodPOST}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.ShouldSkip(e)
	}
}
