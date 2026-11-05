package net

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestNetLibrary(t *testing.T) {
	env, err := cel.NewEnv(
		cel.Variable("event", cel.AnyType),
		Net(config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	tests := []struct {
		name     string
		expr     string
		expected bool
	}{
		{name: "fc00::", expr: "net.is_private_ip('fc00::')", expected: true},
		{name: "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", expr: "net.is_private_ip('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')", expected: true},
		{name: "fbff:ffff::1", expr: "net.is_private_ip('fbff:ffff::1')", expected: false},
		{name: "fe00::", expr: "net.is_private_ip('fe00::')", expected: false},
		{name: "fe80::", expr: "net.is_private_ip('fe80::')", expected: true},
		{name: "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", expr: "net.is_private_ip('febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff')", expected: true},
		{name: "fe7f:ffff::1", expr: "net.is_private_ip('fe7f:ffff::1')", expected: false},
		{name: "fec0::", expr: "net.is_private_ip('fec0::')", expected: false},
		{name: "2001:4860:4860::8888", expr: "net.is_private_ip('2001:4860:4860::8888')", expected: false},
		{name: "::", expr: "net.is_private_ip('::')", expected: false},
		{name: "100.64.0.0", expr: "net.is_private_ip('100.64.0.0')", expected: true},
		{name: "100.127.255.255", expr: "net.is_private_ip('100.127.255.255')", expected: true},
		{name: "100.63.255.255", expr: "net.is_private_ip('100.63.255.255')", expected: false},
		{name: "100.128.0.0", expr: "net.is_private_ip('100.128.0.0')", expected: false},
		{name: "::ffff:100.64.0.1", expr: "net.is_private_ip('::ffff:100.64.0.1')", expected: true},
		{name: "::ffff:8.8.8.8", expr: "net.is_private_ip('::ffff:8.8.8.8')", expected: false},
		{
			name:     "localhost IPv4",
			expr:     "net.is_private_ip('127.0.0.1')",
			expected: true,
		},
		{
			name:     "localhost IPv6",
			expr:     "net.is_private_ip('::1')",
			expected: true,
		},
		{
			name:     "private IP 10.x.x.x",
			expr:     "net.is_private_ip('10.0.0.1')",
			expected: true,
		},
		{
			name:     "private IP 172.16.x.x",
			expr:     "net.is_private_ip('172.16.0.1')",
			expected: true,
		},
		{
			name:     "private IP 172.31.x.x",
			expr:     "net.is_private_ip('172.31.255.255')",
			expected: true,
		},
		{
			name:     "private IP 192.168.x.x",
			expr:     "net.is_private_ip('192.168.1.1')",
			expected: true,
		},
		{
			name:     "multicast IP",
			expr:     "net.is_private_ip('224.0.0.1')",
			expected: true,
		},
		{
			name:     "experimental IP",
			expr:     "net.is_private_ip('240.0.0.1')",
			expected: true,
		},
		{
			name:     "APIPA IP",
			expr:     "net.is_private_ip('169.254.1.1')",
			expected: true,
		},
		{
			name:     "public IP",
			expr:     "net.is_private_ip('8.8.8.8')",
			expected: false,
		},
		{
			name:     "another public IP",
			expr:     "net.is_private_ip('1.1.1.1')",
			expected: false,
		},
		{
			name:     "invalid IP",
			expr:     "net.is_private_ip('invalid-ip')",
			expected: false,
		},
		{
			name:     "empty string",
			expr:     "net.is_private_ip('')",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, issues := env.Compile(tt.expr)
			if issues != nil {
				t.Fatalf("failed to compile expression: %v", issues.Err())
			}

			program, err := env.Program(ast)
			if err != nil {
				t.Fatalf("failed to create program: %v", err)
			}

			result, _, err := program.Eval(map[string]any{
				"event": map[string]any{
					"ip": "test",
				},
			})
			if err != nil {
				t.Fatalf("failed to eval program: %v", err)
			}

			actual, ok := result.Value().(bool)
			if !ok {
				t.Fatalf("expected bool result, got %T", result.Value())
			}

			assert.Equal(t, tt.expected, actual, "result should match expected value")
		})
	}
}

func TestNetLibraryErrorCases(t *testing.T) {
	env, err := cel.NewEnv(
		cel.Variable("event", cel.AnyType),
		Net(config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	tests := []struct {
		name        string
		expr        string
		expectError bool
	}{
		{
			name:        "wrong number of arguments",
			expr:        "net.is_private_ip()",
			expectError: true,
		},
		{
			name:        "too many arguments",
			expr:        "net.is_private_ip('127.0.0.1', 'extra')",
			expectError: true,
		},
		{
			name:        "wrong argument type",
			expr:        "net.is_private_ip(123)",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, issues := env.Compile(tt.expr)
			if issues != nil {
				if tt.expectError {
					return // Expected compilation error
				}
				t.Fatalf("failed to compile expression: %v", issues.Err())
			}

			program, err := env.Program(ast)
			if err != nil {
				if tt.expectError {
					return // Expected program creation error
				}
				t.Fatalf("failed to create program: %v", err)
			}

			_, _, err = program.Eval(map[string]any{
				"event": map[string]any{
					"ip": "test",
				},
			})
			if err != nil && tt.expectError {
				return // Expected evaluation error
			}
			if err != nil && !tt.expectError {
				t.Fatalf("unexpected error during evaluation: %v", err)
			}
		})
	}
}

func TestFormatEndpoint(t *testing.T) {
	env, err := cel.NewEnv(
		cel.Variable("event", cel.MapType(cel.StringType, cel.DynType)),
		Net(config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	tests := []struct {
		name     string
		expr     string
		event    map[string]any
		expected string
	}{
		{name: "IPv4", expr: "net.format_endpoint('10.0.0.5', 23)", expected: "10.0.0.5:23"},
		{name: "IPv6", expr: "net.format_endpoint('fd00::1', 23)", expected: "[fd00::1]:23"},
		{name: "IPv6 loopback", expr: "net.format_endpoint('::1', 443)", expected: "[::1]:443"},
		{name: "IPv4-mapped IPv6", expr: "net.format_endpoint('::ffff:8.8.8.8', 53)", expected: "[::ffff:8.8.8.8]:53"},
		{name: "IPv6 with zone", expr: "net.format_endpoint('fe80::1%eth0', 22)", expected: "[fe80::1%eth0]:22"},
		{name: "hostname", expr: "net.format_endpoint('example.com', 80)", expected: "example.com:80"},
		{name: "empty address", expr: "net.format_endpoint('', 80)", expected: ":80"},
		{name: "port zero", expr: "net.format_endpoint('10.0.0.5', 0)", expected: "10.0.0.5:0"},
		{
			name:     "event fields IPv6",
			expr:     "net.format_endpoint(event.dstAddr, event.dstPort)",
			event:    map[string]any{"dstAddr": "fd00::1", "dstPort": int64(23)},
			expected: "[fd00::1]:23",
		},
		{
			name:     "event fields IPv4",
			expr:     "'connected to ' + net.format_endpoint(event.dstAddr, event.dstPort)",
			event:    map[string]any{"dstAddr": "10.0.0.5", "dstPort": int64(23)},
			expected: "connected to 10.0.0.5:23",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, issues := env.Compile(tt.expr)
			if issues != nil {
				t.Fatalf("failed to compile expression: %v", issues.Err())
			}
			program, err := env.Program(ast)
			if err != nil {
				t.Fatalf("failed to create program: %v", err)
			}
			event := tt.event
			if event == nil {
				event = map[string]any{}
			}
			result, _, err := program.Eval(map[string]any{"event": event})
			if err != nil {
				t.Fatalf("failed to eval program: %v", err)
			}
			assert.Equal(t, tt.expected, result.Value())
		})
	}
}

func TestFormatEndpointErrorCases(t *testing.T) {
	env, err := cel.NewEnv(Net(config.Config{}))
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	for _, expr := range []string{
		"net.format_endpoint('10.0.0.5')",
		"net.format_endpoint(23, '10.0.0.5')",
		"net.format_endpoint('10.0.0.5', '23')",
		"net.format_endpoint('10.0.0.5', 23, 'extra')",
	} {
		t.Run(expr, func(t *testing.T) {
			_, issues := env.Compile(expr)
			assert.Error(t, issues.Err(), "expected a compile error")
		})
	}
}
