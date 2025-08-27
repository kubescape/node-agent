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

			result, _, err := program.Eval(map[string]interface{}{
				"event": map[string]interface{}{
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

			_, _, err = program.Eval(map[string]interface{}{
				"event": map[string]interface{}{
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
