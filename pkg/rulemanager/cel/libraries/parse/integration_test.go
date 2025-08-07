package parse

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestParseLibraryIntegration(t *testing.T) {
	// Create CEL environment with parse library
	env, err := cel.NewEnv(
		cel.Variable("data", cel.AnyType),
		Parse(config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
	}

	tests := []struct {
		name     string
		expr     string
		expected string
	}{
		{
			name:     "get exec path with args",
			expr:     "parse.get_exec_path(['/bin/ls', '-la'], 'ls')",
			expected: "/bin/ls",
		},
		{
			name:     "get exec path with empty first arg",
			expr:     "parse.get_exec_path(['', '-la'], 'ls')",
			expected: "ls",
		},
		{
			name:     "get exec path with empty args",
			expr:     "parse.get_exec_path([], 'python')",
			expected: "python",
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
				"data": map[string]interface{}{
					"args": []string{},
					"comm": "test",
				},
			})
			if err != nil {
				t.Fatalf("failed to evaluate expression: %v", err)
			}

			actual, ok := result.Value().(string)
			if !ok {
				t.Fatalf("expected string result, got %T", result.Value())
			}

			assert.Equal(t, tt.expected, actual, "result should match expected value")
		})
	}
}
