package parse

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestParseLibrary(t *testing.T) {
	env, err := cel.NewEnv(
		cel.Variable("event", cel.AnyType),
		Parse(config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	tests := []struct {
		name     string
		expr     string
		expected string
	}{
		{
			name:     "args with first element",
			expr:     "parse.get_exec_path(['/bin/ls', '-la'], 'ls')",
			expected: "/bin/ls",
		},
		{
			name:     "args with empty first element",
			expr:     "parse.get_exec_path(['', '-la'], 'ls')",
			expected: "ls",
		},
		{
			name:     "empty args list",
			expr:     "parse.get_exec_path([], 'ls')",
			expected: "ls",
		},
		{
			name:     "single element in args",
			expr:     "parse.get_exec_path(['/usr/bin/python'], 'python')",
			expected: "/usr/bin/python",
		},
		{
			name:     "basename with full path",
			expr:     "parse.basename('/usr/bin/nmap')",
			expected: "nmap",
		},
		{
			name:     "basename with just filename",
			expr:     "parse.basename('nmap')",
			expected: "nmap",
		},
		{
			name:     "basename with trailing slash",
			expr:     "parse.basename('/usr/bin/')",
			expected: "",
		},
		{
			name:     "basename with root path",
			expr:     "parse.basename('/nmap')",
			expected: "nmap",
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
					"args": []string{},
					"comm": "test",
				},
			})
			if err != nil {
				t.Fatalf("failed to eval program: %v", err)
			}

			actual, ok := result.Value().(string)
			if !ok {
				t.Fatalf("expected string result, got %T", result.Value())
			}

			assert.Equal(t, tt.expected, actual, "result should match expected value")
		})
	}
}

func TestCelBindWithJoinedArgs(t *testing.T) {
	env, err := cel.NewEnv(
		cel.Variable("event", cel.AnyType),
		Parse(config.Config{}),
		ext.Strings(),
		ext.Bindings(),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	tests := []struct {
		name     string
		expr     string
		args     []string
		expected bool
	}{
		{
			name:     "cel.bind caches joined args - match",
			expr:     "cel.bind(joined_args, event.args.join(' '), joined_args.contains('-e') && joined_args.contains('cmd'))",
			args:     []string{"nc", "-e", "/bin/sh", "cmd"},
			expected: true,
		},
		{
			name:     "cel.bind caches joined args - no match",
			expr:     "cel.bind(joined_args, event.args.join(' '), joined_args.contains('-e') && joined_args.contains('cmd'))",
			args:     []string{"ls", "-la"},
			expected: false,
		},
		{
			name:     "cel.bind with multiple contains checks",
			expr:     "cel.bind(joined_args, event.args.join(' '), joined_args.contains('socket') || joined_args.contains('exec') || joined_args.contains('pty'))",
			args:     []string{"python", "-c", "import pty; pty.spawn('/bin/sh')"},
			expected: true,
		},
		{
			name:     "cel.bind with empty args",
			expr:     "cel.bind(joined_args, event.args.join(' '), joined_args.contains('test'))",
			args:     []string{},
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
					"args": tt.args,
					"comm": "test",
				},
			})
			if err != nil {
				t.Fatalf("failed to eval program: %v", err)
			}

			actual, ok := result.Value().(bool)
			if !ok {
				t.Fatalf("expected bool result, got %T", result.Value())
			}

			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestParseLibraryErrorCases(t *testing.T) {
	env, err := cel.NewEnv(
		cel.Variable("event", cel.AnyType),
		Parse(config.Config{}),
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
			expr:        "parse.get_exec_path(['/bin/ls'])",
			expectError: true,
		},
		{
			name:        "wrong argument types",
			expr:        "parse.get_exec_path('not a list', 'ls')",
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
					"args": []string{},
					"comm": "test",
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
