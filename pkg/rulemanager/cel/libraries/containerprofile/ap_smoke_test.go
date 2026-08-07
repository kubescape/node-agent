package containerprofile

import (
	"sort"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/kubescape/node-agent/pkg/config"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/stretchr/testify/assert"
)

// TestDeclarationsCompileEachOverload builds a CEL env with the cp library
// and compiles + programs a representative call for every function declared
// by the library. It is a registration-regression guard: if an overload is
// wired with the wrong argument types (or dropped/renamed), the matching
// expression fails to compile or program, failing the test. No cluster or
// profile is required — only the type-checker and program binder run.
//
// The exprByFunc map is asserted to cover EXACTLY the set of functions in
// Declarations(), so adding or removing a declared function without updating
// this smoke test is itself a failure.
func TestDeclarationsCompileEachOverload(t *testing.T) {
	// One well-typed call site per declared function.
	exprByFunc := map[string]string{
		"cp.was_executed":                       `cp.was_executed(containerID, s)`,
		"cp.was_executed_with_args":             `cp.was_executed_with_args(containerID, s, strs)`,
		"cp.was_path_opened":                    `cp.was_path_opened(containerID, s)`,
		"cp.was_path_opened_with_flags":         `cp.was_path_opened_with_flags(containerID, s, strs)`,
		"cp.was_path_opened_with_suffix":        `cp.was_path_opened_with_suffix(containerID, s)`,
		"cp.was_path_opened_with_prefix":        `cp.was_path_opened_with_prefix(containerID, s)`,
		"cp.was_syscall_used":                   `cp.was_syscall_used(containerID, s)`,
		"cp.was_capability_used":                `cp.was_capability_used(containerID, s)`,
		"cp.was_endpoint_accessed":              `cp.was_endpoint_accessed(containerID, s)`,
		"cp.was_endpoint_accessed_with_method":  `cp.was_endpoint_accessed_with_method(containerID, s, s)`,
		"cp.was_endpoint_accessed_with_methods": `cp.was_endpoint_accessed_with_methods(containerID, s, strs)`,
		"cp.was_endpoint_accessed_with_prefix":  `cp.was_endpoint_accessed_with_prefix(containerID, s)`,
		"cp.was_endpoint_accessed_with_suffix":  `cp.was_endpoint_accessed_with_suffix(containerID, s)`,
		"cp.was_host_accessed":                  `cp.was_host_accessed(containerID, s)`,
	}

	objCache := objectcachev1.RuleObjectCacheMock{}
	lib := New(&objCache, config.Config{})

	// The smoke test must track the library's declared surface exactly.
	declared := make([]string, 0)
	for name := range lib.(*containerProfileLibrary).Declarations() {
		declared = append(declared, name)
	}
	covered := make([]string, 0, len(exprByFunc))
	for name := range exprByFunc {
		covered = append(covered, name)
	}
	sort.Strings(declared)
	sort.Strings(covered)
	assert.Equal(t, declared, covered,
		"exprByFunc must cover exactly the functions in Declarations() — a drift means a function was added/removed without updating this smoke test")

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("s", cel.StringType),
		cel.Variable("strs", cel.ListType(cel.StringType)),
		CP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	// Activation for the eval pass: an empty objectCache has no profile, so
	// every helper resolves to false via ConvertProfileNotAvailableErrToBool.
	// Eval exercises each declared function's binding closure end-to-end.
	activation := map[string]interface{}{
		"containerID": "cid",
		"s":           "x",
		"strs":        []string{"a", "b"},
	}

	for name, expr := range exprByFunc {
		t.Run(name, func(t *testing.T) {
			ast, issues := env.Compile(expr)
			if issues != nil && issues.Err() != nil {
				t.Fatalf("compile %q failed: %v", expr, issues.Err())
			}
			program, err := env.Program(ast)
			if err != nil {
				t.Fatalf("program %q failed: %v", expr, err)
			}
			out, _, err := program.Eval(activation)
			if err != nil {
				t.Fatalf("eval %q failed: %v", expr, err)
			}
			// With no profile in the cache every helper degrades to false.
			assert.Equal(t, false, out.Value(), "expr %q should evaluate to false with no profile", expr)
		})
	}
}
