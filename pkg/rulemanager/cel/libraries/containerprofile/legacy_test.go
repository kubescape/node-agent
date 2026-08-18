package containerprofile

import (
	"sort"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
	"github.com/stretchr/testify/assert"
)

// TestLegacyAPDeclarationsMirrorCP is a drift guard: AP() must expose
// exactly the cp.* function set under the ap. prefix, one-for-one, with no
// functions gained or lost, and every ap.* overload id must be unique from
// its cp.* counterpart (cel-go requires overload ids to be unique per
// environment). If this test needs updating because Declarations() changed,
// the same update belongs in TestDeclarationsCompileEachOverload.
func TestLegacyAPDeclarationsMirrorCP(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{}
	base := New(&objCache, config.Config{}).(*containerProfileLibrary)
	alias := &legacyContainerProfileLibrary{base: base, name: "ap", prefix: "ap."}

	wantNames := make([]string, 0)
	for name := range base.Declarations() {
		wantNames = append(wantNames, "ap."+strings.TrimPrefix(name, "cp."))
	}
	gotNames := make([]string, 0)
	for name := range alias.Declarations() {
		gotNames = append(gotNames, name)
	}
	sort.Strings(wantNames)
	sort.Strings(gotNames)
	assert.Equal(t, wantNames, gotNames, "ap.* alias set must exactly mirror cp.*'s declared functions")
	assert.Equal(t, "ap", alias.LibraryName())

	// Registering both namespaces in one env must not collide (this is what
	// blows up at cel.NewEnv/env.Program time if overload ids aren't unique).
	_, err := cel.NewEnv(CP(&objCache, config.Config{}), AP(&objCache, config.Config{}))
	assert.NoError(t, err, "cp.* and ap.* must register into the same env without overload id collisions")
}

// TestLegacyAPMatchesCP_ExecOpenSyscallCapability proves that the ap.*
// aliases for the exec/open/syscall/capability helpers evaluate identically
// to their cp.* equivalents against the same ContainerProfile data — and
// that cp.* itself is unaffected by AP() also being registered in the env
// (regression guard for #864's cp.* namespace).
func TestLegacyAPMatchesCP_ExecOpenSyscallCapability(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}
	objCache.SetSharedContainerData("test-container-id", &objectcache.WatchedContainerData{
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {{Name: "test-container"}},
		},
	})

	profile := &v1beta1.ContainerProfile{}
	profile.Spec = v1beta1.ContainerProfileSpec{
		Execs: []v1beta1.ExecCalls{
			{Path: "/bin/bash", Args: []string{"/bin/bash", "-c", "curl http://example.com"}},
		},
		Opens: []v1beta1.OpenCalls{
			{Path: "/etc/passwd", Flags: []string{"O_RDONLY"}},
		},
		Syscalls: []string{"open", "read", "execve"},
		Capabilities: []string{
			"NET_ADMIN", "SYS_ADMIN",
		},
	}
	objCache.SetContainerProfile(profile)

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		CP(&objCache, config.Config{}),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	testCases := []struct {
		name string
		cp   string
		ap   string
		want bool
	}{
		{
			name: "was_executed",
			cp:   `cp.was_executed(containerID, "/bin/bash")`,
			ap:   `ap.was_executed(containerID, "/bin/bash")`,
			want: true,
		},
		{
			name: "was_executed (miss)",
			cp:   `cp.was_executed(containerID, "/bin/nonexistent")`,
			ap:   `ap.was_executed(containerID, "/bin/nonexistent")`,
			want: false,
		},
		{
			name: "was_executed_with_args",
			cp:   `cp.was_executed_with_args(containerID, "/bin/bash", ["/bin/bash", "-c", "curl http://example.com"])`,
			ap:   `ap.was_executed_with_args(containerID, "/bin/bash", ["/bin/bash", "-c", "curl http://example.com"])`,
			want: true,
		},
		{
			name: "was_path_opened",
			cp:   `cp.was_path_opened(containerID, "/etc/passwd")`,
			ap:   `ap.was_path_opened(containerID, "/etc/passwd")`,
			want: true,
		},
		{
			name: "was_path_opened_with_flags",
			cp:   `cp.was_path_opened_with_flags(containerID, "/etc/passwd", ["O_RDONLY"])`,
			ap:   `ap.was_path_opened_with_flags(containerID, "/etc/passwd", ["O_RDONLY"])`,
			want: true,
		},
		{
			name: "was_path_opened_with_suffix",
			cp:   `cp.was_path_opened_with_suffix(containerID, "passwd")`,
			ap:   `ap.was_path_opened_with_suffix(containerID, "passwd")`,
			want: true,
		},
		{
			name: "was_path_opened_with_prefix",
			cp:   `cp.was_path_opened_with_prefix(containerID, "/etc/")`,
			ap:   `ap.was_path_opened_with_prefix(containerID, "/etc/")`,
			want: true,
		},
		{
			name: "was_syscall_used",
			cp:   `cp.was_syscall_used(containerID, "execve")`,
			ap:   `ap.was_syscall_used(containerID, "execve")`,
			want: true,
		},
		{
			name: "was_capability_used",
			cp:   `cp.was_capability_used(containerID, "SYS_ADMIN")`,
			ap:   `ap.was_capability_used(containerID, "SYS_ADMIN")`,
			want: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cpResult := evalBool(t, env, tc.cp, map[string]interface{}{"containerID": "test-container-id"})
			apResult := evalBool(t, env, tc.ap, map[string]interface{}{"containerID": "test-container-id"})
			assert.Equal(t, tc.want, cpResult, "cp.* result for %s", tc.name)
			assert.Equal(t, cpResult, apResult, "ap.* must match cp.* for %s", tc.name)
		})
	}
}

// TestLegacyAPMatchesCP_HTTPAndHost covers the remaining ap.* helpers
// (endpoint + host predicates) against a projected profile, proving the
// ap.* aliases evaluate identically to cp.*.
func TestLegacyAPMatchesCP_HTTPAndHost(t *testing.T) {
	pcp := endpointsPCP(
		[]string{"/v1/api/users", "http://api.example.com/health"},
		[]string{"/v1/api/orders/" + dynamicpathdetector.DynamicIdentifier},
	)
	objCache := &mockObjectCacheForPattern{pcp: pcp}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		CP(objCache, config.Config{}),
		AP(objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	testCases := []struct {
		name string
		cp   string
		ap   string
		want bool
	}{
		{
			name: "was_endpoint_accessed",
			cp:   `cp.was_endpoint_accessed(containerID, "/v1/api/users")`,
			ap:   `ap.was_endpoint_accessed(containerID, "/v1/api/users")`,
			want: true,
		},
		{
			name: "was_endpoint_accessed_with_method",
			cp:   `cp.was_endpoint_accessed_with_method(containerID, "/v1/api/users", "GET")`,
			ap:   `ap.was_endpoint_accessed_with_method(containerID, "/v1/api/users", "GET")`,
			want: true,
		},
		{
			name: "was_endpoint_accessed_with_methods",
			cp:   `cp.was_endpoint_accessed_with_methods(containerID, "/v1/api/users", ["GET", "POST"])`,
			ap:   `ap.was_endpoint_accessed_with_methods(containerID, "/v1/api/users", ["GET", "POST"])`,
			want: true,
		},
		{
			name: "was_endpoint_accessed_with_prefix",
			cp:   `cp.was_endpoint_accessed_with_prefix(containerID, "/v1/api")`,
			ap:   `ap.was_endpoint_accessed_with_prefix(containerID, "/v1/api")`,
			want: true,
		},
		{
			name: "was_endpoint_accessed_with_suffix",
			cp:   `cp.was_endpoint_accessed_with_suffix(containerID, "/health")`,
			ap:   `ap.was_endpoint_accessed_with_suffix(containerID, "/health")`,
			want: true,
		},
		{
			name: "was_host_accessed",
			cp:   `cp.was_host_accessed(containerID, "api.example.com")`,
			ap:   `ap.was_host_accessed(containerID, "api.example.com")`,
			want: true,
		},
		{
			name: "was_endpoint_accessed (miss)",
			cp:   `cp.was_endpoint_accessed(containerID, "/v1/api/secrets")`,
			ap:   `ap.was_endpoint_accessed(containerID, "/v1/api/secrets")`,
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cpResult := evalBool(t, env, tc.cp, map[string]interface{}{"containerID": "cid"})
			apResult := evalBool(t, env, tc.ap, map[string]interface{}{"containerID": "cid"})
			assert.Equal(t, tc.want, cpResult, "cp.* result for %s", tc.name)
			assert.Equal(t, cpResult, apResult, "ap.* must match cp.* for %s", tc.name)
		})
	}
}

// evalBool compiles and evaluates a CEL boolean expression against env,
// failing the test on any compile/program/eval error.
func evalBool(t *testing.T, env *cel.Env, expr string, activation map[string]interface{}) bool {
	t.Helper()
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("failed to compile %q: %v", expr, issues.Err())
	}
	program, err := env.Program(ast)
	if err != nil {
		t.Fatalf("failed to create program for %q: %v", expr, err)
	}
	out, _, err := program.Eval(activation)
	if err != nil {
		t.Fatalf("failed to eval %q: %v", expr, err)
	}
	result, ok := out.Value().(bool)
	if !ok {
		t.Fatalf("expr %q returned %T, expected bool", expr, out.Value())
	}
	return result
}
