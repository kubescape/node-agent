package containerprofile

import (
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMatchExecArgv covers the B1′ argv contract used by R0040.
func TestMatchExecArgv(t *testing.T) {
	truncated := strings.Repeat("a", 255)
	full := strings.Repeat("a", 300)

	tests := []struct {
		name    string
		profile []string
		runtime []string
		want    bool
	}{
		{"absolute argv[0] in profile vs real argv[0]", []string{"/bin/sh", "-c", "x"}, []string{"sh", "-c", "x"}, true},
		{"login shell", []string{"-bash"}, []string{"/bin/bash"}, true},
		{"login shell at runtime", []string{"/bin/bash"}, []string{"-bash"}, true},
		{"busybox applets stay distinct", []string{"/bin/ls"}, []string{"cat"}, false},
		{"wildcard ⋯⋯ compares full vectors", []string{"⋯⋯"}, []string{"anything", "goes"}, true},
		{"wildcard ⋯ compares full vectors", []string{"⋯", "-c", "x"}, []string{"sh", "-c", "x"}, true},
		{"wildcard ⋯ full compare still anchors the rest", []string{"⋯", "-c", "x"}, []string{"sh", "-c", "y"}, false},
		{"single-element profile requires single-element runtime", []string{"/usr/bin/cat"}, []string{"cat", "x"}, false},
		{"single-element profile, single-element runtime", []string{"/usr/bin/cat"}, []string{"cat"}, true},
		{"* is literal in argv[0]", []string{"*"}, []string{"cat"}, false},
		{"* is literal in later args", []string{"/bin/ls", "*"}, []string{"ls", "/etc"}, false},
		{"* matches a literal *", []string{"/bin/ls", "*"}, []string{"ls", "*"}, true},
		{"empty profile is no constraint", []string{}, []string{"sh", "-c", "x"}, true},
		{"nil profile is no constraint", nil, []string{"sh"}, true},
		{"nil runtime args is an unknown capture", []string{"/bin/sh", "-c", "x"}, nil, true},
		{"empty runtime args is an unknown capture", []string{"/bin/sh", "-c", "x"}, []string{}, true},
		{"exec -a renames argv[0]", []string{"sleep", "1"}, []string{"fake", "1"}, false},
		{"rest of the argv differs", []string{"/bin/sh", "-c", "x"}, []string{"sh", "-c", "y"}, false},
		{"extra runtime arg", []string{"/bin/sh", "-c", "x"}, []string{"sh", "-c", "x", "y"}, false},
		{"legacy 255-byte truncated arg vs full arg", []string{"/bin/echo", truncated}, []string{"echo", full}, false},
		{"legacy 20-argument limit vs full argv", append([]string{"/bin/echo"}, strings.Split(strings.Repeat("a ", 19), " ")[:19]...), append([]string{"echo"}, strings.Split(strings.Repeat("a ", 25), " ")[:25]...), false},
		{"shebang profile learned before the upgrade", []string{"/app/run.sh"}, []string{"/bin/sh", "/app/run.sh"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, matchExecArgv(tt.profile, tt.runtime))
		})
	}
}

// TestExecWithArgsBasenameArgv0 runs B1′ through cp.was_executed_with_args
// with a profile that stores argv[0] as an absolute path.
func TestExecWithArgsBasenameArgv0(t *testing.T) {
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
			{Path: "/usr/bin/dash", Args: []string{"/bin/sh", "-c", "x"}},
			{Path: "/bin/busybox", Args: []string{"/bin/ls"}},
		},
	}
	objCache.SetContainerProfile(profile)

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("args", cel.ListType(cel.StringType)),
		CP(&objCache, config.Config{}),
	)
	require.NoError(t, err)
	ast, issues := env.Compile(`cp.was_executed_with_args(containerID, path, args)`)
	require.NoError(t, issues.Err())
	program, err := env.Program(ast)
	require.NoError(t, err)

	tests := []struct {
		name string
		path string
		args []string
		want bool
	}{
		{"real argv[0] matches absolute profile argv[0]", "/usr/bin/dash", []string{"sh", "-c", "x"}, true},
		{"argv not captured", "/usr/bin/dash", []string{}, true},
		{"different command", "/usr/bin/dash", []string{"sh", "-c", "y"}, false},
		{"busybox applet ls", "/bin/busybox", []string{"ls"}, true},
		{"busybox applet cat", "/bin/busybox", []string{"cat"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, err := program.Eval(map[string]any{
				"containerID": "test-container-id",
				"path":        tt.path,
				"args":        tt.args,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, result.Value().(bool))
		})
	}
}
