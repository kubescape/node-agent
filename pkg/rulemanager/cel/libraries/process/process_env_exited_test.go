package process

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/stretchr/testify/require"
)

func TestProcessEnvExitedProcess(t *testing.T) {
	cmd := exec.Command("true")
	require.NoError(t, cmd.Run())
	pid := cmd.Process.Pid
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	require.ErrorIs(t, err, os.ErrNotExist)

	env, err := cel.NewEnv(Process(config.Config{}))
	require.NoError(t, err)
	for index, expression := range []string{
		fmt.Sprintf("size(process.get_process_env(%d)) == 0", pid),
		fmt.Sprintf("'GLIBC_TUNABLES' in process.get_process_env(%d) && process.get_process_env(%d)['GLIBC_TUNABLES'].matches('glibc')", pid, pid),
	} {
		ast, issues := env.Compile(expression)
		require.NoError(t, issues.Err())
		program, err := env.Program(ast)
		require.NoError(t, err)
		result, _, err := program.Eval(map[string]any{})
		require.NoError(t, err)
		if index == 0 {
			require.Equal(t, types.True, result)
		} else {
			require.Equal(t, types.False, result)
		}
	}
}

func TestProcessEnvPreservesOtherErrors(t *testing.T) {
	for _, err := range []error{os.ErrPermission, os.ErrNotExist, fmt.Errorf("unexpected read failure")} {
		result := types.WrapErr(fmt.Errorf("failed to get process environment: %w", err))
		require.Same(t, result, processEnvOrEmpty(result))
	}
}

func TestProcessEnvExitedResultIsNotCached(t *testing.T) {
	functionCache := cache.NewFunctionCache(cache.FunctionCacheConfig{})
	calls := 0
	cached := functionCache.WithCache(func(...ref.Val) ref.Val {
		calls++
		if calls == 1 {
			return types.WrapErr(fmt.Errorf("%w: %w", errProcessExited, os.ErrNotExist))
		}
		return types.NewStringStringMap(types.DefaultTypeAdapter, map[string]string{"GLIBC_TUNABLES": "glibc.malloc.check=1"})
	}, "process.get_process_env")

	pid := types.Int(123)
	require.Equal(t, types.IntZero, processEnvOrEmpty(cached(pid)).(traits.Sizer).Size())
	result := processEnvOrEmpty(cached(pid))
	require.Equal(t, types.String("glibc.malloc.check=1"), result.(traits.Indexer).Get(types.String("GLIBC_TUNABLES")))
	require.Equal(t, result, processEnvOrEmpty(cached(pid)))
	require.Equal(t, 2, calls, "missing PIDs must be retried; successful environments must still be cached")
}
