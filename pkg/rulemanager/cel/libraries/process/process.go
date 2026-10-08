package process

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/prometheus/procfs"
)

var errProcessExited = errors.New("process exited before environment lookup")

// LD_PRELOAD_ENV_VARS contains the environment variables that can be used for LD_PRELOAD
var LD_PRELOAD_ENV_VARS = []string{
	"LD_PRELOAD",
	"LD_LIBRARY_PATH",
	"LD_AUDIT",
	"LD_BIND_NOW",
	"LD_DEBUG",
	"LD_PROFILE",
	"LD_USE_LOAD_BIAS",
	"LD_SHOW_AUXV",
	"LD_ORIGIN_PATH",
	"LD_LIBRARY_PATH_FDS",
	"LD_ASSUME_KERNEL",
	"LD_VERBOSE",
	"LD_WARN",
	"LD_TRACE_LOADED_OBJECTS",
	"LD_BIND_NOT",
	"LD_NOWARN",
	"LD_HWCAP_MASK",
	"LD_SHOW_AUXV",
	"LD_USE_LOAD_BIAS",
	"LD_ORIGIN_PATH",
	"LD_LIBRARY_PATH_FDS",
	"LD_ASSUME_KERNEL",
	"LD_VERBOSE",
	"LD_WARN",
	"LD_TRACE_LOADED_OBJECTS",
	"LD_BIND_NOT",
	"LD_NOWARN",
	"LD_HWCAP_MASK",
}

func (l *processLibrary) getProcessEnv(pid ref.Val) ref.Val {
	pidInt, ok := pid.Value().(int64)
	if !ok {
		return types.MaybeNoSuchOverloadErr(pid)
	}

	envMap, err := GetProcessEnv(int(pidInt))
	if err != nil {
		return types.WrapErr(fmt.Errorf("failed to get process environment: %w", err))
	}

	// Convert map[string]string to map[string]interface{} for CEL
	result := make(map[string]any)
	for k, v := range envMap {
		result[k] = v
	}

	return types.NewDynamicMap(types.DefaultTypeAdapter, result)
}

// processEnvOrEmpty converts an exited process to an empty environment after
// caching, so a missing process does not cache an empty map for a reused PID.
// This avoids expected evaluation errors; it cannot recover the exited process's
// environment, so environment-based rules may miss short-lived commands.
func processEnvOrEmpty(result ref.Val) ref.Val {
	if err, ok := result.(*types.Err); ok && errors.Is(err, errProcessExited) {
		return types.NewStringStringMap(types.DefaultTypeAdapter, map[string]string{})
	}
	return result
}

func (l *processLibrary) getLdHookVar(pid ref.Val) ref.Val {
	pidUint, ok := pid.Value().(uint64)
	if !ok {
		return types.MaybeNoSuchOverloadErr(pid)
	}

	// Get process environment variables
	envMap, err := GetProcessEnv(int(pidUint))
	if err != nil {
		return types.String("")
	}

	// Check for LD hook variables
	envVar, found := GetLdHookVar(envMap)
	if !found {
		return types.String("")
	}

	return types.String(envVar)
}

// GetProcessEnv reads a process's live /proc/<pid>/environ at call time, not at
// exec-event capture time. Short-lived processes can exit before the read;
// their environment cannot be recovered from the exec event by this helper.
func GetProcessEnv(pid int) (map[string]string, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return nil, err
	}

	proc, err := fs.Proc(pid)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %w", errProcessExited, err)
		}
		return nil, err
	}

	env, err := proc.Environ()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %w", errProcessExited, err)
		}
		return nil, err
	}

	envMap := make(map[string]string)
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	return envMap, nil
}

// GetLdHookVar checks if any LD_PRELOAD environment variables are set
func GetLdHookVar(envVars map[string]string) (string, bool) {
	for _, envVar := range LD_PRELOAD_ENV_VARS {
		if _, ok := envVars[envVar]; ok {
			return envVar, true
		}
	}
	return "", false
}
