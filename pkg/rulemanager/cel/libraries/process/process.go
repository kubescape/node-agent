package process

import (
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/prometheus/procfs"
)

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
		return types.NewErr("failed to get process environment: %v", err)
	}

	// Convert map[string]string to map[string]interface{} for CEL
	result := make(map[string]interface{})
	for k, v := range envMap {
		result[k] = v
	}

	return types.NewDynamicMap(types.DefaultTypeAdapter, result)
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

// GetProcessEnv retrieves the environment variables for a given process ID
func GetProcessEnv(pid int) (map[string]string, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return nil, err
	}

	proc, err := fs.Proc(pid)
	if err != nil {
		return nil, err
	}

	env, err := proc.Environ()
	if err != nil {
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
