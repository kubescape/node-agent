package utils

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

const (
	procDirName = "/proc"
)

type ProcessDetails struct {
	CmdLine []string `json:"cmdline"`
	PID     int32    `json:"pid"`
}

// LocateProcessByExecSuffix locates process with executable name ends with `processSuffix`.
// The first entry at `/proc` that matches the suffix is returned, other process are ignored.
// It returns a `ProcessDetails` object.
func LocateProcessByExecSuffix(processSuffix string) (*ProcessDetails, error) {
	// TODO: consider taking the exec name from /proc/[pid]/exe instead of /proc/[pid]/cmdline
	procDir, err := os.Open(procDirName)
	if err != nil {
		return nil, fmt.Errorf("failed to open processes dir: %v", err)
	}
	defer procDir.Close()
	var pidDirs []string
	for pidDirs, err = procDir.Readdirnames(100); err == nil; pidDirs, err = procDir.Readdirnames(100) {
		for pidIdx := range pidDirs {
			// since processes are about to die in the middle of the loop, we will ignore next errors
			pid, err := strconv.ParseInt(pidDirs[pidIdx], 10, 0)
			if err != nil {
				continue
			}
			specificProcessCMD := path.Join(procDirName, pidDirs[pidIdx], "cmdline")
			cmdLine, err := os.ReadFile(specificProcessCMD)
			if err != nil {
				continue
			}
			cmdLineSplitted := bytes.Split(cmdLine, []byte{00})

			processNameFromCMD := cmdLineSplitted[0]
			if len(processNameFromCMD) == 0 {
				continue
			}
			// solve open shift kubelet not start with full path
			if processNameFromCMD[0] != '/' && processNameFromCMD[0] != '[' {
				processNameFromCMD = append([]byte{'/'}, processNameFromCMD...)
			}
			if bytes.HasSuffix(processNameFromCMD, []byte(processSuffix)) {
				logger.L().Debug("process found", helpers.String("processSuffix", processSuffix),
					helpers.Int("pid", int(pid)))
				res := &ProcessDetails{PID: int32(pid), CmdLine: make([]string, 0, len(cmdLineSplitted))}
				for splitIdx := range cmdLineSplitted {
					res.CmdLine = append(res.CmdLine, string(cmdLineSplitted[splitIdx]))
				}
				return res, nil
			}
		}
	}
	if err != io.EOF {
		return nil, fmt.Errorf("failed to read processes dir names: %v", err)
	}
	return nil, fmt.Errorf("no process with given suffix found")
}

// GetArg returns argument value from the process cmdline, and an ok.
// If the argument does not exist, it returns an empty string and `false`.
// If the argument exists but has no value, it returns an empty string and `true`.
// TODO: support multiple options
func (p ProcessDetails) GetArg(argName string) (string, bool) {
	for idx, arg := range p.CmdLine {
		if !strings.HasPrefix(arg, argName) {
			continue
		}

		val := arg[len(argName):]

		if val != "" {
			// Case `--foo=bar`
			if strings.HasPrefix(val, "=") {
				val = val[1:]
				return val, true
			}

			// argName != current arg
			continue
		}

		// Case `--foo bar`
		next := idx + 1
		if next < len(p.CmdLine) {
			val = p.CmdLine[next]
			return val, true
		}

		// Case `--foo` (flags without value)
		return "", true
	}

	return "", false
}

// RawCmd returns the raw command used to start the process
func (p ProcessDetails) RawCmd() string {
	return strings.Join(p.CmdLine, " ")
}

// RootDir returns the root directory of a process.
// This is useful when dealing with processes that are running inside a container
func (p ProcessDetails) RootDir() string {
	return fmt.Sprintf("/proc/%d/root", p.PID)
}

// ContaineredPath returns path for the file that the process see.
// This is useful when dealing with processes that are running inside a container
func (p ProcessDetails) ContaineredPath(filePath string) string {
	return path.Join(p.RootDir(), filePath)
}
