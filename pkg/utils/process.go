package utils

import (
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/prometheus/procfs"
)

func GetProcessStat(pid int) (*procfs.ProcStat, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return nil, err
	}

	proc, err := fs.Proc(pid)
	if err != nil {
		return nil, err
	}

	stat, err := proc.Stat()
	if err != nil {
		return nil, err
	}

	return &stat, nil
}

func GetCmdlineByPid(pid int) (*string, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return nil, err
	}

	proc, err := fs.Proc(pid)
	if err != nil {
		return nil, err
	}

	cmdline, err := proc.CmdLine()
	if err != nil {
		return nil, err
	}

	cmdlineStr := strings.Join(cmdline, " ")

	return &cmdlineStr, nil
}

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

// Creates a process tree from a process.
// The process tree will be built from scanning the /proc filesystem.
func CreateProcessTree(process *apitypes.Process, shimPid uint32) (apitypes.Process, error) {
	pfs, err := procfs.NewFS("/proc")
	if err != nil {
		return apitypes.Process{}, err
	}

	proc, err := pfs.Proc(int(process.PID))
	if err != nil {
		logger.L().Debug("Failed to get process", helpers.String("error", err.Error()))
		return apitypes.Process{}, err
	}

	// build the process tree
	treeRoot, err := buildProcessTree(proc, &pfs, shimPid, nil)
	if err != nil {
		return apitypes.Process{}, err
	}

	return treeRoot, nil
}

// Recursively build the process tree.
func buildProcessTree(proc procfs.Proc, procfs *procfs.FS, shimPid uint32, processTree *apitypes.Process) (apitypes.Process, error) {
	// If the current process is the shim, return the process tree.
	if proc.PID == int(shimPid) {
		return *processTree.DeepCopy(), nil
	}

	stat, err := proc.Stat()
	if err != nil {
		return apitypes.Process{}, err
	}

	parent, err := procfs.Proc(stat.PPID)
	if err != nil {
		return apitypes.Process{}, err
	}

	var uid, gid uint32
	status, err := proc.NewStatus()
	if err != nil {
		return apitypes.Process{}, err
	} else {
		uid = uint32(status.UIDs[1])
		gid = uint32(status.GIDs[1])
	}

	// Make the parent process the parent of the current process (move the current process to the parent's children).
	currentProcess := apitypes.Process{
		Comm: stat.Comm,
		Path: func() string {
			path, err := proc.Executable()
			if err != nil {
				return ""
			}
			return path
		}(),
		// TODO: Hardlink
		// TODO: UpperLayer
		PID:  uint32(stat.PID),
		PPID: uint32(parent.PID),
		Cmdline: func() string {
			cmdline, err := proc.CmdLine()
			if err != nil {
				return ""
			}
			return strings.Join(cmdline, " ")
		}(),
		Pcomm: func() string {
			pcomm, err := parent.Comm()
			if err != nil {
				return ""
			}
			return pcomm
		}(),
		Gid: &gid,
		Uid: &uid,
		Cwd: func() string {
			cwd, err := proc.Cwd()
			if err != nil {
				return ""
			}
			return cwd
		}(),
	}

	if processTree != nil {
		if currentProcess.ChildrenMap == nil {
			currentProcess.ChildrenMap = make(map[apitypes.CommPID]*apitypes.Process)
		}
		currentProcess.ChildrenMap[apitypes.CommPID{Comm: processTree.Comm, PID: processTree.PID}] = processTree
	}

	return buildProcessTree(parent, procfs, shimPid, &currentProcess)
}

func GetPathFromPid(pid uint32) (string, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return "", err
	}

	proc, err := fs.Proc(int(pid))
	if err != nil {
		return "", err
	}

	path, err := proc.Executable()
	if err != nil {
		return "", err
	}

	return path, nil
}

func GetCommFromPid(pid uint32) (string, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return "", err
	}

	proc, err := fs.Proc(int(pid))
	if err != nil {
		return "", err
	}

	comm, err := proc.Comm()
	if err != nil {
		return "", err
	}

	return comm, nil
}

func GetProcessFromProcessTree(process *apitypes.Process, pid uint32) *apitypes.Process {
	if process.PID == pid {
		return process
	}

	for i := range process.ChildrenMap {
		if p := GetProcessFromProcessTree(process.ChildrenMap[i], pid); p != nil {
			return p
		}
	}

	return nil
}
