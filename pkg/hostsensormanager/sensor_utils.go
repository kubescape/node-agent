package hostsensormanager

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

const (
	hostFSPrefix = "/host_fs" // Mount point for host filesystem
	procDirName  = "/proc"
)

// --- File Utilities ---

// hostPath converts a path to the host filesystem path
func hostPath(p string) string {
	if strings.HasPrefix(p, hostFSPrefix) {
		return p
	}
	return path.Join(hostFSPrefix, p)
}

// readFileOnHostFileSystem reads a file from the host filesystem
func readFileOnHostFileSystem(filePath string) ([]byte, error) {
	hPath := hostPath(filePath)
	content, err := os.ReadFile(hPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", hPath, err)
	}
	return content, nil
}

// MakeFileInfo returns a FileInfo object for given path
func MakeFileInfo(filePath string, readContent bool) (*FileInfo, error) {
	ret := FileInfo{Path: filePath}

	// Permissions
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}
	ret.Permissions = int(info.Mode().Perm())

	// Ownership
	asUnix, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		ret.Ownership = &FileOwnership{Err: "not a unix filesystem"}
	} else {
		ret.Ownership = &FileOwnership{
			UID: int64(asUnix.Uid),
			GID: int64(asUnix.Gid),
		}
		// Simplified username/groupname - just stringify IDs for now
		ret.Ownership.Username = strconv.FormatInt(ret.Ownership.UID, 10)
		ret.Ownership.Groupname = strconv.FormatInt(ret.Ownership.GID, 10)
	}

	// Content
	if readContent {
		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil, err
		}
		ret.Content = content
	}

	return &ret, nil
}

// MakeChangedRootFileInfo makes a file info object for the given path on the given root directory.
func MakeChangedRootFileInfo(rootDir string, filePath string, readContent bool) (*FileInfo, error) {
	fullPath := path.Join(rootDir, filePath)
	obj, err := MakeFileInfo(fullPath, readContent)
	if err != nil {
		return obj, err
	}
	obj.Path = filePath
	return obj, nil
}

// --- Process Utilities ---

type ProcessDetails struct {
	CmdLine []string `json:"cmdline"`
	PID     int32    `json:"pid"`
}

func (p ProcessDetails) RootDir() string {
	return hostPath(fmt.Sprintf("/proc/%d/root", p.PID))
}

func (p ProcessDetails) RawCmd() string {
	return strings.Join(p.CmdLine, " ")
}

func (p ProcessDetails) GetArg(argName string) (string, bool) {
	for idx, arg := range p.CmdLine {
		if !strings.HasPrefix(arg, argName) {
			continue
		}
		val := arg[len(argName):]
		if val != "" {
			if strings.HasPrefix(val, "=") {
				return val[1:], true
			}
			continue
		}
		if idx+1 < len(p.CmdLine) {
			return p.CmdLine[idx+1], true
		}
		return "", true
	}
	return "", false
}

// LocateProcessByExecSuffix locates process with executable name ends with processSuffix.
func LocateProcessByExecSuffix(processSuffix string) (*ProcessDetails, error) {
	hProcDir := hostPath(procDirName)
	procDir, err := os.Open(hProcDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open processes dir %s: %w", hProcDir, err)
	}
	defer procDir.Close()

	var pidDirs []string
	for pidDirs, err = procDir.Readdirnames(100); err == nil; pidDirs, err = procDir.Readdirnames(100) {
		for _, pidDir := range pidDirs {
			pid, err := strconv.ParseInt(pidDir, 10, 32)
			if err != nil {
				continue
			}
			cmdLinePath := hostPath(path.Join(procDirName, pidDir, "cmdline"))
			cmdLine, err := os.ReadFile(cmdLinePath)
			if err != nil {
				continue
			}
			cmdLineSplitted := bytes.Split(cmdLine, []byte{00})
			if len(cmdLineSplitted) == 0 || len(cmdLineSplitted[0]) == 0 {
				continue
			}
			processName := cmdLineSplitted[0]
			if processName[0] != '/' && processName[0] != '[' {
				processName = append([]byte{'/'}, processName...)
			}
			if bytes.HasSuffix(processName, []byte(processSuffix)) {
				res := &ProcessDetails{PID: int32(pid), CmdLine: make([]string, 0, len(cmdLineSplitted))}
				for _, part := range cmdLineSplitted {
					if len(part) > 0 {
						res.CmdLine = append(res.CmdLine, string(part))
					}
				}
				return res, nil
			}
		}
	}
	return nil, fmt.Errorf("process with suffix %s not found", processSuffix)
}

// --- Verbose Helpers ---

func makeHostFileInfoVerbose(ctx context.Context, filePath string, readContent bool, failMsgs ...helpers.IDetails) *FileInfo {
	fileInfo, err := MakeChangedRootFileInfo(hostFSPrefix, filePath, readContent)
	if err != nil {
		logArgs := append([]helpers.IDetails{helpers.String("path", filePath), helpers.Error(err)}, failMsgs...)
		logger.L().Ctx(ctx).Debug("failed to MakeHostFileInfo", logArgs...)
	}
	return fileInfo
}

func makeContaineredFileInfoVerbose(ctx context.Context, p *ProcessDetails, filePath string, readContent bool, failMsgs ...helpers.IDetails) *FileInfo {
	fileInfo, err := MakeChangedRootFileInfo(p.RootDir(), filePath, readContent)
	if err != nil {
		logArgs := append([]helpers.IDetails{helpers.String("path", filePath), helpers.Error(err)}, failMsgs...)
		logger.L().Ctx(ctx).Debug("failed to makeContaineredFileInfo", logArgs...)
	}
	return fileInfo
}

func makeContaineredFileInfoFromListVerbose(ctx context.Context, p *ProcessDetails, filePathList []string, readContent bool, failMsgs ...helpers.IDetails) *FileInfo {
	for _, filePath := range filePathList {
		fileInfo := makeContaineredFileInfoVerbose(ctx, p, filePath, readContent, failMsgs...)
		if fileInfo != nil {
			return fileInfo
		}
	}
	return nil
}

func makeHostDirFilesInfoVerbose(ctx context.Context, dir string, recursive bool, recursionLevel int) ([]*FileInfo, error) {
	if recursionLevel > 5 { // Limit recursion
		return nil, nil
	}
	hDirPath := hostPath(dir)
	dirInfo, err := os.Open(hDirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open dir %s: %w", hDirPath, err)
	}
	defer dirInfo.Close()

	var fileInfos []*FileInfo
	var fileNames []string
	for fileNames, err = dirInfo.Readdirnames(100); err == nil; fileNames, err = dirInfo.Readdirnames(100) {
		for _, fileName := range fileNames {
			filePath := path.Join(dir, fileName)
			hFilePath := hostPath(filePath)
			stats, err := os.Stat(hFilePath)
			if err != nil {
				continue
			}
			if stats.IsDir() && recursive {
				innerInfos, _ := makeHostDirFilesInfoVerbose(ctx, filePath, recursive, recursionLevel+1)
				fileInfos = append(fileInfos, innerInfos...)
			} else if !stats.IsDir() {
				info := makeHostFileInfoVerbose(ctx, filePath, false)
				if info != nil {
					fileInfos = append(fileInfos, info)
				}
			}
		}
	}
	return fileInfos, nil
}
