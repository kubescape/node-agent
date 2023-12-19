package utils

import (
	"context"
	"errors"
	"os"
	"path"
	"syscall"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	sensorDs "node-agent/pkg/sensor/datastructures"
)

var (
	ErrNotUnixFS = errors.New("operation not supported by the file system")
)

// ReadFileOnHostFileSystem reads a file on the host file system.
func ReadFileOnHostFileSystem(fileName string) ([]byte, error) {
	logger.L().Debug("reading file on host file system", helpers.String("path", HostPath(fileName)))
	return os.ReadFile(HostPath(fileName))
}

func HostPath(filePath string) string {
	return path.Join(HostFileSystemDefaultLocation, filePath)
}

// GetFilePermissions returns file permissions as int.
// On filesystem error, it returns the error as is.
func GetFilePermissions(filePath string) (int, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return 0, err
	}

	permInt := int(info.Mode().Perm())

	return permInt, nil
}

// GetFileUNIXOwnership returns the user id and group of a file.
// On error, it return values of -1 for the ids.
// On filesystem error, it returns the error as is.
// If the filesystem not support UNIX ownership (like FAT), it returns ErrNotUnixFS.
func GetFileUNIXOwnership(filePath string) (int64, int64, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return -1, -1, err
	}

	asUnix, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, -1, ErrNotUnixFS
	}

	user := int64(asUnix.Uid)
	group := int64(asUnix.Gid)

	return user, group, nil
}

// IsPathExists returns true if a given path exist and false otherwise
func IsPathExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

// MakeFileInfo returns a `ds.FileInfo` object for given path
// If `readContent` is set to `true`, it adds the file content
// On access error, it returns the error as is
func MakeFileInfo(filePath string, readContent bool) (*sensorDs.FileInfo, error) {
	ret := sensorDs.FileInfo{Path: filePath}

	logger.L().Debug("making file info", helpers.String("path", filePath))

	// Permissions
	perms, err := GetFilePermissions(filePath)
	if err != nil {
		return nil, err
	}
	ret.Permissions = perms

	// Ownership
	uid, gid, err := GetFileUNIXOwnership(filePath)
	ret.Ownership = &sensorDs.FileOwnership{UID: uid, GID: gid}
	if err != nil {
		ret.Ownership.Err = err.Error()
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

// MakeChangedRootFileInfo makes a file info object
// for the given path on the given root directory.
func MakeChangedRootFileInfo(ctx context.Context, rootDir string, filePath string, readContent bool) (*sensorDs.FileInfo, error) {
	fullPath := path.Join(rootDir, filePath)
	obj, err := MakeFileInfo(fullPath, readContent)

	if err != nil {
		return obj, err
	}

	// Remove `rootDir` from path
	obj.Path = filePath

	// Username
	username, err := getUserName(obj.Ownership.UID, rootDir)
	obj.Ownership.Username = username

	if err != nil {
		logger.L().Ctx(ctx).Warning("MakeHostFileInfo", helpers.Error(err))
	}

	// Groupname
	groupname, err := getGroupName(obj.Ownership.GID, rootDir)
	obj.Ownership.Groupname = groupname

	if err != nil {
		logger.L().Ctx(ctx).Warning("MakeHostFileInfo", helpers.Error(err))
	}

	return obj, nil
}

// MakeContaineredFileInfo makes a file info object
// for a given process file system view.
func MakeContaineredFileInfo(ctx context.Context, p *ProcessDetails, filePath string, readContent bool) (*sensorDs.FileInfo, error) {
	return MakeChangedRootFileInfo(ctx, p.RootDir(), filePath, readContent)
}

// MakeHostFileInfo makes a file info object
// for the given path on the host file system.
func makeHostFileInfo(ctx context.Context, filePath string, readContent bool) (*sensorDs.FileInfo, error) {
	return MakeChangedRootFileInfo(ctx, HostFileSystemDefaultLocation, filePath, readContent)
}
