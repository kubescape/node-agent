package sensor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	ds "github.com/kubescape/node-agent/sensor/datastructures"
	"github.com/kubescape/node-agent/sensor/internal/utils"
)

const (
	maxRecursionDepth = 10
)

// makeHostFileInfoVerbose makes a file info object
// for the given path on the host file system, and with error logging.
// It returns nil on error.
func makeHostFileInfoVerbose(ctx context.Context, path string, readContent bool, failMsgs ...helpers.IDetails) *ds.FileInfo {
	return makeChangedRootFileInfoVerbose(ctx, utils.HostFileSystemDefaultLocation, path, readContent, failMsgs...)
}

// makeContaineredFileInfoFromListVerbose makes a file info object
// for a given process file system view, and with error logging.
// It tries to find the file in the given list of paths, by the order of the list.
// It returns nil on error.
func makeContaineredFileInfoFromListVerbose(ctx context.Context, p *utils.ProcessDetails, filePathList []string, readContent bool, failMsgs ...helpers.IDetails) *ds.FileInfo {

	for _, filePath := range filePathList {
		fileInfo := makeChangedRootFileInfoVerbose(ctx, p.RootDir(), filePath, readContent, failMsgs...)
		if fileInfo != nil {
			return fileInfo
		}
	}
	return nil
}

// makeContaineredFileInfoVerbose makes a file info object
// for a given process file system view, and with error logging.
// It returns nil on error.
func makeContaineredFileInfoVerbose(ctx context.Context, p *utils.ProcessDetails, filePath string, readContent bool, failMsgs ...helpers.IDetails) *ds.FileInfo {
	return makeChangedRootFileInfoVerbose(ctx, p.RootDir(), filePath, readContent, failMsgs...)
}

// makeChangedRootFileInfoVerbose makes a file info object
// for the given path on the given root directory, and with error logging.
func makeChangedRootFileInfoVerbose(ctx context.Context, rootDir string, path string, readContent bool, failMsgs ...helpers.IDetails) *ds.FileInfo {
	fileInfo, err := utils.MakeChangedRootFileInfo(ctx, rootDir, path, readContent)
	if err != nil {
		logArgs := append([]helpers.IDetails{
			helpers.String("path", path),
			helpers.Error(err),
		},
			failMsgs...,
		)
		logger.L().Ctx(ctx).Warning("failed to MakeHostFileInfo", logArgs...)
	}
	return fileInfo
}

// makeHostDirFilesInfo iterate over a directory and make a list of
// file infos for all the files inside it. If `recursive` is set to true,
// the file infos will be added recursively until `maxRecursionDepth` is reached
func makeHostDirFilesInfoVerbose(ctx context.Context, dir string, recursive bool, fileInfos *[]*ds.FileInfo, recursionLevel int) ([]*ds.FileInfo, error) {
	dirInfo, err := os.Open(utils.HostPath(dir))
	if err != nil {
		return nil, fmt.Errorf("failed to open dir at %s: %w", dir, err)
	}
	defer dirInfo.Close()

	if fileInfos == nil {
		fileInfos = &([]*ds.FileInfo{})
	}

	var fileNames []string
	for fileNames, err = dirInfo.Readdirnames(100); err == nil; fileNames, err = dirInfo.Readdirnames(100) {
		// add sorting to make tests deterministic
		sort.Strings(fileNames)
		for i := range fileNames {
			filePath := path.Join(dir, fileNames[i])

			// Check if is directory
			stats, err := os.Stat(utils.HostPath(filePath))
			if err != nil {
				logger.L().Ctx(ctx).Warning("failed to get file stats",
					helpers.String("in", "makeHostDirFilesInfo"),
					helpers.String("path", filePath))
				continue
			}
			if stats.IsDir() {
				if recursionLevel+1 == maxRecursionDepth {
					logger.L().Ctx(ctx).Warning("max recursion depth exceeded",
						helpers.String("in", "makeHostDirFilesInfo"),
						helpers.String("path", filePath))
					continue
				}
				makeHostDirFilesInfoVerbose(ctx, filePath, recursive, fileInfos, recursionLevel+1)
			}

			fileInfo := makeHostFileInfoVerbose(ctx, filePath,
				false,
				helpers.String("in", "makeHostDirFilesInfo"),
				helpers.String("dir", dir),
			)

			// if it is not a directory and content is different from nil, then add this to the list.
			if fileInfo != nil && !stats.IsDir() {
				*fileInfos = append(*fileInfos, fileInfo)
			}

			if !recursive {
				continue
			}
		}
	}

	if errors.Is(err, io.EOF) {
		err = nil
	}

	return *fileInfos, err
}
