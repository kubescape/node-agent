package utils

import (
	"os"
	"path/filepath"
	"strings"
)

func IsSensitivePath(fullPath string, paths []string) bool {
	if fullPath == "" {
		return false
	}

	// Clean and normalize the input path once
	fullPath = filepath.Clean(fullPath)
	if !filepath.IsAbs(fullPath) {
		fullPath = filepath.Clean("/" + fullPath)
	}

	// Pre-compute the directory of the full path since it's used in prefix checks
	fullPathDir := filepath.Dir(fullPath)

	for _, sensitivePath := range paths {
		if sensitivePath == "" {
			continue
		}

		// Clean and normalize the sensitive path
		sensitivePath = filepath.Clean(sensitivePath)
		if !filepath.IsAbs(sensitivePath) {
			sensitivePath = filepath.Clean("/" + sensitivePath)
		}

		// Check exact match first (fast path)
		if fullPath == sensitivePath {
			return true
		}

		// Check if the path is within the sensitive directory
		// Note: This assumes sensitivePath is already verified as a directory
		// through external means if needed
		if strings.HasPrefix(fullPathDir, sensitivePath) {
			return true
		}
	}
	return false
}

// Get the size of the given file.
func GetFileSize(path string) (int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}

	// Get the file size.
	fileInfo, err := file.Stat()
	if err != nil {
		return 0, err
	}

	return fileInfo.Size(), nil
}
