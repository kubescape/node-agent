package hostrules

import (
	_ "embed"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/kubescape/node-agent/pkg/ruleengine"
)

func isSuspiciousTool(execPath string) (bool, int, string) {
	parts := strings.Split(execPath, "/")
	baseName := parts[len(parts)-1]

	if toolInfo, exists := suspiciousTools[baseName]; exists {
		return true, toolInfo.Severity, toolInfo.Category
	}

	return false, ruleengine.RulePriorityLow, ""
}

func isPathNewlyModified(path string, modificationTime time.Time) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}

	return fileInfo.ModTime().After(modificationTime)
}

func isAllowedNamespace(namespace string) bool {
	if namespace == "" {
		return false
	}

	if allowedNamespaces[namespace] {
		return true
	}

	for pattern := range allowedNamespaces {
		if strings.HasPrefix(namespace, pattern+"-") {
			return true
		}
	}

	return false
}

func ComparePaths(sourcePath, targetPath string) bool {
	cleanSource := filepath.Clean(sourcePath)
	cleanTarget := filepath.Clean(targetPath)
	return cleanSource == cleanTarget
}

func hasTargetFlags(flags []string, targetFlags []string) bool {
	for _, flag := range flags {
		if slices.Contains(targetFlags, flag) {
			return true
		}
	}
	return false
}
