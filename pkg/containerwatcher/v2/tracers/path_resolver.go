package tracers

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

const (
	// Default cache size for path resolution
	defaultPathCacheSize = 10000
	// Default cache expiration time
	defaultPathCacheExpiration = 1 * time.Hour
)

// PathResolver provides functionality to resolve full paths from relative paths and PIDs
// by reading the procfs filesystem and caching results
type PathResolver struct {
	cache *expirable.LRU[string, string]
}

// NewPathResolver creates a new path resolver with default cache settings
func NewPathResolver() *PathResolver {
	return NewPathResolverWithConfig(defaultPathCacheSize, defaultPathCacheExpiration)
}

// NewPathResolverWithConfig creates a new path resolver with custom cache settings
func NewPathResolverWithConfig(maxSize int, expiration time.Duration) *PathResolver {
	cache := expirable.NewLRU[string, string](maxSize, nil, expiration)

	return &PathResolver{
		cache: cache,
	}
}

// ResolvePath attempts to resolve a full path from a relative path and PID
// It first checks the cache, and if not found, reads procfs to resolve the path
func (pr *PathResolver) ResolvePath(pid uint32, relativePath string) (string, error) {
	if relativePath == "" {
		return "", fmt.Errorf("relative path cannot be empty")
	}

	// If the relative path is absolute (starts with /), return it as is
	if strings.HasPrefix(relativePath, "/") {
		return relativePath, nil
	}

	// Create cache key from PID and relative path
	cacheKey := fmt.Sprintf("%d:%s", pid, relativePath)

	// Check cache first
	if cachedPath, exists := pr.cache.Get(cacheKey); exists {
		logger.L().Debug("Path resolved from cache",
			helpers.String("pid", fmt.Sprintf("%d", pid)),
			helpers.String("relativePath", relativePath),
			helpers.String("fullPath", cachedPath))
		return cachedPath, nil
	}

	// Resolve path from procfs
	fullPath, err := pr.resolvePathFromProcfs(pid, relativePath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve path from procfs: %w", err)
	}

	// Cache the result
	pr.cache.Add(cacheKey, fullPath)

	logger.L().Debug("Path resolved from procfs",
		helpers.String("pid", fmt.Sprintf("%d", pid)),
		helpers.String("relativePath", relativePath),
		helpers.String("fullPath", fullPath))

	return fullPath, nil
}

// resolvePathFromProcfs reads the procfs filesystem to resolve the full path
func (pr *PathResolver) resolvePathFromProcfs(pid uint32, relativePath string) (string, error) {
	// Read the cwd (current working directory) from /proc/{pid}/cwd
	cwdPath := fmt.Sprintf("/proc/%d/cwd", pid)

	cwd, err := os.Readlink(cwdPath)
	if err != nil {
		// If we can't read the cwd, try to use the root directory
		rootPath := fmt.Sprintf("/proc/%d/root", pid)
		root, err := os.Readlink(rootPath)
		if err != nil {
			return "", fmt.Errorf("failed to read both cwd and root for pid %d: %w", pid, err)
		}
		cwd = root
	}

	// Combine cwd with relative path
	fullPath := filepath.Join(cwd, relativePath)

	// Clean the path to resolve any . or .. components
	fullPath = filepath.Clean(fullPath)

	return fullPath, nil
}

// GetCacheStats returns cache statistics for monitoring
func (pr *PathResolver) GetCacheStats() (hits, misses int) {
	// Note: expirable.LRU doesn't provide direct stats, so we return 0 for now
	// In a production environment, you might want to implement custom metrics
	return 0, 0
}

// ClearCache clears all cached entries
func (pr *PathResolver) ClearCache() {
	pr.cache.Purge()
	logger.L().Debug("Path resolver cache cleared")
}

// GetCacheSize returns the current number of cached entries
func (pr *PathResolver) GetCacheSize() int {
	return pr.cache.Len()
}
