package tracers

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPathResolver(t *testing.T) {
	resolver := NewPathResolver()
	assert.NotNil(t, resolver)
	assert.NotNil(t, resolver.cache)
	assert.Equal(t, 0, resolver.GetCacheSize())
}

func TestNewPathResolverWithConfig(t *testing.T) {
	maxSize := 100
	expiration := 30 * time.Minute

	resolver := NewPathResolverWithConfig(maxSize, expiration)
	assert.NotNil(t, resolver)
	assert.NotNil(t, resolver.cache)
	assert.Equal(t, 0, resolver.GetCacheSize())
}

func TestPathResolver_ResolvePath_EmptyPath(t *testing.T) {
	resolver := NewPathResolver()

	_, err := resolver.ResolvePath(1, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "relative path cannot be empty")
}

func TestPathResolver_ResolvePath_AbsolutePath(t *testing.T) {
	resolver := NewPathResolver()

	absolutePath := "/usr/bin/ls"
	result, err := resolver.ResolvePath(1, absolutePath)

	assert.NoError(t, err)
	assert.Equal(t, absolutePath, result)
}

func TestPathResolver_ResolvePath_RelativePath(t *testing.T) {
	resolver := NewPathResolver()

	// Test with current process PID
	pid := uint32(os.Getpid())

	// Create a temporary directory and file for testing
	tempDir, err := os.MkdirTemp("", "path_resolver_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a test file
	testFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test"), 0644)
	require.NoError(t, err)

	// Change to the temp directory
	originalCwd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(originalCwd)

	err = os.Chdir(tempDir)
	require.NoError(t, err)

	// Test resolving a relative path
	relativePath := "test.txt"
	result, err := resolver.ResolvePath(pid, relativePath)

	assert.NoError(t, err)
	assert.Equal(t, testFile, result)
}

func TestPathResolver_CacheFunctionality(t *testing.T) {
	resolver := NewPathResolver()

	// Test that cache works with relative paths
	pid := uint32(os.Getpid())
	relativePath := "test.txt"

	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "cache_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a test file
	testFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test"), 0644)
	require.NoError(t, err)

	// Change to the temp directory
	originalCwd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(originalCwd)

	err = os.Chdir(tempDir)
	require.NoError(t, err)

	// First call should resolve from procfs
	result1, err := resolver.ResolvePath(pid, relativePath)
	assert.NoError(t, err)
	assert.Equal(t, 1, resolver.GetCacheSize())

	// Second call should use cache
	result2, err := resolver.ResolvePath(pid, relativePath)
	assert.NoError(t, err)
	assert.Equal(t, result1, result2)
	assert.Equal(t, 1, resolver.GetCacheSize())
}

func TestPathResolver_ClearCache(t *testing.T) {
	resolver := NewPathResolver()

	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "clear_cache_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create test files
	testFile1 := filepath.Join(tempDir, "test1.txt")
	testFile2 := filepath.Join(tempDir, "test2.txt")
	err = os.WriteFile(testFile1, []byte("test1"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(testFile2, []byte("test2"), 0644)
	require.NoError(t, err)

	// Change to the temp directory
	originalCwd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(originalCwd)

	err = os.Chdir(tempDir)
	require.NoError(t, err)

	// Add some entries to cache using relative paths
	pid := uint32(os.Getpid())
	resolver.ResolvePath(pid, "test1.txt")
	resolver.ResolvePath(pid, "test2.txt")

	assert.Greater(t, resolver.GetCacheSize(), 0)

	// Clear cache
	resolver.ClearCache()
	assert.Equal(t, 0, resolver.GetCacheSize())
}

func TestPathResolver_GetCacheStats(t *testing.T) {
	resolver := NewPathResolver()

	hits, misses := resolver.GetCacheStats()
	assert.Equal(t, 0, hits)
	assert.Equal(t, 0, misses)
}

func TestPathResolver_ResolvePath_InvalidPID(t *testing.T) {
	resolver := NewPathResolver()

	// Test with a very high PID that likely doesn't exist
	invalidPID := uint32(999999)
	_, err := resolver.ResolvePath(invalidPID, "test.txt")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve path from procfs")
}
