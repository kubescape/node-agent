package applicationprofile

import (
	"testing"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/library/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

func TestApplicationProfileCaching(t *testing.T) {
	objCache := profilevalidator.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}

	objCache.SetSharedContainerData("test-container-id", &objectcache.WatchedContainerData{
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {
				{
					Name: "test-container",
				},
			},
		},
	})

	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name: "test-container",
		Opens: []v1beta1.OpenCalls{
			{
				Path:  "/etc/passwd",
				Flags: []string{"O_RDONLY"},
			},
		},
		Execs: []v1beta1.ExecCalls{
			{
				Path: "/bin/ls",
				Args: []string{"-la"},
			},
		},
		Syscalls:     []string{"open", "read", "write"},
		Capabilities: []string{"CAP_NET_ADMIN"},
	})
	objCache.SetApplicationProfile(profile)

	// Create library with cache
	lib := &apLibrary{
		objectCache:   &objCache,
		functionCache: cache.NewFunctionCache(cache.DefaultFunctionCacheConfig()),
	}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("args", cel.ListType(cel.StringType)),
		cel.Variable("syscall", cel.StringType),
		cel.Variable("capability", cel.StringType),
		cel.Lib(lib),
	)
	assert.NoError(t, err)

	testCases := []struct {
		name       string
		expression string
		vars       map[string]interface{}
		expected   bool
	}{
		{
			name:       "was_path_opened caching",
			expression: `ap.was_path_opened(containerID, path)`,
			vars: map[string]interface{}{
				"containerID": "test-container-id",
				"path":        "/etc/passwd",
			},
			expected: true,
		},
		{
			name:       "was_executed caching",
			expression: `ap.was_executed(containerID, path)`,
			vars: map[string]interface{}{
				"containerID": "test-container-id",
				"path":        "/bin/ls",
			},
			expected: true,
		},
		{
			name:       "was_executed_with_args caching",
			expression: `ap.was_executed_with_args(containerID, path, args)`,
			vars: map[string]interface{}{
				"containerID": "test-container-id",
				"path":        "/bin/ls",
				"args":        []string{"-la"},
			},
			expected: true,
		},
		{
			name:       "was_syscall_used caching",
			expression: `ap.was_syscall_used(containerID, syscall)`,
			vars: map[string]interface{}{
				"containerID": "test-container-id",
				"syscall":     "open",
			},
			expected: true,
		},
		{
			name:       "was_capability_used caching",
			expression: `ap.was_capability_used(containerID, capability)`,
			vars: map[string]interface{}{
				"containerID": "test-container-id",
				"capability":  "CAP_NET_ADMIN",
			},
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ast, issues := env.Compile(tc.expression)
			assert.NoError(t, issues.Err())

			program, err := env.Program(ast)
			assert.NoError(t, err)

			// Initial cache should be empty
			initialCacheSize := lib.functionCache.GetCacheStats()

			// First call - should cache the result
			result1, _, err := program.Eval(tc.vars)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, result1.Value())

			// Cache should have one more entry
			cacheSize1 := lib.functionCache.GetCacheStats()
			assert.Equal(t, initialCacheSize+1, cacheSize1, "Cache should have one new entry after first call")

			// Second call with same parameters - should use cache
			result2, _, err := program.Eval(tc.vars)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, result2.Value())

			// Cache size should remain the same (cache hit)
			cacheSize2 := lib.functionCache.GetCacheStats()
			assert.Equal(t, cacheSize1, cacheSize2, "Cache size should not increase on cache hit")

			// Verify results are identical
			assert.Equal(t, result1.Value(), result2.Value(), "Cached and non-cached results should be identical")
		})
	}
}

func TestApplicationProfileCacheDifferentArguments(t *testing.T) {
	objCache := profilevalidator.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}

	objCache.SetSharedContainerData("test-container-id", &objectcache.WatchedContainerData{
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {
				{
					Name: "test-container",
				},
			},
		},
	})

	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name: "test-container",
		Opens: []v1beta1.OpenCalls{
			{
				Path:  "/etc/passwd",
				Flags: []string{"O_RDONLY"},
			},
			{
				Path:  "/tmp/test.txt",
				Flags: []string{"O_WRONLY"},
			},
		},
	})
	objCache.SetApplicationProfile(profile)

	lib := &apLibrary{
		objectCache:   &objCache,
		functionCache: cache.NewFunctionCache(cache.DefaultFunctionCacheConfig()),
	}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Lib(lib),
	)
	assert.NoError(t, err)

	ast, issues := env.Compile(`ap.was_path_opened(containerID, path)`)
	assert.NoError(t, issues.Err())

	program, err := env.Program(ast)
	assert.NoError(t, err)

	// Call with first path
	result1, _, err := program.Eval(map[string]interface{}{
		"containerID": "test-container-id",
		"path":        "/etc/passwd",
	})
	assert.NoError(t, err)
	assert.True(t, result1.Value().(bool))

	cacheSize1 := lib.functionCache.GetCacheStats()
	assert.Equal(t, 1, cacheSize1, "Cache should have 1 entry")

	// Call with second path - should create new cache entry
	result2, _, err := program.Eval(map[string]interface{}{
		"containerID": "test-container-id",
		"path":        "/tmp/test.txt",
	})
	assert.NoError(t, err)
	assert.True(t, result2.Value().(bool))

	cacheSize2 := lib.functionCache.GetCacheStats()
	assert.Equal(t, 2, cacheSize2, "Cache should have 2 entries for different arguments")

	// Call with non-existent path - should create third cache entry
	result3, _, err := program.Eval(map[string]interface{}{
		"containerID": "test-container-id",
		"path":        "/nonexistent",
	})
	assert.NoError(t, err)
	assert.False(t, result3.Value().(bool))

	cacheSize3 := lib.functionCache.GetCacheStats()
	assert.Equal(t, 3, cacheSize3, "Cache should have 3 entries for different arguments")
}

func TestApplicationProfileCacheExpiration(t *testing.T) {
	objCache := profilevalidator.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}

	objCache.SetSharedContainerData("test-container-id", &objectcache.WatchedContainerData{
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {
				{
					Name: "test-container",
				},
			},
		},
	})

	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name: "test-container",
		Opens: []v1beta1.OpenCalls{
			{
				Path:  "/etc/passwd",
				Flags: []string{"O_RDONLY"},
			},
		},
	})
	objCache.SetApplicationProfile(profile)

	// Create cache with short TTL for testing
	config := cache.FunctionCacheConfig{
		MaxSize: 100,
		TTL:     50 * time.Millisecond,
	}
	lib := &apLibrary{
		objectCache:   &objCache,
		functionCache: cache.NewFunctionCache(config),
	}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Lib(lib),
	)
	assert.NoError(t, err)

	ast, issues := env.Compile(`ap.was_path_opened(containerID, path)`)
	assert.NoError(t, issues.Err())

	program, err := env.Program(ast)
	assert.NoError(t, err)

	vars := map[string]interface{}{
		"containerID": "test-container-id",
		"path":        "/etc/passwd",
	}

	// First call
	result1, _, err := program.Eval(vars)
	assert.NoError(t, err)
	assert.True(t, result1.Value().(bool))

	cacheSize1 := lib.functionCache.GetCacheStats()
	assert.Equal(t, 1, cacheSize1, "Cache should have 1 entry")

	// Wait for cache to expire
	time.Sleep(100 * time.Millisecond)

	// Second call after expiration - cache should be empty
	result2, _, err := program.Eval(vars)
	assert.NoError(t, err)
	assert.True(t, result2.Value().(bool))

	// Cache should have been repopulated
	cacheSize2 := lib.functionCache.GetCacheStats()
	assert.Equal(t, 1, cacheSize2, "Cache should be repopulated after expiration")
}

func TestApplicationProfileCachePerformance(t *testing.T) {
	objCache := profilevalidator.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}

	objCache.SetSharedContainerData("test-container-id", &objectcache.WatchedContainerData{
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {
				{
					Name: "test-container",
				},
			},
		},
	})

	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name: "test-container",
		Opens: []v1beta1.OpenCalls{
			{
				Path:  "/etc/passwd",
				Flags: []string{"O_RDONLY"},
			},
		},
	})
	objCache.SetApplicationProfile(profile)

	lib := &apLibrary{
		objectCache:   &objCache,
		functionCache: cache.NewFunctionCache(cache.DefaultFunctionCacheConfig()),
	}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Lib(lib),
	)
	assert.NoError(t, err)

	ast, issues := env.Compile(`ap.was_path_opened(containerID, path)`)
	assert.NoError(t, issues.Err())

	program, err := env.Program(ast)
	assert.NoError(t, err)

	vars := map[string]interface{}{
		"containerID": "test-container-id",
		"path":        "/etc/passwd",
	}

	// Measure time for first call (cache miss)
	start1 := time.Now()
	result1, _, err := program.Eval(vars)
	duration1 := time.Since(start1)
	assert.NoError(t, err)
	assert.True(t, result1.Value().(bool))

	// Measure time for second call (cache hit)
	start2 := time.Now()
	result2, _, err := program.Eval(vars)
	duration2 := time.Since(start2)
	assert.NoError(t, err)
	assert.True(t, result2.Value().(bool))

	// Cache hit should be faster (though this is not guaranteed in all environments)
	t.Logf("First call (cache miss): %v", duration1)
	t.Logf("Second call (cache hit): %v", duration2)

	// Verify results are the same
	assert.Equal(t, result1.Value(), result2.Value())

	// Verify cache was used
	cacheSize := lib.functionCache.GetCacheStats()
	assert.Equal(t, 1, cacheSize, "Cache should contain 1 entry")
}

func TestApplicationProfileCacheClearCache(t *testing.T) {
	objCache := profilevalidator.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}

	objCache.SetSharedContainerData("test-container-id", &objectcache.WatchedContainerData{
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {
				{
					Name: "test-container",
				},
			},
		},
	})

	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name: "test-container",
		Opens: []v1beta1.OpenCalls{
			{
				Path:  "/etc/passwd",
				Flags: []string{"O_RDONLY"},
			},
		},
	})
	objCache.SetApplicationProfile(profile)

	lib := &apLibrary{
		objectCache:   &objCache,
		functionCache: cache.NewFunctionCache(cache.DefaultFunctionCacheConfig()),
	}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Lib(lib),
	)
	assert.NoError(t, err)

	ast, issues := env.Compile(`ap.was_path_opened(containerID, path)`)
	assert.NoError(t, issues.Err())

	program, err := env.Program(ast)
	assert.NoError(t, err)

	vars := map[string]interface{}{
		"containerID": "test-container-id",
		"path":        "/etc/passwd",
	}

	// First call - populate cache
	result1, _, err := program.Eval(vars)
	assert.NoError(t, err)
	assert.True(t, result1.Value().(bool))

	cacheSize1 := lib.functionCache.GetCacheStats()
	assert.Equal(t, 1, cacheSize1, "Cache should have 1 entry")

	// Clear cache
	lib.functionCache.ClearCache()

	cacheSize2 := lib.functionCache.GetCacheStats()
	assert.Equal(t, 0, cacheSize2, "Cache should be empty after clear")

	// Call again - should repopulate cache
	result2, _, err := program.Eval(vars)
	assert.NoError(t, err)
	assert.True(t, result2.Value().(bool))

	cacheSize3 := lib.functionCache.GetCacheStats()
	assert.Equal(t, 1, cacheSize3, "Cache should have 1 entry after repopulation")
}
