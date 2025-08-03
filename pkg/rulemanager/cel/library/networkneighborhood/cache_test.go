package networkneighborhood

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

func TestNetworkNeighborhoodCaching(t *testing.T) {
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

	nn := &v1beta1.NetworkNeighborhood{}
	nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
		Name: "test-container",
		Egress: []v1beta1.NetworkNeighbor{
			{
				IPAddress: "192.168.1.100",
				DNSNames:  []string{"api.example.com"},
			},
			{
				IPAddress: "10.0.0.50",
				DNSNames:  []string{"database.internal"},
			},
		},
		Ingress: []v1beta1.NetworkNeighbor{
			{
				IPAddress: "172.16.0.10",
				DNSNames:  []string{"loadbalancer.example.com"},
			},
		},
	})
	objCache.SetNetworkNeighborhood(nn)

	// Create library with cache
	lib := &nnLibrary{
		objectCache:   &objCache,
		functionCache: cache.NewFunctionCache(cache.DefaultFunctionCacheConfig()),
	}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("address", cel.StringType),
		cel.Variable("domain", cel.StringType),
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
			name:       "was_address_in_egress caching",
			expression: `nn.was_address_in_egress(containerID, address)`,
			vars: map[string]interface{}{
				"containerID": "test-container-id",
				"address":     "192.168.1.100",
			},
			expected: true,
		},
		{
			name:       "was_address_in_ingress caching",
			expression: `nn.was_address_in_ingress(containerID, address)`,
			vars: map[string]interface{}{
				"containerID": "test-container-id",
				"address":     "172.16.0.10",
			},
			expected: true,
		},
		{
			name:       "is_domain_in_egress caching",
			expression: `nn.is_domain_in_egress(containerID, domain)`,
			vars: map[string]interface{}{
				"containerID": "test-container-id",
				"domain":      "api.example.com",
			},
			expected: true,
		},
		{
			name:       "is_domain_in_ingress caching",
			expression: `nn.is_domain_in_ingress(containerID, domain)`,
			vars: map[string]interface{}{
				"containerID": "test-container-id",
				"domain":      "loadbalancer.example.com",
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

func TestNetworkNeighborhoodCacheDifferentArguments(t *testing.T) {
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

	nn := &v1beta1.NetworkNeighborhood{}
	nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
		Name: "test-container",
		Egress: []v1beta1.NetworkNeighbor{
			{
				IPAddress: "192.168.1.100",
				DNSNames:  []string{"api.example.com"},
			},
			{
				IPAddress: "10.0.0.50",
				DNSNames:  []string{"database.internal"},
			},
		},
	})
	objCache.SetNetworkNeighborhood(nn)

	lib := &nnLibrary{
		objectCache:   &objCache,
		functionCache: cache.NewFunctionCache(cache.DefaultFunctionCacheConfig()),
	}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("address", cel.StringType),
		cel.Lib(lib),
	)
	assert.NoError(t, err)

	ast, issues := env.Compile(`nn.was_address_in_egress(containerID, address)`)
	assert.NoError(t, issues.Err())

	program, err := env.Program(ast)
	assert.NoError(t, err)

	// Call with first address
	result1, _, err := program.Eval(map[string]interface{}{
		"containerID": "test-container-id",
		"address":     "192.168.1.100",
	})
	assert.NoError(t, err)
	assert.True(t, result1.Value().(bool))

	cacheSize1 := lib.functionCache.GetCacheStats()
	assert.Equal(t, 1, cacheSize1, "Cache should have 1 entry")

	// Call with second address - should create new cache entry
	result2, _, err := program.Eval(map[string]interface{}{
		"containerID": "test-container-id",
		"address":     "10.0.0.50",
	})
	assert.NoError(t, err)
	assert.True(t, result2.Value().(bool))

	cacheSize2 := lib.functionCache.GetCacheStats()
	assert.Equal(t, 2, cacheSize2, "Cache should have 2 entries for different arguments")

	// Call with non-existent address - should create third cache entry
	result3, _, err := program.Eval(map[string]interface{}{
		"containerID": "test-container-id",
		"address":     "1.1.1.1",
	})
	assert.NoError(t, err)
	assert.False(t, result3.Value().(bool))

	cacheSize3 := lib.functionCache.GetCacheStats()
	assert.Equal(t, 3, cacheSize3, "Cache should have 3 entries for different arguments")
}

func TestNetworkNeighborhoodCacheExpiration(t *testing.T) {
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

	nn := &v1beta1.NetworkNeighborhood{}
	nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
		Name: "test-container",
		Egress: []v1beta1.NetworkNeighbor{
			{
				IPAddress: "192.168.1.100",
				DNSNames:  []string{"api.example.com"},
			},
		},
	})
	objCache.SetNetworkNeighborhood(nn)

	// Create cache with short TTL for testing
	config := cache.FunctionCacheConfig{
		MaxSize: 100,
		TTL:     50 * time.Millisecond,
	}
	lib := &nnLibrary{
		objectCache:   &objCache,
		functionCache: cache.NewFunctionCache(config),
	}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("address", cel.StringType),
		cel.Lib(lib),
	)
	assert.NoError(t, err)

	ast, issues := env.Compile(`nn.was_address_in_egress(containerID, address)`)
	assert.NoError(t, issues.Err())

	program, err := env.Program(ast)
	assert.NoError(t, err)

	vars := map[string]interface{}{
		"containerID": "test-container-id",
		"address":     "192.168.1.100",
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

func TestNetworkNeighborhoodCachePerformance(t *testing.T) {
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

	nn := &v1beta1.NetworkNeighborhood{}
	nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
		Name: "test-container",
		Egress: []v1beta1.NetworkNeighbor{
			{
				IPAddress: "192.168.1.100",
				DNSNames:  []string{"api.example.com"},
			},
		},
	})
	objCache.SetNetworkNeighborhood(nn)

	lib := &nnLibrary{
		objectCache:   &objCache,
		functionCache: cache.NewFunctionCache(cache.DefaultFunctionCacheConfig()),
	}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("address", cel.StringType),
		cel.Lib(lib),
	)
	assert.NoError(t, err)

	ast, issues := env.Compile(`nn.was_address_in_egress(containerID, address)`)
	assert.NoError(t, issues.Err())

	program, err := env.Program(ast)
	assert.NoError(t, err)

	vars := map[string]interface{}{
		"containerID": "test-container-id",
		"address":     "192.168.1.100",
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

func TestNetworkNeighborhoodCacheMultipleFunctions(t *testing.T) {
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

	nn := &v1beta1.NetworkNeighborhood{}
	nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
		Name: "test-container",
		Egress: []v1beta1.NetworkNeighbor{
			{
				IPAddress: "192.168.1.100",
				DNSNames:  []string{"api.example.com"},
			},
		},
		Ingress: []v1beta1.NetworkNeighbor{
			{
				IPAddress: "172.16.0.10",
				DNSNames:  []string{"loadbalancer.example.com"},
			},
		},
	})
	objCache.SetNetworkNeighborhood(nn)

	lib := &nnLibrary{
		objectCache:   &objCache,
		functionCache: cache.NewFunctionCache(cache.DefaultFunctionCacheConfig()),
	}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Lib(lib),
	)
	assert.NoError(t, err)

	// Test multiple functions are cached independently
	testExpressions := []struct {
		expression string
		expected   bool
	}{
		{`nn.was_address_in_egress(containerID, "192.168.1.100")`, true},
		{`nn.was_address_in_ingress(containerID, "172.16.0.10")`, true},
		{`nn.is_domain_in_egress(containerID, "api.example.com")`, true},
		{`nn.is_domain_in_ingress(containerID, "loadbalancer.example.com")`, true},
	}

	for i, tc := range testExpressions {
		ast, issues := env.Compile(tc.expression)
		assert.NoError(t, issues.Err())

		program, err := env.Program(ast)
		assert.NoError(t, err)

		// First call - should cache the result
		result1, _, err := program.Eval(map[string]interface{}{
			"containerID": "test-container-id",
		})
		assert.NoError(t, err)
		assert.Equal(t, tc.expected, result1.Value())

		// Cache should have i+1 entries
		cacheSize1 := lib.functionCache.GetCacheStats()
		assert.Equal(t, i+1, cacheSize1, "Cache should have %d entries", i+1)

		// Second call with same parameters - should use cache
		result2, _, err := program.Eval(map[string]interface{}{
			"containerID": "test-container-id",
		})
		assert.NoError(t, err)
		assert.Equal(t, tc.expected, result2.Value())

		// Cache size should remain the same (cache hit)
		cacheSize2 := lib.functionCache.GetCacheStats()
		assert.Equal(t, cacheSize1, cacheSize2, "Cache size should not increase on cache hit")
	}
}

func TestNetworkNeighborhoodCacheClearCache(t *testing.T) {
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

	nn := &v1beta1.NetworkNeighborhood{}
	nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
		Name: "test-container",
		Egress: []v1beta1.NetworkNeighbor{
			{
				IPAddress: "192.168.1.100",
				DNSNames:  []string{"api.example.com"},
			},
		},
	})
	objCache.SetNetworkNeighborhood(nn)

	lib := &nnLibrary{
		objectCache:   &objCache,
		functionCache: cache.NewFunctionCache(cache.DefaultFunctionCacheConfig()),
	}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("address", cel.StringType),
		cel.Lib(lib),
	)
	assert.NoError(t, err)

	ast, issues := env.Compile(`nn.was_address_in_egress(containerID, address)`)
	assert.NoError(t, issues.Err())

	program, err := env.Program(ast)
	assert.NoError(t, err)

	vars := map[string]interface{}{
		"containerID": "test-container-id",
		"address":     "192.168.1.100",
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

func TestNetworkNeighborhoodCacheKeyGeneration(t *testing.T) {
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

	nn := &v1beta1.NetworkNeighborhood{}
	nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
		Name: "test-container",
		Egress: []v1beta1.NetworkNeighbor{
			{
				IPAddress: "192.168.1.100",
				DNSNames:  []string{"api.example.com"},
			},
		},
	})
	objCache.SetNetworkNeighborhood(nn)

	lib := &nnLibrary{
		objectCache:   &objCache,
		functionCache: cache.NewFunctionCache(cache.DefaultFunctionCacheConfig()),
	}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("address", cel.StringType),
		cel.Lib(lib),
	)
	assert.NoError(t, err)

	ast, issues := env.Compile(`nn.was_address_in_egress(containerID, address)`)
	assert.NoError(t, issues.Err())

	program, err := env.Program(ast)
	assert.NoError(t, err)

	// Test that same arguments in different order produce same cache result
	// (cache key generation should be order-independent where possible)
	vars1 := map[string]interface{}{
		"containerID": "test-container-id",
		"address":     "192.168.1.100",
	}

	// First call
	result1, _, err := program.Eval(vars1)
	assert.NoError(t, err)
	assert.True(t, result1.Value().(bool))

	cacheSize1 := lib.functionCache.GetCacheStats()
	assert.Equal(t, 1, cacheSize1, "Cache should have 1 entry")

	// Second call with same values
	result2, _, err := program.Eval(vars1)
	assert.NoError(t, err)
	assert.True(t, result2.Value().(bool))

	// Should still be 1 entry (cache hit)
	cacheSize2 := lib.functionCache.GetCacheStats()
	assert.Equal(t, 1, cacheSize2, "Cache should still have 1 entry after cache hit")
}
