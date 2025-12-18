package cache

import (
	"testing"
	"time"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/stretchr/testify/assert"
)

func TestFunctionCache_WithCache_BasicUsage(t *testing.T) {
	cache := NewFunctionCache(DefaultFunctionCacheConfig())

	// Mock function that returns a simple boolean
	callCount := 0
	mockFunc := func(values ...ref.Val) ref.Val {
		callCount++
		// Simple logic: return true if first arg equals "test"
		if len(values) > 0 {
			if str, ok := values[0].Value().(string); ok && str == "test" {
				return types.Bool(true)
			}
		}
		return types.Bool(false)
	}

	// Wrap the function with caching
	cachedFunc := cache.WithCache(mockFunc, "test_function")

	// First call - should hit the original function
	result1 := cachedFunc(types.String("test"))
	assert.Equal(t, true, result1.Value().(bool))
	assert.Equal(t, 1, callCount)

	// Second call with same args - should hit cache
	result2 := cachedFunc(types.String("test"))
	assert.Equal(t, true, result2.Value().(bool))
	assert.Equal(t, 1, callCount) // callCount should not increase

	// Third call with different args - should hit original function
	result3 := cachedFunc(types.String("different"))
	assert.Equal(t, false, result3.Value().(bool))
	assert.Equal(t, 2, callCount) // callCount should increase
}

func TestFunctionCache_WithCache_MultipleArguments(t *testing.T) {
	cache := NewFunctionCache(DefaultFunctionCacheConfig())

	callCount := 0
	mockFunc := func(values ...ref.Val) ref.Val {
		callCount++
		// Return true if we have exactly 2 arguments
		return types.Bool(len(values) == 2)
	}

	cachedFunc := cache.WithCache(mockFunc, "multi_arg_function")

	// Call with 2 arguments
	result1 := cachedFunc(types.String("arg1"), types.String("arg2"))
	assert.Equal(t, true, result1.Value().(bool))
	assert.Equal(t, 1, callCount)

	// Same call should hit cache
	result2 := cachedFunc(types.String("arg1"), types.String("arg2"))
	assert.Equal(t, true, result2.Value().(bool))
	assert.Equal(t, 1, callCount)

	// Different arguments should miss cache
	result3 := cachedFunc(types.String("arg3"), types.String("arg4"))
	assert.Equal(t, true, result3.Value().(bool))
	assert.Equal(t, 2, callCount)
}

func TestFunctionCache_WithCache_ErrorsNotCached(t *testing.T) {
	cache := NewFunctionCache(DefaultFunctionCacheConfig())

	callCount := 0
	mockFunc := func(values ...ref.Val) ref.Val {
		callCount++
		// Always return an error
		return types.NewErr("test error")
	}

	cachedFunc := cache.WithCache(mockFunc, "error_function")

	// First call
	result1 := cachedFunc(types.String("test"))
	assert.True(t, types.IsError(result1))
	assert.Equal(t, 1, callCount)

	// Second call with same args - should NOT hit cache (errors aren't cached)
	result2 := cachedFunc(types.String("test"))
	assert.True(t, types.IsError(result2))
	assert.Equal(t, 2, callCount) // Should increase since errors aren't cached
}

func TestFunctionCache_TTL_Expiration(t *testing.T) {
	// Create cache with very short TTL for testing
	config := FunctionCacheConfig{
		MaxSize: 100,
		TTL:     50 * time.Millisecond,
	}
	cache := NewFunctionCache(config)

	callCount := 0
	mockFunc := func(values ...ref.Val) ref.Val {
		callCount++
		return types.Bool(true)
	}

	cachedFunc := cache.WithCache(mockFunc, "ttl_function")

	// First call
	result1 := cachedFunc(types.String("test"))
	assert.Equal(t, true, result1.Value().(bool))
	assert.Equal(t, 1, callCount)

	// Second call immediately - should hit cache
	result2 := cachedFunc(types.String("test"))
	assert.Equal(t, true, result2.Value().(bool))
	assert.Equal(t, 1, callCount)

	// Wait for TTL to expire
	time.Sleep(60 * time.Millisecond)

	// Third call - should miss cache due to expiration
	result3 := cachedFunc(types.String("test"))
	assert.Equal(t, true, result3.Value().(bool))
	assert.Equal(t, 2, callCount) // Should increase due to expiration
}

func TestFunctionCache_ClearCache(t *testing.T) {
	cache := NewFunctionCache(DefaultFunctionCacheConfig())

	callCount := 0
	mockFunc := func(values ...ref.Val) ref.Val {
		callCount++
		return types.Bool(true)
	}

	cachedFunc := cache.WithCache(mockFunc, "clear_test_function")

	// First call
	cachedFunc(types.String("test"))
	assert.Equal(t, 1, callCount)
	assert.Equal(t, 1, cache.GetCacheStats())

	// Second call - should hit cache
	cachedFunc(types.String("test"))
	assert.Equal(t, 1, callCount)

	// Clear cache
	cache.ClearCache()
	assert.Equal(t, 0, cache.GetCacheStats())

	// Third call - should miss cache due to clear
	cachedFunc(types.String("test"))
	assert.Equal(t, 2, callCount)
}

func TestFunctionCache_GenerateCacheKey(t *testing.T) {
	cache := NewFunctionCache(DefaultFunctionCacheConfig())

	tests := []struct {
		name         string
		functionName string
		values       []ref.Val
		expected     string
	}{
		{
			name:         "single string argument",
			functionName: "test_func",
			values:       []ref.Val{types.String("hello")},
			expected:     "test_func|hello",
		},
		{
			name:         "multiple arguments",
			functionName: "multi_func",
			values:       []ref.Val{types.String("arg1"), types.String("arg2")},
			expected:     "multi_func|arg1|arg2",
		},
		{
			name:         "mixed types",
			functionName: "mixed_func",
			values:       []ref.Val{types.String("str"), types.Bool(true), types.Int(42)},
			expected:     "mixed_func|str|true|42",
		},
		{
			name:         "no arguments",
			functionName: "no_args",
			values:       []ref.Val{},
			expected:     "no_args",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cache.generateCacheKey(tt.functionName, tt.values...)
			assert.Equal(t, tt.expected, result)
		})
	}
}
