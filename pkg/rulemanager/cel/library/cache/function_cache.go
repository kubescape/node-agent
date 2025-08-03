package cache

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

type FunctionCacheConfig struct {
	MaxSize int
	TTL     time.Duration
}

func DefaultFunctionCacheConfig() FunctionCacheConfig {
	return FunctionCacheConfig{
		MaxSize: 1000,
		TTL:     time.Minute,
	}
}

type FunctionCache struct {
	cache *expirable.LRU[string, ref.Val]
}

func NewFunctionCache(config FunctionCacheConfig) *FunctionCache {
	if config.MaxSize <= 0 {
		config.MaxSize = 1000
	}
	if config.TTL <= 0 {
		config.TTL = time.Minute
	}

	cache := expirable.NewLRU[string, ref.Val](config.MaxSize, nil, config.TTL)

	return &FunctionCache{
		cache: cache,
	}
}

type CelFunction func(...ref.Val) ref.Val

func (fc *FunctionCache) WithCache(fn CelFunction, functionName string) CelFunction {
	return func(values ...ref.Val) ref.Val {
		key := fc.generateCacheKey(functionName, values...)

		if cached, found := fc.cache.Get(key); found {
			return cached
		}

		result := fn(values...)

		if !types.IsError(result) {
			fc.cache.Add(key, result)
		}

		return result
	}
}

func (fc *FunctionCache) generateCacheKey(functionName string, values ...ref.Val) string {
	var keyParts []string
	keyParts = append(keyParts, functionName)

	for _, val := range values {
		keyParts = append(keyParts, fc.valueToString(val))
	}

	// Don't sort - maintain order with function name first, then arguments in order
	return strings.Join(keyParts, "|")
}

func (fc *FunctionCache) valueToString(val ref.Val) string {
	if val == nil {
		return "nil"
	}

	switch v := val.Value().(type) {
	case string:
		return v
	case bool:
		return fmt.Sprintf("%t", v)
	case int64:
		return fmt.Sprintf("%d", v)
	case float64:
		return fmt.Sprintf("%f", v)
	case []interface{}:
		var parts []string
		for _, item := range v {
			parts = append(parts, fmt.Sprintf("%v", item))
		}
		return "[" + strings.Join(parts, ",") + "]"
	default:
		return fmt.Sprintf("%v", v)
	}
}

func (fc *FunctionCache) ClearCache() {
	fc.cache.Purge()
}

func (fc *FunctionCache) GetCacheStats() (size int) {
	return fc.cache.Len()
}
