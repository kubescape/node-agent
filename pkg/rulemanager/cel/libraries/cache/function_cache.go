package cache

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

// ProfileNotAvailableErr is a sentinel error message used to indicate that a profile
// is not yet available. This error is NOT cached, allowing retry when profile becomes available.
// After the cache layer, this error should be converted to a default value (e.g., false)
// to allow rule evaluation to continue without failing.
const ProfileNotAvailableErr = "profile not available"

// NewProfileNotAvailableErr creates a new "profile not available" error.
// This error will NOT be cached, allowing the function to be re-evaluated
// when the profile becomes available.
func NewProfileNotAvailableErr(format string, args ...any) ref.Val {
	return types.NewErr(ProfileNotAvailableErr+": "+format, args...)
}

// IsProfileNotAvailableErr checks if the given value is a "profile not available" error.
func IsProfileNotAvailableErr(val ref.Val) bool {
	if !types.IsError(val) {
		return false
	}
	errVal, ok := val.Value().(error)
	if !ok {
		return false
	}
	return strings.Contains(errVal.Error(), ProfileNotAvailableErr)
}

// ConvertProfileNotAvailableErrToBool converts a "profile not available" error to a boolean value.
// This should be called AFTER the cache layer to ensure the error is not cached,
// but the rule evaluation can continue with a default value.
func ConvertProfileNotAvailableErrToBool(val ref.Val, defaultVal bool) ref.Val {
	if IsProfileNotAvailableErr(val) {
		return types.Bool(defaultVal)
	}
	return val
}

type FunctionCacheConfig struct {
	MaxSize int           `mapstructure:"maxSize"`
	TTL     time.Duration `mapstructure:"ttl"`
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
