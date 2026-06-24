package rulecooldown

import (
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/kubescape/go-logger"
)

type RuleCooldownConfig struct {
	// Disabled is the master kill-switch for rule cooldown. When true, cooldown is
	// bypassed entirely regardless of the other fields. Zero value (false) preserves
	// the historical behavior of being governed by OnProfileFailure.
	Disabled           bool          `mapstructure:"ruleCooldownDisabled"`
	CooldownDuration   time.Duration `mapstructure:"ruleCooldownDuration"`
	CooldownAfterCount int           `mapstructure:"ruleCooldownAfterCount"`
	// Deprecated: retained for backward compatibility. Setting it false still disables
	// cooldown, but new callers should use Disabled as the explicit master switch.
	OnProfileFailure bool `mapstructure:"ruleCooldownOnProfileFailure"`
	MaxSize          int  `mapstructure:"ruleCooldownMaxSize"`
}

type RuleCooldown struct {
	cooldownConfig RuleCooldownConfig
	cooldownMap    *expirable.LRU[string, int]
}

func NewRuleCooldown(config RuleCooldownConfig) *RuleCooldown {
	if config.MaxSize <= 0 {
		logger.L().Fatal("MaxSize must be greater than 0")
	}

	cache := expirable.NewLRU[string, int](config.MaxSize, nil, config.CooldownDuration)

	return &RuleCooldown{
		cooldownConfig: config,
		cooldownMap:    cache,
	}
}

func (rc *RuleCooldown) ShouldCooldown(uniqueID string, containerID string, ruleID string) (bool, int) {
	key := uniqueID + containerID + ruleID

	// Disabled is the explicit master switch; OnProfileFailure is retained for
	// backward compatibility and still disables cooldown when false.
	if rc.cooldownConfig.Disabled || !rc.cooldownConfig.OnProfileFailure {
		return false, 1
	}

	count, exists := rc.cooldownMap.Get(key)
	if !exists {
		rc.cooldownMap.Add(key, 1)
	}

	count++
	rc.cooldownMap.Add(key, count)
	return count > rc.cooldownConfig.CooldownAfterCount, count
}
