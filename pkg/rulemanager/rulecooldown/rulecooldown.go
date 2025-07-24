package rulecooldown

import (
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/node-agent/pkg/ruleengine"
)

type RuleCooldownConfig struct {
	CooldownDuration   time.Duration `mapstructure:"ruleCooldownDuration"`
	CooldownAfterCount int           `mapstructure:"ruleCooldownAfterCount"`
	OnProfileFailure   bool          `mapstructure:"ruleCooldownOnProfileFailure"`
	MaxSize            int           `mapstructure:"ruleCooldownMaxSize"`
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

func (rc *RuleCooldown) ShouldCooldown(ruleFailures ruleengine.RuleFailure) (bool, int) {
	alert := ruleFailures.GetBaseRuntimeAlert()
	key := alert.UniqueID + ruleFailures.GetRuntimeProcessDetails().ContainerID + ruleFailures.GetRuleId()

	// If we're not on profile failure, and the profile failed, don't cooldown
	if !rc.cooldownConfig.OnProfileFailure && alert.ProfileMetadata.FailOnProfile {
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
