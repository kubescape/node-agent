package rulecooldown

import (
	"fmt"
	"testing"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/ruleengine/v1"
	"github.com/stretchr/testify/assert"
)

func TestShouldCooldown(t *testing.T) {
	tests := []struct {
		name             string
		config           RuleCooldownConfig
		ruleFailure      *ruleengine.GenericRuleFailure
		expectedCooldown bool
		expectedCount    int
		iterations       int
		profileFailure   bool
		waitBetweenCalls time.Duration
	}{
		{
			name: "no cooldown on first occurrence",
			config: RuleCooldownConfig{
				CooldownDuration:   1 * time.Hour,
				CooldownAfterCount: 3,
				OnProfileFailure:   true,
				MaxSize:            1000,
			},
			ruleFailure: &ruleengine.GenericRuleFailure{
				BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
					UniqueID: "test-alert-1",
				},
				RuntimeProcessDetails: apitypes.ProcessTree{
					ContainerID: "test-container-1",
				},
			},
			expectedCooldown: false,
			expectedCount:    1,
			iterations:       1,
			profileFailure:   false,
		},
		{
			name: "cooldown after threshold",
			config: RuleCooldownConfig{
				CooldownDuration:   1 * time.Hour,
				CooldownAfterCount: 3,
				OnProfileFailure:   true,
				MaxSize:            1000,
			},
			ruleFailure: &ruleengine.GenericRuleFailure{
				BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
					UniqueID: "test-alert-2",
				},
				RuntimeProcessDetails: apitypes.ProcessTree{
					ContainerID: "test-container-2",
				},
			},
			expectedCooldown: false,
			expectedCount:    3,
			iterations:       3,
			profileFailure:   false,
		},
		{
			name: "no cooldown on profile failure when disabled",
			config: RuleCooldownConfig{
				CooldownDuration:   1 * time.Hour,
				CooldownAfterCount: 3,
				OnProfileFailure:   false,
				MaxSize:            1000,
			},
			ruleFailure: &ruleengine.GenericRuleFailure{
				BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
					UniqueID: "test-alert-3",
					ProfileMetadata: &apitypes.ProfileMetadata{
						FailOnProfile: true,
					},
				},
				RuntimeProcessDetails: apitypes.ProcessTree{
					ContainerID: "test-container-3",
				},
			},
			expectedCooldown: false,
			expectedCount:    1,
			iterations:       1,
			profileFailure:   true,
		},
		{
			name: "cooldown expires after duration",
			config: RuleCooldownConfig{
				CooldownDuration:   100 * time.Millisecond,
				CooldownAfterCount: 3,
				OnProfileFailure:   true,
				MaxSize:            1000,
			},
			ruleFailure: &ruleengine.GenericRuleFailure{
				BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
					UniqueID: "test-alert-4",
				},
				RuntimeProcessDetails: apitypes.ProcessTree{
					ContainerID: "test-container-4",
				},
			},
			expectedCooldown: false,
			expectedCount:    1,
			iterations:       1,
			profileFailure:   false,
			waitBetweenCalls: 200 * time.Millisecond,
		},
		{
			name: "cooldown on profile failure when enabled",
			config: RuleCooldownConfig{
				CooldownDuration:   1 * time.Hour,
				CooldownAfterCount: 3,
				OnProfileFailure:   true,
				MaxSize:            1000,
			},
			ruleFailure: &ruleengine.GenericRuleFailure{
				BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
					UniqueID: "test-alert-3",
					ProfileMetadata: &apitypes.ProfileMetadata{
						FailOnProfile: true,
					},
				},
				RuntimeProcessDetails: apitypes.ProcessTree{
					ContainerID: "test-container-3",
				},
			},
			expectedCooldown: false,
			expectedCount:    3,
			iterations:       3,
			profileFailure:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := NewRuleCooldown(tt.config)

			if tt.profileFailure {
				tt.ruleFailure.BaseRuntimeAlert.ProfileMetadata.FailOnProfile = true
			}

			var lastCooldown bool
			var lastCount int

			for i := 0; i < tt.iterations; i++ {
				if i > 0 && tt.waitBetweenCalls > 0 {
					time.Sleep(tt.waitBetweenCalls)
				}
				lastCooldown, lastCount = rc.ShouldCooldown(tt.ruleFailure)
			}

			assert.Equal(t, tt.expectedCooldown, lastCooldown)
			assert.Equal(t, tt.expectedCount, lastCount)
		})
	}
}

func TestShouldCooldownImmediate(t *testing.T) {
	rc := NewRuleCooldown(RuleCooldownConfig{
		CooldownDuration:   1 * time.Hour,
		CooldownAfterCount: 1,
		OnProfileFailure:   true,
		MaxSize:            1000,
	})

	ruleFailure := &ruleengine.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID: "test-alert-immediate",
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ContainerID: "test-container-immediate",
		},
	}

	// First call should trigger cooldown immediately
	cooldown, count := rc.ShouldCooldown(ruleFailure)
	assert.False(t, cooldown)
	assert.Equal(t, 1, count)

	// Second call should still be in cooldown
	cooldown, count = rc.ShouldCooldown(ruleFailure)
	assert.True(t, cooldown)
	assert.Equal(t, 2, count)
}

func TestShouldCooldownOnProfileFailure(t *testing.T) {
	rc := NewRuleCooldown(RuleCooldownConfig{
		CooldownDuration:   1 * time.Hour,
		CooldownAfterCount: 2,
		OnProfileFailure:   true,
		MaxSize:            1000,
	})

	ruleFailure := &ruleengine.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID: "test-alert-profile",
			ProfileMetadata: &apitypes.ProfileMetadata{
				FailOnProfile: true,
			},
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ContainerID: "test-container-profile",
		},
	}

	// First call should not cooldown
	cooldown, count := rc.ShouldCooldown(ruleFailure)
	assert.False(t, cooldown)
	assert.Equal(t, 1, count)

	// Second call should not cooldown
	cooldown, count = rc.ShouldCooldown(ruleFailure)
	assert.False(t, cooldown)
	assert.Equal(t, 2, count)

	// Third call should cooldown
	cooldown, count = rc.ShouldCooldown(ruleFailure)
	assert.True(t, cooldown)
	assert.Equal(t, 3, count)
}

func TestShouldCooldownDifferentKeys(t *testing.T) {
	rc := NewRuleCooldown(RuleCooldownConfig{
		CooldownDuration:   1 * time.Hour,
		CooldownAfterCount: 2,
		OnProfileFailure:   true,
		MaxSize:            1000,
	})

	// First rule failure
	ruleFailure1 := &ruleengine.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID: "test-alert-1",
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ContainerID: "test-container-1",
		},
	}

	// Second rule failure with different key
	ruleFailure2 := &ruleengine.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID: "test-alert-2",
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ContainerID: "test-container-1", // Same container, different alert
		},
	}

	// First failure - first call
	cooldown, count := rc.ShouldCooldown(ruleFailure1)
	assert.False(t, cooldown)
	assert.Equal(t, 1, count)

	// Second failure - first call
	cooldown, count = rc.ShouldCooldown(ruleFailure2)
	assert.False(t, cooldown)
	assert.Equal(t, 1, count)

	// First failure - second call
	cooldown, count = rc.ShouldCooldown(ruleFailure1)
	assert.False(t, cooldown)
	assert.Equal(t, 2, count)

	// Second failure - second call
	cooldown, count = rc.ShouldCooldown(ruleFailure2)
	assert.False(t, cooldown)
	assert.Equal(t, 2, count)
}

func TestShouldCooldownMaxSize(t *testing.T) {
	maxSize := 2
	rc := NewRuleCooldown(RuleCooldownConfig{
		CooldownDuration:   1 * time.Hour,
		CooldownAfterCount: 2,
		OnProfileFailure:   true,
		MaxSize:            maxSize,
	})

	// Fill up the cache
	for i := 0; i < maxSize; i++ {
		failure := &ruleengine.GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
				UniqueID: fmt.Sprintf("test-alert-%d", i),
			},
			RuntimeProcessDetails: apitypes.ProcessTree{
				ContainerID: fmt.Sprintf("test-container-%d", i),
			},
		}
		rc.ShouldCooldown(failure)
	}

	// Add one more to trigger eviction
	newFailure := &ruleengine.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID: "test-alert-new",
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ContainerID: "test-container-new",
		},
	}

	// Should not be in cooldown since it's a new entry
	cooldown, count := rc.ShouldCooldown(newFailure)
	assert.False(t, cooldown)
	assert.Equal(t, 1, count)

	// Verify the oldest entry was evicted by trying to access it
	oldFailure := &ruleengine.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID: "test-alert-0",
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ContainerID: "test-container-0",
		},
	}

	// Should not be in cooldown since it was evicted
	cooldown, count = rc.ShouldCooldown(oldFailure)
	assert.False(t, cooldown)
	assert.Equal(t, 1, count)
}
