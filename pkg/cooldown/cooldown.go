package cooldown

import (
	"container/list"
	"sync"
	"time"

	"github.com/goradd/maps"
)

// CooldownConfig holds the configuration for a cooldown
type CooldownConfig struct {
	Threshold        int
	AlertWindow      time.Duration
	BaseCooldown     time.Duration
	MaxCooldown      time.Duration
	CooldownIncrease float64
}

// Cooldown represents the cooldown mechanism for a specific alert
type Cooldown struct {
	mu              sync.RWMutex
	lastAlertTime   time.Time
	currentCooldown time.Duration
	alertTimes      *list.List
	config          CooldownConfig
}

// CooldownManager manages cooldowns for different alerts
type CooldownManager struct {
	cooldowns maps.SafeMap[string, *Cooldown]
}

// NewCooldownManager creates a new CooldownManager
func NewCooldownManager() *CooldownManager {
	return &CooldownManager{}
}

// NewCooldown creates a new Cooldown with the given configuration
func NewCooldown(config CooldownConfig) *Cooldown {
	return &Cooldown{
		currentCooldown: config.BaseCooldown,
		alertTimes:      list.New(),
		config:          config,
	}
}

// ConfigureCooldown sets up or updates the cooldown configuration for a specific alert
func (cm *CooldownManager) ConfigureCooldown(alertID string, config CooldownConfig) {
	cooldown := NewCooldown(config)
	cm.cooldowns.Set(alertID, cooldown)
}

// ShouldAlert determines if an alert should be triggered based on the cooldown mechanism
func (cm *CooldownManager) ShouldAlert(alertID string) bool {
	if !cm.cooldowns.Has(alertID) {
		// If no configuration exists, always allow the alert
		return true
	}

	cooldown := cm.cooldowns.Get(alertID)

	return cooldown.shouldAlert()
}

func (c *Cooldown) shouldAlert() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Remove alerts outside the window
	for c.alertTimes.Len() > 0 {
		if now.Sub(c.alertTimes.Front().Value.(time.Time)) > c.config.AlertWindow {
			c.alertTimes.Remove(c.alertTimes.Front())
		} else {
			break
		}
	}

	// If we're below the threshold, always allow the alert
	if c.alertTimes.Len() < c.config.Threshold {
		c.alertTimes.PushBack(now)
		c.lastAlertTime = now
		return true
	}

	// If we're at the threshold, allow the alert but increase the cooldown
	if c.alertTimes.Len() == c.config.Threshold {
		c.alertTimes.PushBack(now)
		c.lastAlertTime = now
		c.currentCooldown = time.Duration(float64(c.config.BaseCooldown) * c.config.CooldownIncrease)
		if c.currentCooldown > c.config.MaxCooldown {
			c.currentCooldown = c.config.MaxCooldown
		}
		return true
	}

	// If we've exceeded the threshold, check if we're still in the cooldown period
	if now.Sub(c.lastAlertTime) < c.currentCooldown {
		return false
	}

	// We're past the cooldown period, allow the alert and increase the cooldown further
	c.alertTimes.PushBack(now)
	c.lastAlertTime = now
	c.currentCooldown = time.Duration(float64(c.currentCooldown) * c.config.CooldownIncrease)
	if c.currentCooldown > c.config.MaxCooldown {
		c.currentCooldown = c.config.MaxCooldown
	}
	return true
}

// ResetCooldown resets the cooldown for a specific alert
func (cm *CooldownManager) ResetCooldown(alertID string) {
	if cm.cooldowns.Has(alertID) {
		cooldown := cm.cooldowns.Get(alertID)
		cooldown.mu.Lock()
		cooldown.alertTimes.Init() // Clear the list
		cooldown.currentCooldown = cooldown.config.BaseCooldown
		cooldown.mu.Unlock()
	}
}

// HasCooldownConfig checks if a cooldown configuration exists for a specific alert
func (cm *CooldownManager) HasCooldownConfig(alertID string) bool {
	return cm.cooldowns.Has(alertID)
}
