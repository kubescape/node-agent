package cooldown

import (
	"container/list"
	"sync"
	"time"
)

// AlertID represents the unique identifier for an alert
type AlertID string

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
	mu        sync.RWMutex
	cooldowns map[AlertID]*Cooldown
}

// NewCooldownManager creates a new CooldownManager
func NewCooldownManager() *CooldownManager {
	return &CooldownManager{
		cooldowns: make(map[AlertID]*Cooldown),
	}
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
func (cm *CooldownManager) ConfigureCooldown(alertID AlertID, config CooldownConfig) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cooldown, exists := cm.cooldowns[alertID]; exists {
		cooldown.mu.Lock()
		cooldown.config = config
		cooldown.currentCooldown = config.BaseCooldown
		cooldown.mu.Unlock()
	} else {
		cm.cooldowns[alertID] = NewCooldown(config)
	}
}

// ShouldAlert determines if an alert should be triggered based on the cooldown mechanism
func (cm *CooldownManager) ShouldAlert(alertID AlertID) bool {
	cm.mu.RLock()
	cooldown, exists := cm.cooldowns[alertID]
	cm.mu.RUnlock()

	if !exists {
		// If no configuration exists, always allow the alert
		return true
	}

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

	// Check if we're still in the cooldown period
	if now.Sub(c.lastAlertTime) < c.currentCooldown {
		return false
	}

	// Add current alert time
	c.alertTimes.PushBack(now)

	// If we've exceeded the threshold, increase the cooldown
	if c.alertTimes.Len() > c.config.Threshold {
		c.currentCooldown = time.Duration(float64(c.currentCooldown) * c.config.CooldownIncrease)
		if c.currentCooldown > c.config.MaxCooldown {
			c.currentCooldown = c.config.MaxCooldown
		}
	} else if c.alertTimes.Len() <= c.config.Threshold/2 {
		// If we're below half the threshold, start decreasing the cooldown
		c.currentCooldown = time.Duration(float64(c.currentCooldown) / c.config.CooldownIncrease)
		if c.currentCooldown < c.config.BaseCooldown {
			c.currentCooldown = c.config.BaseCooldown
		}
	}

	c.lastAlertTime = now
	return true
}

// ResetCooldown resets the cooldown for a specific alert
func (cm *CooldownManager) ResetCooldown(alertID AlertID) {
	cm.mu.RLock()
	cooldown, exists := cm.cooldowns[alertID]
	cm.mu.RUnlock()

	if exists {
		cooldown.mu.Lock()
		cooldown.alertTimes.Init() // Clear the list
		cooldown.currentCooldown = cooldown.config.BaseCooldown
		cooldown.mu.Unlock()
	}
}
