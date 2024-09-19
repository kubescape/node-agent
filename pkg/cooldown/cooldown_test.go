package cooldown

import (
	"sync"
	"testing"
	"time"
)

func TestNewCooldownManager(t *testing.T) {
	cm := NewCooldownManager()
	if cm == nil {
		t.Error("NewCooldownManager() returned nil")
	}
}

func TestConfigureCooldown(t *testing.T) {
	cm := NewCooldownManager()
	config := CooldownConfig{
		Threshold:        5,
		AlertWindow:      100 * time.Millisecond,
		BaseCooldown:     10 * time.Millisecond,
		MaxCooldown:      500 * time.Millisecond,
		CooldownIncrease: 2.0,
	}

	cm.ConfigureCooldown("test-alert", config)

	if !cm.HasCooldownConfig("test-alert") {
		t.Error("ConfigureCooldown() did not add the configuration")
	}

	// Test updating existing configuration
	newConfig := CooldownConfig{
		Threshold:        10,
		AlertWindow:      200 * time.Millisecond,
		BaseCooldown:     20 * time.Millisecond,
		MaxCooldown:      1 * time.Second,
		CooldownIncrease: 3.0,
	}
	cm.ConfigureCooldown("test-alert", newConfig)

	if !cm.HasCooldownConfig("test-alert") {
		t.Error("ConfigureCooldown() did not update the configuration")
	}
}

func TestShouldAlert(t *testing.T) {
	cm := NewCooldownManager()
	config := CooldownConfig{
		Threshold:        3,
		AlertWindow:      100 * time.Millisecond,
		BaseCooldown:     10 * time.Millisecond,
		MaxCooldown:      50 * time.Millisecond,
		CooldownIncrease: 2.0,
	}
	cm.ConfigureCooldown("test-alert", config)

	// First alert should always be allowed
	if !cm.ShouldAlert("test-alert") {
		t.Error("First alert was not allowed")
	}

	// Second alert within BaseCooldown should not be allowed
	time.Sleep(5 * time.Millisecond)
	if cm.ShouldAlert("test-alert") {
		t.Error("Second alert within BaseCooldown was allowed")
	}

	// Alert after BaseCooldown should be allowed
	time.Sleep(6 * time.Millisecond)
	if !cm.ShouldAlert("test-alert") {
		t.Error("Alert after BaseCooldown was not allowed")
	}

	// Trigger alerts to exceed threshold
	for i := 0; i < 3; i++ {
		time.Sleep(11 * time.Millisecond)
		cm.ShouldAlert("test-alert")
	}

	// Next alert should not be allowed due to increased cooldown
	if cm.ShouldAlert("test-alert") {
		t.Error("Alert was allowed immediately after exceeding threshold")
	}

	// Wait for increased cooldown (2 * BaseCooldown)
	time.Sleep(21 * time.Millisecond)
	if !cm.ShouldAlert("test-alert") {
		t.Error("Alert was not allowed after increased cooldown period")
	}

	// Alert for unconfigured alert ID should always be allowed
	if !cm.ShouldAlert("unconfigured-alert") {
		t.Error("Alert for unconfigured alert ID was not allowed")
	}
}

func TestResetCooldown(t *testing.T) {
	cm := NewCooldownManager()
	config := CooldownConfig{
		Threshold:        3,
		AlertWindow:      100 * time.Millisecond,
		BaseCooldown:     10 * time.Millisecond,
		MaxCooldown:      50 * time.Millisecond,
		CooldownIncrease: 2.0,
	}
	cm.ConfigureCooldown("test-alert", config)

	// Trigger alerts to increase cooldown
	for i := 0; i < 4; i++ {
		cm.ShouldAlert("test-alert")
		time.Sleep(11 * time.Millisecond)
	}

	// Verify that cooldown is in effect
	if cm.ShouldAlert("test-alert") {
		t.Error("Cooldown was not in effect before reset")
	}

	// Reset cooldown
	cm.ResetCooldown("test-alert")

	// Allow a small delay for reset to take effect
	time.Sleep(1 * time.Millisecond)

	// Alert should now be allowed
	if !cm.ShouldAlert("test-alert") {
		t.Error("Alert was not allowed after reset")
	}

	// Resetting an unconfigured alert should not panic
	cm.ResetCooldown("unconfigured-alert")
}

func TestCooldownIncrease(t *testing.T) {
	cm := NewCooldownManager()
	config := CooldownConfig{
		Threshold:        2,
		AlertWindow:      50 * time.Millisecond,
		BaseCooldown:     10 * time.Millisecond,
		MaxCooldown:      100 * time.Millisecond,
		CooldownIncrease: 2.0,
	}
	cm.ConfigureCooldown("test-alert", config)

	// Trigger alerts to increase cooldown
	for i := 0; i < 3; i++ {
		time.Sleep(11 * time.Millisecond)
		cm.ShouldAlert("test-alert")
	}

	// Next alert should be blocked due to increased cooldown
	time.Sleep(11 * time.Millisecond)
	if cm.ShouldAlert("test-alert") {
		t.Error("Alert was allowed despite increased cooldown")
	}

	// Wait for increased cooldown and alert should be allowed
	time.Sleep(11 * time.Millisecond)
	if !cm.ShouldAlert("test-alert") {
		t.Error("Alert was not allowed after increased cooldown period")
	}
}

func TestCooldownDecrease(t *testing.T) {
	cm := NewCooldownManager()
	config := CooldownConfig{
		Threshold:        4,
		AlertWindow:      50 * time.Millisecond,
		BaseCooldown:     10 * time.Millisecond,
		MaxCooldown:      100 * time.Millisecond,
		CooldownIncrease: 2.0,
	}
	cm.ConfigureCooldown("test-alert", config)

	// Trigger alerts to increase cooldown
	for i := 0; i < 5; i++ {
		time.Sleep(11 * time.Millisecond)
		cm.ShouldAlert("test-alert")
	}

	// Wait for alert window to pass
	time.Sleep(51 * time.Millisecond)

	// Trigger a single alert
	cm.ShouldAlert("test-alert")

	// Wait for base cooldown
	time.Sleep(11 * time.Millisecond)

	// Alert should be allowed and cooldown should have decreased
	if !cm.ShouldAlert("test-alert") {
		t.Error("Alert was not allowed after cooldown should have decreased")
	}
}

func TestConcurrency(t *testing.T) {
	cm := NewCooldownManager()
	config := CooldownConfig{
		Threshold:        5,
		AlertWindow:      100 * time.Millisecond,
		BaseCooldown:     10 * time.Millisecond,
		MaxCooldown:      500 * time.Millisecond,
		CooldownIncrease: 2.0,
	}
	cm.ConfigureCooldown("test-alert", config)

	// Run 100 goroutines simultaneously
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cm.ShouldAlert("test-alert")
		}()
	}

	wg.Wait()

	// Check that the cooldown has increased
	if cm.ShouldAlert("test-alert") {
		t.Error("Cooldown did not increase as expected under concurrent load")
	}
}
