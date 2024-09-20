package cooldown

import (
	"fmt"
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

func TestComprehensiveShouldAlert(t *testing.T) {
	cm := NewCooldownManager()
	config := CooldownConfig{
		Threshold:        3,
		AlertWindow:      100 * time.Millisecond,
		BaseCooldown:     10 * time.Millisecond,
		MaxCooldown:      50 * time.Millisecond,
		CooldownIncrease: 2.0,
	}
	cm.ConfigureCooldown("test-alert", config)

	fmt.Println("Starting comprehensive cooldown test...")
	fmt.Printf("Config: Threshold=%d, AlertWindow=%v, BaseCooldown=%v, MaxCooldown=%v, CooldownIncrease=%.1f\n\n",
		config.Threshold, config.AlertWindow, config.BaseCooldown, config.MaxCooldown, config.CooldownIncrease)

	testCases := []struct {
		name     string
		delay    time.Duration
		expected bool
	}{
		{"First alert", 0, true},
		{"Second alert (immediate)", 0, true},
		{"Third alert (immediate)", 0, true},
		{"Fourth alert (immediate, should increase cooldown)", 0, true},
		{"Fifth alert (immediate, should be blocked)", 0, false},
		{"Sixth alert (after base cooldown)", config.BaseCooldown, false},
		{"Seventh alert (after increased cooldown)", config.BaseCooldown * 2, true},
		{"Eighth alert (immediate after cooldown)", 0, false},
		{"Ninth alert (after alert window)", config.AlertWindow, true},
		{"Tenth alert (immediate)", 0, true},
		{"Eleventh alert (immediate)", 0, true},
	}

	startTime := time.Now()

	for i, tc := range testCases {
		time.Sleep(tc.delay)
		result := cm.ShouldAlert("test-alert")
		elapsed := time.Since(startTime)

		cooldown := cm.cooldowns.Get("test-alert")
		fmt.Printf("%d. %s (at %v):\n   Expected: %v, Got: %v\n   Alert Count: %d, Current Cooldown: %v\n",
			i+1, tc.name, elapsed.Round(time.Millisecond), tc.expected, result, cooldown.alertTimes.Len(), cooldown.currentCooldown)

		if result != tc.expected {
			t.Errorf("%s: expected %v, got %v", tc.name, tc.expected, result)
		}
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
		cm.ShouldAlert("test-alert")
	}

	// Next alert should be blocked due to increased cooldown
	if cm.ShouldAlert("test-alert") {
		t.Error("Alert was allowed despite increased cooldown")
	}

	// Wait for increased cooldown and alert should be allowed
	time.Sleep(21 * time.Millisecond)
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
