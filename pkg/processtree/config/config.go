package config

import "time"

type ExitCleanupConfig struct {
	MaxPendingExits int           `mapstructure:"maxPendingExits"`
	CleanupInterval time.Duration `mapstructure:"cleanupInterval"`
	CleanupDelay    time.Duration `mapstructure:"cleanupDelay"`
}
