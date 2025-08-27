package fimmanager

import (
	"context"
	"testing"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFIMManager(t *testing.T) {
	// Test with FIM disabled
	cfg := config.Config{
		FIM: config.FIMConfig{
			Enabled: false,
		},
	}

	manager, err := NewFIMManager(cfg, "test-cluster", "test-node", nil)
	require.NoError(t, err)
	assert.NotNil(t, manager)
	assert.False(t, manager.IsRunning())
	assert.False(t, manager.cfg.FIM.Enabled)

	// Test with FIM enabled but no directories
	cfg.FIM.Enabled = true
	cfg.FIM.Directories = []config.FIMDirectoryConfig{}

	manager, err = NewFIMManager(cfg, "test-cluster", "test-node", nil)
	assert.Error(t, err)
	assert.Nil(t, manager)

	// Test with FIM enabled and valid directories
	cfg.FIM.Directories = []config.FIMDirectoryConfig{
		{
			Path:     "/etc",
			OnCreate: true,
			OnChange: true,
			OnRemove: true,
		},
	}

	manager, err = NewFIMManager(cfg, "test-cluster", "test-node", nil)
	require.NoError(t, err)
	assert.NotNil(t, manager)
	assert.True(t, manager.cfg.FIM.Enabled)
	assert.Len(t, manager.cfg.FIM.Directories, 1)
}

func TestFIMManagerStartStop(t *testing.T) {
	cfg := config.Config{
		FIM: config.FIMConfig{
			Enabled: true,
			Directories: []config.FIMDirectoryConfig{
				{
					Path:     "/etc",
					OnCreate: true,
					OnChange: true,
					OnRemove: true,
				},
			},
		},
	}

	manager, err := NewFIMManager(cfg, "test-cluster", "test-node", nil)
	require.NoError(t, err)

	// Test start
	ctx := context.Background()
	err = manager.Start(ctx)
	// Note: This might fail in test environment due to lack of CAP_SYS_ADMIN
	// That's expected behavior
	if err != nil {
		t.Logf("FIM manager start failed (expected in test environment): %v", err)
	} else {
		assert.True(t, manager.IsRunning())
	}

	// Test stop
	manager.Stop()
	assert.False(t, manager.IsRunning())
}

func TestFIMManagerGetStatus(t *testing.T) {
	cfg := config.Config{
		FIM: config.FIMConfig{
			Enabled: true,
			Directories: []config.FIMDirectoryConfig{
				{
					Path:     "/etc",
					OnCreate: true,
					OnChange: true,
					OnRemove: true,
				},
				{
					Path:     "/var/log",
					OnCreate: true,
					OnChange: false,
					OnRemove: true,
				},
			},
		},
	}

	manager, err := NewFIMManager(cfg, "test-cluster", "test-node", nil)
	require.NoError(t, err)

	status := manager.GetStatus()
	assert.NotNil(t, status)
	assert.True(t, status["enabled"].(bool))
	assert.False(t, status["running"].(bool))
	assert.Equal(t, 2, status["directories"].(int))
}
