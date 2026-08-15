package utils

import (
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
)

func TestCopyProcess_CarriesStartTime(t *testing.T) {
	wall := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	src := &armotypes.Process{PID: 5, Comm: "a", StartTime: wall}
	assert.Equal(t, wall, CopyProcess(src).StartTime,
		"CopyProcess strips any field it does not explicitly list — StartTime must be listed")
}

func TestEnrichProcess_FillsEmptyStartTime(t *testing.T) {
	wall := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	target := &armotypes.Process{PID: 5}
	EnrichProcess(target, &armotypes.Process{PID: 5, StartTime: wall})
	assert.Equal(t, wall, target.StartTime)

	// fill-if-empty: an existing value is never overwritten
	other := wall.Add(time.Hour)
	EnrichProcess(target, &armotypes.Process{PID: 5, StartTime: other})
	assert.Equal(t, wall, target.StartTime)
}
