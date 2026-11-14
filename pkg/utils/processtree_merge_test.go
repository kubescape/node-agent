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

// The bulk exporter sends only the merged tree, so a field CopyProcess drops
// is missing from every bulked alert.
func TestCopyProcess_CarriesEveryNodeField(t *testing.T) {
	uid, gid := uint32(1000), uint32(1001)
	upperLayer := true
	src := &armotypes.Process{
		PID:        5,
		PPID:       1,
		Comm:       "a",
		Pcomm:      "sh",
		Cmdline:    "a -x",
		Cwd:        "/tmp",
		Path:       "/tmp/a",
		Hardlink:   "/tmp/a",
		Uid:        &uid,
		Gid:        &gid,
		UserName:   "app",
		GroupName:  "app",
		StartTime:  time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC),
		UpperLayer: &upperLayer,
		ChildrenMap: map[armotypes.CommPID]*armotypes.Process{
			{PID: 6}: {PID: 6},
		},
	}

	want := *src
	want.ChildrenMap = map[armotypes.CommPID]*armotypes.Process{}
	assert.Equal(t, &want, CopyProcess(src))
}

// A process first seen without these fields gets them from a later alert in the
// same bulk.
func TestEnrichProcess_FillsEveryEmptyNodeField(t *testing.T) {
	upperLayer := true
	target := &armotypes.Process{PID: 5, Comm: "a"}
	source := &armotypes.Process{
		PID:        5,
		Comm:       "a",
		Hardlink:   "/tmp/a",
		UserName:   "app",
		GroupName:  "app",
		UpperLayer: &upperLayer,
	}

	EnrichProcess(target, source)

	assert.Equal(t, "/tmp/a", target.Hardlink)
	assert.Equal(t, "app", target.UserName)
	assert.Equal(t, "app", target.GroupName)
	if assert.NotNil(t, target.UpperLayer) {
		assert.True(t, *target.UpperLayer)
		assert.NotSame(t, source.UpperLayer, target.UpperLayer, "the pointer must be copied, not shared")
	}
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
