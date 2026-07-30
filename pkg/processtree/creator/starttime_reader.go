package processtreecreator

import (
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/prometheus/procfs"
)

// nsPerTick converts /proc/<pid>/stat field 22 (clock ticks since boot) to
// boot-relative nanoseconds. USER_HZ is 100, so this is exact: 1e9 / 100.
// The procfs feeder defines the same constant for the periodic scan; both are
// package-private and must stay in agreement.
const nsPerTick = uint64(10_000_000)

// newProcfsStartTimeReader returns the on-demand equivalent of the periodic
// scan's start-time read: /proc/<pid>/stat field 22 (creation time in clock
// ticks since boot), converted to boot-relative nanoseconds plus the derived
// display-only wall time.
//
// This is NOT the rejected "derive the start time from an exec event" option.
// That rejection was of event TIMESTAMPS — an exec event stamps the exec
// instant, not process creation, so the value changes when a process re-execs.
// This reads the same kernel source as the periodic scan, at the same
// semantics, just fetched when the node is created instead of waiting up to a
// full scan interval. Without it every process shorter than one scan interval
// carries a zero start time, and short-lived processes are exactly the
// population most exposed to pid reuse.
//
// Returns zeros when the process is already gone (it died before its creation
// event was processed) — the caller keeps the pre-existing zero-value
// behaviour rather than guessing.
func newProcfsStartTimeReader() func(pid uint32) (uint64, time.Time) {
	var (
		once     sync.Once
		fs       procfs.FS
		fsReady  bool
		bootTime time.Time
	)
	return func(pid uint32) (uint64, time.Time) {
		// Resolve /proc and btime once, not per read: procfs.NewProc would
		// re-stat the mount point on every call.
		once.Do(func() {
			f, err := procfs.NewDefaultFS()
			if err != nil {
				logger.L().Warning("processtree: cannot open /proc, on-demand start times disabled", helpers.Error(err))
				return
			}
			fs, fsReady = f, true
			if s, err := f.Stat(); err == nil {
				bootTime = time.Unix(int64(s.BootTime), 0)
			} else {
				// Boot-relative identity is unaffected; only the display value is lost.
				logger.L().Warning("processtree: cannot read /proc/stat btime, wall-clock start times disabled", helpers.Error(err))
			}
		})
		if !fsReady {
			return 0, time.Time{}
		}
		proc, err := fs.Proc(int(pid))
		if err != nil {
			return 0, time.Time{}
		}
		stat, err := proc.Stat()
		if err != nil || stat.Starttime == 0 {
			return 0, time.Time{}
		}
		ns := stat.Starttime * nsPerTick
		if bootTime.IsZero() {
			return ns, time.Time{}
		}
		return ns, bootTime.Add(time.Duration(ns))
	}
}
