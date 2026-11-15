package processtreecreator

import (
	"sync"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/prometheus/procfs"
)

// newProcfsParentReader returns a reader for a pid's CURRENT parent and its
// boot-relative start time, both from /proc/<pid>/stat (fields 4 and 22). It
// uses the same /proc mount as the on-demand start-time reader.
//
// Opening /proc is retried on every call until it succeeds, then kept. The
// reader only runs on the rare unknown-parent exec path, so a retry costs one
// stat of the mount point there and never touches the hot path.
//
// ok is false when the process is gone (ENOENT/ESRCH) or the stat cannot be
// parsed; callers must then keep the parent they already have.
func newProcfsParentReader() func(pid uint32) (ppid uint32, startTimeNs uint64, ok bool) {
	var (
		mu     sync.Mutex
		fs     procfs.FS
		ready  bool
		warned bool
	)
	return func(pid uint32) (uint32, uint64, bool) {
		mu.Lock()
		if !ready {
			f, err := procfs.NewDefaultFS()
			if err != nil {
				if !warned {
					logger.L().Warning("processtree: cannot open /proc, parent re-read unavailable until it can", helpers.Error(err))
					warned = true
				}
				mu.Unlock()
				return 0, 0, false
			}
			fs, ready = f, true
		}
		mu.Unlock()
		proc, err := fs.Proc(int(pid))
		if err != nil {
			return 0, 0, false
		}
		stat, err := proc.Stat()
		if err != nil || stat.PPID <= 0 {
			return 0, 0, false
		}
		return uint32(stat.PPID), stat.Starttime * nsPerTick, true
	}
}
