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
// ok is false when the process is gone (ENOENT/ESRCH) or the stat cannot be
// parsed; callers must then keep the parent they already have.
func newProcfsParentReader() func(pid uint32) (ppid uint32, startTimeNs uint64, ok bool) {
	var (
		once    sync.Once
		fs      procfs.FS
		fsReady bool
	)
	return func(pid uint32) (uint32, uint64, bool) {
		once.Do(func() {
			f, err := procfs.NewDefaultFS()
			if err != nil {
				logger.L().Warning("processtree: cannot open /proc, parent re-read disabled", helpers.Error(err))
				return
			}
			fs, fsReady = f, true
		})
		if !fsReady {
			return 0, 0, false
		}
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
