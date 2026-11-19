//go:build linux

package integration

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	rf "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/restartfence"
	"golang.org/x/sys/unix"
)

// Exit proof uses the full generation-bearing kernfs handle, never a path's
// absence or a truncated inode. The caller supplies the trusted host root.
type fenceExitProbe interface {
	Gone(uint64) (bool, error)
	Close() error
}
type fenceReclaimer interface {
	RemoveExitedChild(rf.PodRef, rf.ChildRef) (rf.PodRef, error)
	RemoveExited(rf.PodRef) error
	RemoveExitedOrphanCounters(uint64) error
}
type handleExitProbe struct {
	fd   int
	kind int32
}

func (p *handleExitProbe) Close() error { return unix.Close(p.fd) }
func (p *handleExitProbe) Gone(id uint64) (bool, error) {
	if id == 0 {
		return false, errors.New("zero cgroup handle")
	}
	b := make([]byte, 8)
	binary.NativeEndian.PutUint64(b, id)
	fd, err := unix.OpenByHandleAt(p.fd, unix.NewFileHandle(p.kind, b), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if errors.Is(err, unix.ESTALE) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, unix.Close(fd)
}

// On the supported 64-bit amd64 kernfs cohort, the hierarchy root is the
// first allocation (full ID 1). This prevents a namespace-relative subtree
// presented as mountinfo root "/" from authorizing negative lookup proofs.
// Other layouts/architectures remain retained, not guessed compatible.
func validateFenceRootHandle(h unix.FileHandle, arch string) error {
	if arch != "amd64" || h.Type() != 0xfe || len(h.Bytes()) != 8 {
		return errors.New("unsupported host kernfs root handle")
	}
	if binary.NativeEndian.Uint64(h.Bytes()) != 1 {
		return errors.New("exit proof requires full host hierarchy root ID 1")
	}
	return nil
}

// mountinfo's cgroup root field is rendered relative to the reader's cgroup
// namespace, not the VFS superblock root. A host-root bind inherited by a
// container can be printed as /../.., whereas a remounted subtree prints /.
// Call only after proving the exact descriptor's global kernfs root handle.
func validateFenceRootMountView(info []byte, mountID int) error {
	id := strconv.Itoa(mountID)
	found := false
	for _, line := range strings.Split(string(info), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != id {
			continue
		}
		dash := slices.Index(f, "-")
		if found || dash < 6 || dash+3 >= len(f) || f[dash+1] != "cgroup2" {
			return errors.New("invalid host cgroup mount identity")
		}
		// Only an actual root label or a namespace-relative chain of
		// ancestors is consistent with the verified global root handle.
		view := f[3]
		if view != "/" {
			for strings.HasPrefix(view, "/..") {
				view = view[3:]
			}
			if view != "" {
				return errors.New("unexpected host cgroup mount root view")
			}
		}
		found = true
	}
	if !found {
		return errors.New("trusted host cgroup mount ID is not visible")
	}
	return nil
}

func openFenceExitProbe(root string) (fenceExitProbe, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("trusted absolute host cgroup root required")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, root, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		return nil, err
	}
	fail := func(err error) (fenceExitProbe, error) { return nil, errors.Join(err, unix.Close(fd)) }
	var fs unix.Statfs_t
	if err = unix.Fstatfs(fd, &fs); err != nil {
		return fail(err)
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return fail(errors.New("exit probe root is not cgroup2"))
	}
	h, mountID, err := unix.NameToHandleAt(fd, "", unix.AT_EMPTY_PATH)
	if err != nil {
		return fail(err)
	}
	// FILEID_KERNFS is 0xfe with exactly one full 64-bit kernfs ID.
	if err := validateFenceRootHandle(h, runtime.GOARCH); err != nil {
		return fail(err)
	}
	// Check the mount ID independently on the same descriptor. The mountinfo
	// pathname is only corroboration after the full root handle proved scope.
	var meta unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_STATX_DONT_SYNC, unix.STATX_MNT_ID, &meta); err != nil {
		return fail(fmt.Errorf("statx host cgroup mount identity: %w", err))
	}
	if mountID <= 0 || meta.Mask&unix.STATX_MNT_ID == 0 || meta.Mnt_id != uint64(mountID) {
		return fail(errors.New("host cgroup descriptor mount ID mismatch"))
	}
	info, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return fail(err)
	}
	if err := validateFenceRootMountView(info, mountID); err != nil {
		return fail(err)
	}
	// Calibrate actual handle lookup before interpreting any negative answer.
	live, err := unix.OpenByHandleAt(fd, h, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return fail(fmt.Errorf("exit probe calibration: %w", err))
	}
	round, roundMount, err := unix.NameToHandleAt(live, "", unix.AT_EMPTY_PATH)
	closeErr := unix.Close(live)
	if err != nil || closeErr != nil {
		return fail(errors.Join(err, closeErr))
	}
	if roundMount != mountID || round.Type() != h.Type() || !slices.Equal(round.Bytes(), h.Bytes()) {
		return fail(errors.New("exit probe calibration identity mismatch"))
	}
	return &handleExitProbe{fd: fd, kind: h.Type()}, nil
}

// ReclamationError reports unavailable/degraded physical-exit probing without
// pretending that reclamation occurred. Publication still fails closed at the
// kernel capacity limit; inability to GC never authorizes dropping a row.
func (m *ExecFenceManager) ReclamationError() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.gcError
}

// reclaimExited runs under m.mu before publication. Each pass examines at most
// 64 pods (each kernel row has bounded children), rotating across retained rows.
func (m *ExecFenceManager) reclaimExited(groups map[uint64][]preparedFenceChild) {
	if m.exitProbe == nil {
		return
	}
	m.gcError = nil
	k, ok := m.kernel.(fenceReclaimer)
	if !ok {
		m.gcError = errors.New("kernel does not support exact exit reclamation")
		return
	}
	probe, err := m.exitProbe()
	if err != nil {
		m.gcError = err
		return
	}
	defer func() { m.gcError = errors.Join(m.gcError, probe.Close()) }()
	snapshot, err := m.kernel.Snapshot()
	if err != nil {
		m.gcError = err
		return
	}
	ids := make([]uint64, 0, len(snapshot.PerCgroup))
	for id := range snapshot.PerCgroup {
		if id != 0 {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	start, _ := slices.BinarySearch(ids, m.gcCursor)
	if start == len(ids) {
		start = 0
	}
	// Current census rows get priority before their next publication. Cap this
	// extra work too; pathological census size cannot monopolize reconciliation.
	work := make([]uint64, 0, 64)
	for _, id := range ids {
		if len(groups[id]) != 0 && len(work) < 32 {
			work = append(work, id)
		}
	}
	for n := 0; n < len(ids) && n < 32; n++ {
		id := ids[(start+n)%len(ids)]
		m.gcCursor = id + 1
		if !slices.Contains(work, id) {
			work = append(work, id)
		}
	}
	for _, id := range work {
		state, found, err := m.kernel.ReadPod(id)
		if err != nil {
			m.gcError = errors.Join(m.gcError, err)
			continue
		}
		if !found {
			// A killed writer may leave a counter reservation without a
			// published pod row. Counter iteration still finds it after
			// restart; prove physical exit before reclaiming it.
			if len(groups[id]) != 0 {
				continue
			}
			gone, e := probe.Gone(id)
			if e == nil && gone {
				e = k.RemoveExitedOrphanCounters(id)
				if e == nil {
					delete(m.pods, id)
					delete(m.scope, id)
				}
			}
			m.gcError = errors.Join(m.gcError, e)
			continue
		}
		current := groups[id]
		if len(current) == 0 {
			gone, e := probe.Gone(id)
			if e != nil {
				m.gcError = errors.Join(m.gcError, e)
				continue
			}
			if gone {
				if e = k.RemoveExited(state.PodRef); e != nil {
					m.gcError = errors.Join(m.gcError, e)
					continue
				}
				delete(m.pods, id)
				delete(m.scope, id)
				continue
			}
		}
		for _, child := range state.Children {
			present := false
			for _, c := range current {
				if c.cgroups.ContainerID == child.ID {
					present = true
					break
				}
			}
			if present {
				continue
			}
			gone, e := probe.Gone(child.ID)
			if e != nil {
				m.gcError = errors.Join(m.gcError, e)
				continue
			}
			if !gone {
				continue
			}
			ref, e := k.RemoveExitedChild(state.PodRef, child.ChildRef)
			if e != nil {
				m.gcError = errors.Join(m.gcError, e)
				break
			}
			state.PodRef = ref
			m.pods[id] = ref
		}
	}
}

// A retained exact binding may outlive its kernel row after GC. Re-prove its
// physical exit for every native teardown; a prior GC observation is not a seal.
func (m *ExecFenceManager) bindingExited(childID uint64) (bool, error) {
	if m.exitProbe == nil {
		return false, nil
	}
	probe, err := m.exitProbe()
	if err != nil {
		return false, err
	}
	gone, err := probe.Gone(childID)
	return gone, errors.Join(err, probe.Close())
}
