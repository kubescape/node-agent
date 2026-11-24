package integration

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"golang.org/x/sys/unix"
)

// fileIDKernfs is FILEID_KERNFS (include/linux/exportfs.h): a kernfs file
// handle whose payload is the node's 64-bit ID. On cgroup v2 that ID is the
// cgroup ID (the directory's inode), which the kernel never reuses.
const fileIDKernfs = 0xfe

// handleSyscalls is the system call layer of the cgroup-gone check
// (replaced in tests).
type handleSyscalls struct {
	// openRoot opens the cgroup v2 mount root (a directory).
	openRoot func(path string) (int, error)
	// fstatfsType returns the file system magic of fd.
	fstatfsType func(fd int) (int64, error)
	// openByHandle is open_by_handle_at(2).
	openByHandle func(mountFD int, handle unix.FileHandle, flags int) (int, error)
	// handleOf is name_to_handle_at(fd, "", AT_EMPTY_PATH): the kernel's own
	// handle of the open directory fd.
	handleOf func(fd int) (unix.FileHandle, error)
	// dacReadSearch reports whether CAP_DAC_READ_SEARCH is effective.
	dacReadSearch func() (bool, error)
	close         func(fd int) error
	// pathID is cgroupID: the cgroup ID (inode) of the cgroup v2 directory
	// rel under root, for the live veto.
	pathID func(root, rel string) (uint64, error)
	// now is the clock of the two-check rule.
	now func() time.Time
}

var linuxHandleSyscalls = handleSyscalls{
	openRoot: func(path string) (int, error) {
		return unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	},
	fstatfsType: func(fd int) (int64, error) {
		var fs unix.Statfs_t
		if err := unix.Fstatfs(fd, &fs); err != nil {
			return 0, err
		}
		return fs.Type, nil
	},
	openByHandle: unix.OpenByHandleAt,
	handleOf: func(fd int) (unix.FileHandle, error) {
		h, _, err := unix.NameToHandleAt(fd, "", unix.AT_EMPTY_PATH)
		return h, err
	},
	dacReadSearch: func() (bool, error) {
		// As the root barrier's self-test (rootbarrier/selftest_linux.go).
		hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		var data [2]unix.CapUserData
		if err := unix.Capget(&hdr, &data[0]); err != nil {
			return false, err
		}
		c := uint(unix.CAP_DAC_READ_SEARCH)
		return data[c/32].Effective&(1<<(c%32)) != 0, nil
	},
	close:  unix.Close,
	pathID: cgroupID,
	now:    time.Now,
}

// goneConfirmAfter is the least time between the two ESTALE answers that
// prove a cgroup gone (see cgroupGoneChecker.gone). It is shorter than the
// refresh period (5 s), so a removed cgroup is proven by the next refresh
// or sweep, and long enough that one transient failure cannot answer both.
const goneConfirmAfter = time.Second

// staleForget drops a first ESTALE that no check repeated for this long
// (the cgroup's record is gone): the map stays bounded.
const staleForget = 10 * time.Minute

// cgroupHandle is the kernfs file handle of cgroup ID id.
func cgroupHandle(id uint64) unix.FileHandle {
	var payload [8]byte
	binary.NativeEndian.PutUint64(payload[:], id)
	return unix.NewFileHandle(fileIDKernfs, payload[:])
}

// cgroupGoneChecker proves that a cgroup no longer exists from its ID alone,
// never from a path: open_by_handle_at on the cgroup v2 root with the
// cgroup's kernfs handle. The kernel looks the ID up in the hierarchy's ID
// table (kernfs_find_and_get_node_by_id) and answers ESTALE when no active
// node has it: the cgroup was removed. Since the ID is never reused, a
// repeated answer is final (gone has the two-check rule). Any other failure (EPERM without CAP_DAC_READ_SEARCH,
// EMFILE, ...) proves nothing: the cgroup is then not gone, and its mark
// stays (fail-closed).
type cgroupGoneChecker struct {
	sys    handleSyscalls
	rootFD int
	// mu guards stale: when each cgroup ID first answered ESTALE, and when
	// it last did (the sections' sweeps call gone concurrently).
	root      string
	mu        sync.Mutex
	stale     map[uint64]staleSeen
	lastForgo time.Time
	// paths are the cgroup paths noted for IDs (notePath), for the live
	// veto. Dropped when the ID is proven gone, or not noted again for
	// staleForget.
	paths map[uint64]notedPath
	// failures counts the checks that could not decide (logged on the
	// first one only, so a missing capability does not flood the log).
	failures atomic.Uint64
}

// newCgroupGoneChecker opens the cgroup v2 root at root (the host's
// /sys/fs/cgroup) and keeps it open for the checks, for as long as the
// process runs (the start gate is never turned off). It refuses a root that
// is not cgroup v2: cgroup v1 file handles carry other IDs.
func newCgroupGoneChecker(root string, sys handleSyscalls) (*cgroupGoneChecker, error) {
	fd, err := sys.openRoot(root)
	if err != nil {
		return nil, fmt.Errorf("cgroup-gone check: open %s: %w", root, err)
	}
	magic, err := sys.fstatfsType(fd)
	if err == nil && magic != unix.CGROUP2_SUPER_MAGIC {
		err = fmt.Errorf("%s is not cgroup v2 (magic %#x)", root, magic)
	}
	if err != nil {
		_ = sys.close(fd)
		return nil, fmt.Errorf("cgroup-gone check: %w", err)
	}
	return &cgroupGoneChecker{sys: sys, rootFD: fd, root: root, stale: map[uint64]staleSeen{}, paths: map[uint64]notedPath{}}, nil
}

type staleSeen struct{ first, last time.Time }

type notedPath struct {
	path  string
	noted time.Time
}

// notePath records the cgroup path of ID id (relative to the cgroup v2
// root), from the gate's joins and the refresh's binds. With the gate on
// these cover every pod record S2 holds, so the veto reaches S2's gone
// checks too without changing SetCgroupGone's signature.
func (c *cgroupGoneChecker) notePath(id uint64, path string) {
	if id == 0 || path == "" {
		return
	}
	now := c.sys.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.paths[id] = notedPath{path: path, noted: now}
}

// liveByPath reports whether the noted path of id exists and is the
// cgroup with that ID: the cgroup is then live. A path only ever vetoes;
// a missing path proves nothing (it may be another name of a live cgroup).
func (c *cgroupGoneChecker) liveByPath(id uint64) bool {
	c.mu.Lock()
	noted, ok := c.paths[id]
	c.mu.Unlock()
	if !ok {
		return false
	}
	got, err := c.sys.pathID(c.root, noted.path)
	return err == nil && got == id
}

// selfTest proves the check can answer on this node before the gate uses it
// (S3 review v1 #3): CAP_DAC_READ_SEARCH is effective, the kernel's handle of
// the cgroup v2 root is a kernfs handle of 8 bytes, and the handle built from
// its ID opens, with the flags gone uses. Without the capability in the
// initial user namespace every open_by_handle_at answers EPERM (also on
// 6.12+: the relaxed check needs O_DIRECTORY, which gone does not pass), and
// the check could never prove anything gone.
func (c *cgroupGoneChecker) selfTest() error {
	ok, err := c.sys.dacReadSearch()
	if err != nil {
		return fmt.Errorf("cgroup-gone self-test: reading capabilities: %w", err)
	}
	if !ok {
		return fmt.Errorf("cgroup-gone self-test: CAP_DAC_READ_SEARCH is not effective")
	}
	h, err := c.sys.handleOf(c.rootFD)
	if err != nil {
		return fmt.Errorf("cgroup-gone self-test: name_to_handle_at on the cgroup v2 root: %w", err)
	}
	if h.Type() != fileIDKernfs || len(h.Bytes()) != 8 {
		return fmt.Errorf("cgroup-gone self-test: the cgroup v2 root's handle is type %#x, %d bytes; want a kernfs handle of 8 bytes", h.Type(), len(h.Bytes()))
	}
	id := binary.NativeEndian.Uint64(h.Bytes())
	fd, err := c.sys.openByHandle(c.rootFD, cgroupHandle(id), unix.O_PATH|unix.O_CLOEXEC)
	if err != nil {
		return fmt.Errorf("cgroup-gone self-test: open_by_handle_at of the live cgroup v2 root (ID %d): %w", id, err)
	}
	if err := c.sys.close(fd); err != nil {
		return fmt.Errorf("cgroup-gone self-test: %w", err)
	}
	// The negative probe (S3 review v2 N3): the root's ID with bit 63 set
	// never names a cgroup (on 64-bit, kernfs finds the node by the ID's
	// low bits and then compares the full ID), so the kernel must answer
	// ESTALE. A kernel or LSM that answers anything else could never prove
	// a cgroup gone.
	probe := id | 1<<63
	fd, err = c.sys.openByHandle(c.rootFD, cgroupHandle(probe), unix.O_PATH|unix.O_CLOEXEC)
	if err == nil {
		_ = c.sys.close(fd)
		return fmt.Errorf("cgroup-gone self-test: the never-valid cgroup ID %#x opened", probe)
	}
	if !errors.Is(err, unix.ESTALE) {
		return fmt.Errorf("cgroup-gone self-test: the never-valid cgroup ID %#x answered %v, not ESTALE: nothing could be proven gone", probe, err)
	}
	return nil
}

// gone reports whether cgroup ID id is proven removed: ESTALE on two
// checks at least goneConfirmAfter apart, with no other answer between
// them. One ESTALE does not prove it (S3 review v1 #4): the kernel also
// answers ESTALE for a live cgroup when it fails to allocate the inode
// (kernfs_get_inode failing in kernfs_fh_to_dentry, 6.1 fs/kernfs/mount.c
// :116-119; d_obtain_alias(NULL) in 6.18), on 6.12+ do_handle_to_path turns
// every decode error but ENOMEM into ESTALE (reconnect_path or get_name
// failing, e.g. ENFILE), and on 6.1 exportfs_decode_fh collapses decode
// errors into ESTALE. Those are transient; a removal is permanent, and the
// ID is never reused.
func (c *cgroupGoneChecker) gone(id uint64) bool {
	if id == 0 {
		return false
	}
	fd, err := c.sys.openByHandle(c.rootFD, cgroupHandle(id), unix.O_PATH|unix.O_CLOEXEC)
	stale := errors.Is(err, unix.ESTALE)
	if err == nil {
		_ = c.sys.close(fd)
	}
	now := c.sys.now()
	c.mu.Lock()
	seen, before := c.stale[id]
	switch {
	case !stale:
		delete(c.stale, id)
	case !before:
		c.stale[id] = staleSeen{first: now, last: now}
	default:
		c.stale[id] = staleSeen{first: seen.first, last: now}
	}
	if now.Sub(c.lastForgo) >= staleForget {
		c.lastForgo = now
		for k, v := range c.stale {
			if now.Sub(v.last) >= staleForget {
				delete(c.stale, k)
			}
		}
		for k, v := range c.paths {
			if now.Sub(v.noted) >= staleForget {
				delete(c.paths, k)
			}
		}
	}
	c.mu.Unlock()
	if err == nil {
		return false
	}
	if stale {
		if !before || now.Sub(seen.first) < goneConfirmAfter {
			return false
		}
		// The live veto (S3 review v2 N2): a noted path that still names
		// this ID wins over any number of ESTALE answers.
		if c.liveByPath(id) {
			c.mu.Lock()
			delete(c.stale, id)
			c.mu.Unlock()
			return false
		}
		c.mu.Lock()
		delete(c.paths, id)
		c.mu.Unlock()
		return true
	}
	if c.failures.Add(1) == 1 {
		logger.L().Warning("sandbox start gate: the cgroup-gone check cannot decide; marks are kept", helpers.String("cgroup", fmt.Sprint(id)), helpers.Error(err))
	}
	return false
}
