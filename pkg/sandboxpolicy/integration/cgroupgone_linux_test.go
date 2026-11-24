package integration

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestCgroupGoneChecker: the check decides from the cgroup ID alone, and
// only ESTALE, twice and goneConfirmAfter apart, proves a cgroup gone.
func TestCgroupGoneChecker(t *testing.T) {
	clock := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	var opened []uint64
	var closed []int
	result := map[uint64]error{7: unix.ESTALE, 8: nil, 9: unix.EPERM, 10: unix.ENOENT}
	sys := handleSyscalls{
		openRoot: func(path string) (int, error) {
			if path != "/host/sys/fs/cgroup" {
				t.Fatalf("root %q", path)
			}
			return 3, nil
		},
		fstatfsType: func(fd int) (int64, error) {
			if fd != 3 {
				t.Fatalf("fstatfs fd %d", fd)
			}
			return unix.CGROUP2_SUPER_MAGIC, nil
		},
		openByHandle: func(mountFD int, h unix.FileHandle, flags int) (int, error) {
			if mountFD != 3 || h.Type() != fileIDKernfs || len(h.Bytes()) != 8 || flags&unix.O_PATH == 0 || flags&unix.O_CLOEXEC == 0 {
				t.Fatalf("open_by_handle_at(%d, type %#x len %d, %#x)", mountFD, h.Type(), len(h.Bytes()), flags)
			}
			id := handleID(h)
			opened = append(opened, id)
			if err := result[id]; err != nil {
				return -1, err
			}
			return 40 + int(id), nil
		},
		close: func(fd int) error { closed = append(closed, fd); return nil },
		now:   func() time.Time { return clock },
	}
	c, err := newCgroupGoneChecker("/host/sys/fs/cgroup", sys)
	if err != nil {
		t.Fatal(err)
	}
	// The first check of each ID: nothing is proven gone yet.
	for _, id := range []uint64{7, 8, 9, 10, 0} {
		if c.gone(id) {
			t.Errorf("first check: gone(%d)", id)
		}
	}
	// A second ESTALE too soon proves nothing.
	clock = clock.Add(goneConfirmAfter / 2)
	if c.gone(7) {
		t.Fatal("two ESTALE answers less than goneConfirmAfter apart proved a cgroup gone")
	}
	clock = clock.Add(goneConfirmAfter)
	for id, want := range map[uint64]bool{7: true, 8: false, 9: false, 10: false, 0: false} {
		if got := c.gone(id); got != want {
			t.Errorf("second check: gone(%d) = %v, want %v", id, got, want)
		}
	}
	if len(opened) != 9 || slices.Contains(opened, 0) {
		t.Fatalf("cgroup ID 0 must not be looked up: %v", opened)
	}
	if len(closed) != 2 || closed[0] != 48 || closed[1] != 48 {
		t.Fatalf("the fd of a present cgroup must be closed, and only it: %v", closed)
	}
	if c.failures.Load() != 4 {
		t.Fatalf("undecided checks: %d", c.failures.Load())
	}
	// An answer other than ESTALE between two ESTALE answers starts over
	// (a transient failure, then a live cgroup, then a transient failure).
	result[8] = unix.ESTALE
	c.gone(8)
	result[8] = nil
	clock = clock.Add(2 * goneConfirmAfter)
	c.gone(8)
	result[8] = unix.ESTALE
	clock = clock.Add(2 * goneConfirmAfter)
	if c.gone(8) {
		t.Fatal("ESTALE answers with a live answer between them proved a cgroup gone")
	}
	clock = clock.Add(2 * goneConfirmAfter)
	if !c.gone(8) {
		t.Fatal("two ESTALE answers in a row, far enough apart, must prove it gone")
	}
	// A first ESTALE that no check repeats is forgotten.
	clock = clock.Add(staleForget)
	c.gone(10)
	c.mu.Lock()
	_, kept7 := c.stale[7]
	c.mu.Unlock()
	if kept7 {
		t.Fatal("an ESTALE record no check repeated for staleForget was kept")
	}
	// The handle is the ID in native byte order.
	h := cgroupHandle(0x0102030405060708)
	if handleID(h) != 0x0102030405060708 || len(h.Bytes()) != 8 || h.Type() != 0xfe {
		t.Fatalf("handle type %#x bytes %x", h.Type(), h.Bytes())
	}
}

// TestCgroupGoneCheckerRefusesARoot: a root that cannot be opened, stat'ed,
// or is not cgroup v2 gives no checker, and its fd is closed.
func TestCgroupGoneCheckerRefusesARoot(t *testing.T) {
	for name, tc := range map[string]struct {
		open   error
		statfs error
		magic  int64
	}{
		"open fails":    {open: unix.ENOENT},
		"fstatfs fails": {statfs: unix.EIO, magic: unix.CGROUP2_SUPER_MAGIC},
		"cgroup v1":     {magic: unix.CGROUP_SUPER_MAGIC},
		"tmpfs":         {magic: unix.TMPFS_MAGIC},
	} {
		t.Run(name, func(t *testing.T) {
			closed := 0
			sys := handleSyscalls{
				openRoot: func(string) (int, error) {
					if tc.open != nil {
						return -1, tc.open
					}
					return 3, nil
				},
				fstatfsType:  func(int) (int64, error) { return tc.magic, tc.statfs },
				openByHandle: func(int, unix.FileHandle, int) (int, error) { t.Fatal("no check without a root"); return -1, nil },
				close:        func(int) error { closed++; return nil },
			}
			c, err := newCgroupGoneChecker("/root", sys)
			if err == nil || c != nil {
				t.Fatalf("checker %v, err %v", c, err)
			}
			wantClosed := 1
			if tc.open != nil {
				wantClosed = 0
			}
			if closed != wantClosed {
				t.Fatalf("closed %d, want %d", closed, wantClosed)
			}
		})
	}
}

// TestCgroupGoneSelfTest: the gate's check must answer on this node
// before the gate uses it (S3 review v1 #3).
func TestCgroupGoneSelfTest(t *testing.T) {
	base := func() handleSyscalls {
		sys := startGateSyscalls()
		sys.openByHandle = func(_ int, h unix.FileHandle, flags int) (int, error) {
			if h.Type() != fileIDKernfs || flags != unix.O_PATH|unix.O_CLOEXEC {
				t.Fatalf("self-test opened %d type %#x flags %#x", handleID(h), h.Type(), flags)
			}
			switch handleID(h) {
			case 1:
				return 101, nil
			case 1 | 1<<63:
				return -1, unix.ESTALE
			}
			t.Fatalf("self-test opened %#x", handleID(h))
			return -1, nil
		}
		return sys
	}
	c, err := newCgroupGoneChecker("/r", base())
	if err != nil || c.selfTest() != nil {
		t.Fatalf("a working check failed its self-test: %v %v", err, c.selfTest())
	}
	for name, change := range map[string]func(*handleSyscalls){
		"no CAP_DAC_READ_SEARCH": func(s *handleSyscalls) { s.dacReadSearch = func() (bool, error) { return false, nil } },
		"capget fails":           func(s *handleSyscalls) { s.dacReadSearch = func() (bool, error) { return false, unix.EINVAL } },
		"name_to_handle_at fails": func(s *handleSyscalls) {
			s.handleOf = func(int) (unix.FileHandle, error) { return unix.FileHandle{}, unix.EOPNOTSUPP }
		},
		"not a kernfs handle": func(s *handleSyscalls) {
			s.handleOf = func(int) (unix.FileHandle, error) { return unix.NewFileHandle(1, make([]byte, 8)), nil }
		},
		"open_by_handle_at EPERM": func(s *handleSyscalls) {
			s.openByHandle = func(int, unix.FileHandle, int) (int, error) { return -1, unix.EPERM }
		},
		"open_by_handle_at ESTALE on a live root": func(s *handleSyscalls) {
			s.openByHandle = func(int, unix.FileHandle, int) (int, error) { return -1, unix.ESTALE }
		},
		"the negative probe opens": func(s *handleSyscalls) {
			s.openByHandle = func(int, unix.FileHandle, int) (int, error) { return 101, nil }
		},
		"the negative probe answers ENOENT": func(s *handleSyscalls) {
			s.openByHandle = func(_ int, h unix.FileHandle, _ int) (int, error) {
				if handleID(h) == 1 {
					return 101, nil
				}
				return -1, unix.ENOENT
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			sys := base()
			change(&sys)
			c, err := newCgroupGoneChecker("/r", sys)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.selfTest(); err == nil {
				t.Fatal("the self-test passed")
			}
		})
	}
}

// TestCgroupHandleMatchesTheKernel: rootless, on this host's cgroup v2
// mount. name_to_handle_at (no privilege needed) on this process's own
// cgroup returns the very handle cgroupHandle builds from the cgroup's ID
// (its inode), and the real check never calls that existing cgroup gone,
// with or without CAP_DAC_READ_SEARCH. The ESTALE answer for a removed
// cgroup needs that capability: it is proven in the VM gate.
func TestCgroupHandleMatchesTheKernel(t *testing.T) {
	const root = "/sys/fs/cgroup"
	var fs unix.Statfs_t
	if err := unix.Statfs(root, &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		t.Fatalf("%s is not a cgroup v2 mount (%v, %#x): this test needs one", root, err, fs.Type)
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	var rel string
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		if after, ok := strings.CutPrefix(line, "0::"); ok {
			rel = after
		}
	}
	if rel == "" {
		t.Fatalf("no cgroup v2 entry in /proc/self/cgroup: %q", data)
	}
	dir := filepath.Join(root, rel)
	id, err := cgroupID(root, rel)
	if err != nil {
		t.Fatalf("cgroupID(%s): %v", dir, err)
	}
	h, _, err := unix.NameToHandleAt(unix.AT_FDCWD, dir, 0)
	if err != nil {
		t.Fatalf("name_to_handle_at(%s): %v", dir, err)
	}
	want := cgroupHandle(id)
	if h.Type() != want.Type() || !bytes.Equal(h.Bytes(), want.Bytes()) {
		t.Fatalf("kernel handle type %#x %x, built %#x %x", h.Type(), h.Bytes(), want.Type(), want.Bytes())
	}
	c, err := newCgroupGoneChecker(root, linuxHandleSyscalls)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Close(c.rootFD); err != nil {
			t.Error(err)
		}
	}()
	// The self-test's handle of the root (name_to_handle_at with
	// AT_EMPTY_PATH needs no privilege) is a kernfs handle.
	rootHandle, err := linuxHandleSyscalls.handleOf(c.rootFD)
	if err != nil || rootHandle.Type() != fileIDKernfs || len(rootHandle.Bytes()) != 8 {
		t.Fatalf("handle of the cgroup v2 root: type %#x %x, %v", rootHandle.Type(), rootHandle.Bytes(), err)
	}
	// The live veto on the real file system (rootless): this test's own
	// cgroup's path names its ID.
	c.notePath(id, rel)
	if !c.liveByPath(id) {
		t.Fatalf("the live veto does not recognise %s as cgroup %d", dir, id)
	}
	for range 2 {
		if c.gone(id) {
			t.Fatalf("the existing cgroup %d (%s) was called gone", id, dir)
		}
	}
	capable, err := linuxHandleSyscalls.dacReadSearch()
	if err != nil {
		t.Fatal(err)
	}
	if selfErr := c.selfTest(); !capable {
		if selfErr == nil {
			t.Fatal("the self-test passed without CAP_DAC_READ_SEARCH")
		}
		t.Logf("rootless self-test refuses, as it must: %v", selfErr)
	} else if selfErr != nil {
		t.Fatalf("the self-test failed with CAP_DAC_READ_SEARCH: %v", selfErr)
	}
	// Without the capability the kernel refuses every lookup (EPERM):
	// undecided, never gone.
	fd, err := linuxHandleSyscalls.openByHandle(c.rootFD, cgroupHandle(id), unix.O_PATH|unix.O_CLOEXEC)
	switch {
	case err == nil:
		if err := unix.Close(fd); err != nil {
			t.Error(err)
		}
		// Privileged: a never-used ID is reported gone (ESTALE, twice).
		c.gone(1 << 62)
		time.Sleep(goneConfirmAfter)
		if !c.gone(1 << 62) {
			t.Fatal("a cgroup ID that never existed was not reported gone")
		}
	case errors.Is(err, unix.EPERM):
		if c.failures.Load() == 0 {
			t.Fatal("an EPERM lookup was not counted as undecided")
		}
		t.Logf("rootless: open_by_handle_at answers %v (no CAP_DAC_READ_SEARCH); ESTALE is left to the VM gate", err)
	default:
		t.Fatalf("open_by_handle_at of an existing cgroup: %v", err)
	}
}

// S3 review v2 N2: a noted path that still names the ID vetoes "gone",
// whatever the ESTALE answers; a path never proves gone.
func TestCgroupGoneLiveVeto(t *testing.T) {
	clock := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	live := map[string]uint64{"/kubepods/pod-a": 7}
	var looked []string
	sys := handleSyscalls{
		openRoot:     func(string) (int, error) { return 3, nil },
		fstatfsType:  func(int) (int64, error) { return unix.CGROUP2_SUPER_MAGIC, nil },
		openByHandle: func(int, unix.FileHandle, int) (int, error) { return -1, unix.ESTALE },
		close:        func(int) error { return nil },
		pathID: func(root, rel string) (uint64, error) {
			if root != "/cg" {
				t.Fatalf("root %q", root)
			}
			looked = append(looked, rel)
			if id, ok := live[rel]; ok {
				return id, nil
			}
			return 0, unix.ENOENT
		},
		now: func() time.Time { return clock },
	}
	c, err := newCgroupGoneChecker("/cg", sys)
	if err != nil {
		t.Fatal(err)
	}
	c.notePath(7, "/kubepods/pod-a")
	c.notePath(8, "/kubepods/pod-b")
	c.notePath(9, "/kubepods/pod-a") // a path that names another ID
	check := func(id uint64) bool {
		c.gone(id)
		clock = clock.Add(2 * goneConfirmAfter)
		return c.gone(id)
	}
	if check(7) {
		t.Fatal("a live path with the same ID did not veto gone")
	}
	if !check(8) {
		t.Fatal("a missing path must not veto: the ESTALE answers prove it gone")
	}
	if !check(9) {
		t.Fatal("a path that names another cgroup must not veto")
	}
	if !check(10) {
		t.Fatal("an ID with no noted path is proven gone by the ESTALE answers")
	}
	if !slices.Contains(looked, "/kubepods/pod-a") || slices.Contains(looked, "") {
		t.Fatalf("paths looked up: %v", looked)
	}
	c.mu.Lock()
	_, kept8 := c.paths[8]
	c.mu.Unlock()
	if kept8 {
		t.Fatal("the path of a cgroup proven gone was kept")
	}
}
