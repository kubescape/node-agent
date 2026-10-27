package igbackend

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// ImageIndexLimits may tighten, never enlarge, the finite indexing budget.
// Zero selects the hard maximum for that dimension.
type ImageIndexLimits struct{ Roots, Files, Entries, Depth, PathBytes int }
type ImageInode struct {
	Inode        uint64
	Major, Minor uint32
}

type lowerIndexLease struct {
	mu       sync.Mutex
	Inodes   []ImageInode
	Complete bool
	host     *os.File
	layers   []lowerLayer
	limits   ImageIndexLimits
	closed   bool
}
type lowerLayer struct {
	name     string
	file     *os.File
	identity inodeFingerprint
	digest   [32]byte
}
type inodeFingerprint struct {
	Dev, Ino, Rdev uint64
	Mode, UID, GID uint32
	Links          uint64
	Size           int64
	Mtime, Ctime   unix.Timespec
}

func fingerprint(s unix.Stat_t) inodeFingerprint {
	return inodeFingerprint{uint64(s.Dev), s.Ino, uint64(s.Rdev), s.Mode, s.Uid, s.Gid, uint64(s.Nlink), s.Size, s.Mtim, s.Ctim}
}
func normalizeIndexLimits(l ImageIndexLimits) (ImageIndexLimits, error) {
	values := []*int{&l.Roots, &l.Files, &l.Entries, &l.Depth, &l.PathBytes}
	for i, max := range []int{128, 65536, 262144, 128, 4096} {
		if *values[i] < 0 || *values[i] > max {
			return l, fmt.Errorf("invalid image index budget")
		}
		if *values[i] == 0 {
			*values[i] = max
		}
	}
	return l, nil
}
func indexOpen(parent int, name string, flags uint64, noCross bool) (*os.File, error) {
	resolve := uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS)
	if noCross {
		resolve |= unix.RESOLVE_NO_XDEV
	}
	fd, err := unix.Openat2(parent, name, &unix.OpenHow{Flags: flags | unix.O_CLOEXEC, Resolve: resolve})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func indexStat(file *os.File) (inodeFingerprint, error) {
	var s unix.Stat_t
	err := unix.Fstat(int(file.Fd()), &s)
	return fingerprint(s), err
}
func indexFS(file *os.File) error {
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &fs); err != nil {
		return err
	}
	switch fs.Type {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC:
		return nil
	}
	return fmt.Errorf("unsupported lower filesystem %#x (overlay/nested roots are not accepted)", fs.Type)
}

// buildLowerIndex does NOT establish that these paths are image layers. The
// caller must derive them from authenticated runtime snapshot metadata, match
// the live process root, and validate immutable lower ownership/mount semantics.
// Fingerprints detect ordinary churn, not a privileged host capable of mutating
// supposedly immutable layers or racing observation. A Complete result only
// means this bounded walk completed, not that those external guarantees hold.
func buildLowerIndex(ctx context.Context, hostRoot string, lowerDirs []string, limits ImageIndexLimits) (result *lowerIndexLease, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	limits, err = normalizeIndexLimits(limits)
	if err != nil {
		return nil, err
	}
	if !path.IsAbs(hostRoot) || path.Clean(hostRoot) != hostRoot || len(hostRoot) > 4096 {
		return nil, fmt.Errorf("invalid host root")
	}
	if len(lowerDirs) == 0 || len(lowerDirs) > limits.Roots {
		return nil, fmt.Errorf("invalid lower root count")
	}
	// The configured host root itself must not resolve through symlinks.
	fd, e := unix.Openat2(unix.AT_FDCWD, hostRoot, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS})
	if e != nil {
		return nil, e
	}
	lease := &lowerIndexLease{host: os.NewFile(uintptr(fd), hostRoot), limits: limits}
	defer func() {
		if err != nil {
			err = errors.Join(err, lease.Close())
		}
	}()
	seen := map[string]bool{}
	for _, name := range lowerDirs {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		if !path.IsAbs(name) || name == "/" || path.Clean(name) != name || len(name) > limits.PathBytes || seen[name] {
			return nil, fmt.Errorf("invalid or duplicate lower directory %q", name)
		}
		seen[name] = true
		file, e := indexOpen(int(lease.host.Fd()), strings.TrimPrefix(name, "/"), unix.O_RDONLY|unix.O_DIRECTORY, false)
		if e != nil {
			return nil, e
		}
		lease.layers = append(lease.layers, lowerLayer{name: name, file: file})
		if e = indexFS(file); e != nil {
			return nil, e
		}
		identity, e := indexStat(file)
		if e != nil {
			return nil, e
		}
		lease.layers[len(lease.layers)-1].identity = identity
	}
	keys, digests, e := lease.scan(ctx)
	if e != nil {
		return nil, e
	}
	for i := range lease.layers {
		lease.layers[i].digest = digests[i]
	}
	// A second bounded scan catches changes while another layer was being read.
	if e = lease.check(ctx); e != nil {
		return nil, e
	}
	lease.Inodes = keys
	lease.Complete = true
	return lease, nil
}

type indexWalker struct {
	ctx     context.Context
	limits  ImageIndexLimits
	entries int
	keys    map[ImageInode]struct{}
}

func (w *indexWalker) walk(dir *os.File, name string, depth int, h hash.Hash) (retErr error) {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if depth > w.limits.Depth || len(name) > w.limits.PathBytes {
		return fmt.Errorf("image index depth/path budget exceeded")
	}
	before, err := indexStat(dir)
	if err != nil {
		return err
	}
	// Reopen an independent directory description; never share readdir offsets.
	reader, err := indexOpen(int(dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY, true)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, reader.Close()) }()
	var names []string
	for {
		batch, e := reader.Readdirnames(128)
		for _, child := range batch {
			w.entries++
			if w.entries > w.limits.Entries {
				return fmt.Errorf("image index entry budget exceeded")
			}
			names = append(names, child)
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if e = w.ctx.Err(); e != nil {
			return e
		}
	}
	sort.Strings(names)
	fmt.Fprintf(h, "%q:%+v\n", name, before)
	for _, child := range names {
		if err = w.ctx.Err(); err != nil {
			return err
		}
		childName := path.Join(name, child)
		if len(childName) > w.limits.PathBytes {
			return fmt.Errorf("image index path budget exceeded")
		}
		// O_PATH|O_NOFOLLOW lets us inspect (but never follow) final symlinks.
		file, e := indexOpen(int(dir.Fd()), child, unix.O_PATH|unix.O_NOFOLLOW, true)
		if e != nil {
			return e
		}
		stat, e := indexStat(file)
		closeErr := file.Close()
		if e != nil || closeErr != nil {
			return errors.Join(e, closeErr)
		}
		fmt.Fprintf(h, "%q:%+v\n", childName, stat)
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			key := ImageInode{stat.Ino, unix.Major(stat.Dev), unix.Minor(stat.Dev)}
			w.keys[key] = struct{}{}
			if len(w.keys) > w.limits.Files {
				return fmt.Errorf("image index file budget exceeded")
			}
		case unix.S_IFDIR:
			sub, e := indexOpen(int(dir.Fd()), child, unix.O_RDONLY|unix.O_DIRECTORY, true)
			if e != nil {
				return e
			}
			current, e := indexStat(sub)
			if e == nil && current != stat {
				e = fmt.Errorf("lower directory changed before traversal")
			}
			if e == nil {
				e = w.walk(sub, childName, depth+1, h)
			}
			closeErr := sub.Close()
			if e != nil || closeErr != nil {
				return errors.Join(e, closeErr)
			}
			// Symlinks, devices, FIFOs and sockets are intentionally not image files.
		}
	}
	after, err := indexStat(dir)
	if err != nil {
		return err
	}
	if before != after {
		return fmt.Errorf("lower directory changed during traversal")
	}
	return nil
}
func (l *lowerIndexLease) scan(ctx context.Context) ([]ImageInode, [][32]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	// Revalidate the configured host-root path as well as the pinned layers.
	fd, err := unix.Openat2(unix.AT_FDCWD, l.host.Name(), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		return nil, nil, err
	}
	reopened := os.NewFile(uintptr(fd), l.host.Name())
	current, e := indexStat(reopened)
	pinned, pe := indexStat(l.host)
	ce := reopened.Close()
	if e != nil || pe != nil || ce != nil {
		return nil, nil, errors.Join(e, pe, ce)
	}
	if current.Dev != pinned.Dev || current.Ino != pinned.Ino {
		return nil, nil, fmt.Errorf("host root identity changed")
	}
	w := indexWalker{ctx: ctx, limits: l.limits, keys: map[ImageInode]struct{}{}}
	digests := make([][32]byte, len(l.layers))
	for i, layer := range l.layers {
		reopened, err := indexOpen(int(l.host.Fd()), strings.TrimPrefix(layer.name, "/"), unix.O_RDONLY|unix.O_DIRECTORY, false)
		if err != nil {
			return nil, nil, err
		}
		identity, e := indexStat(reopened)
		fsErr := indexFS(reopened)
		closeErr := reopened.Close()
		if e != nil || fsErr != nil || closeErr != nil {
			return nil, nil, errors.Join(e, fsErr, closeErr)
		}
		pinned, e := indexStat(layer.file)
		if e != nil {
			return nil, nil, e
		}
		if identity != layer.identity || pinned != layer.identity {
			return nil, nil, fmt.Errorf("lower root identity or fingerprint changed")
		}
		h := sha256.New()
		if e = w.walk(layer.file, layer.name, 0, h); e != nil {
			return nil, nil, e
		}
		copy(digests[i][:], h.Sum(nil))
	}
	keys := make([]ImageInode, 0, len(w.keys))
	for key := range w.keys {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.Major != b.Major {
			return a.Major < b.Major
		}
		if a.Minor != b.Minor {
			return a.Minor < b.Minor
		}
		return a.Inode < b.Inode
	})
	return keys, digests, nil
}
func (l *lowerIndexLease) check(ctx context.Context) error {
	if l.closed {
		return fmt.Errorf("lower index lease is closed")
	}
	_, digests, err := l.scan(ctx)
	if err != nil {
		return err
	}
	for i := range digests {
		if digests[i] != l.layers[i].digest {
			return fmt.Errorf("lower layer contents changed")
		}
	}
	return nil
}
func (l *lowerIndexLease) Check() error { return l.CheckContext(context.Background()) }
func (l *lowerIndexLease) CheckContext(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.check(ctx)
}
func (l *lowerIndexLease) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	l.Complete = false
	var errs []error
	for _, layer := range l.layers {
		errs = append(errs, layer.file.Close())
	}
	if l.host != nil {
		errs = append(errs, l.host.Close())
	}
	return errors.Join(errs...)
}
