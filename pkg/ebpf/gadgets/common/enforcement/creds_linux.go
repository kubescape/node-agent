// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// The credential record of ../creds.h.
const (
	credsMap        = "creds"
	credCountsMap   = "cred_counts"
	credInstanceMap = "cred_instance"
	// CredRecordMax is CRED_RECORD_MAX: the entries of the record.
	CredRecordMax = 524288
	// credFillLimit is the fill level, in percent of CredRecordMax, from
	// which CredRecordHealth fails.
	credFillLimit = 90
	// credProbe is CRED_PROBE: with a probe's thread ID, its counter key.
	credProbe = uint64(1) << 63
	// initPIDNamespace is the inode of the initial PID namespace
	// (include/linux/proc_ns.h).
	initPIDNamespace = 0xEFFFFFFC
	// probeTimeout bounds the wait for the probe's credentials to be freed
	// (an RCU grace period).
	probeTimeout = 5 * time.Second
)

// enum cred_result.
const (
	credOK = iota
	credFull
	credOverQuota
	credGone
)

// credWalkArgs is struct cred_walk_args.
type credWalkArgs struct {
	Tid, Flags, Slot, Pad uint32
	Cgroup, TaskCgroup    uint64
}

type credRecord struct {
	walk                    *ebpf.Program
	creds, counts, instance *ebpf.Map
	// free is the name of the section's cred_free program.
	free string
}

// credRecordFrom reads the record's program and maps from a running instance.
func credRecordFrom(gc operators.GadgetContext, config Config) (*credRecord, error) {
	value, _ := gc.GetVar(operators.ProgramPrefix + config.CredWalk)
	walk, ok := value.(*ebpf.Program)
	if !ok || walk == nil {
		return nil, fmt.Errorf("missing credential walk program %s", config.CredWalk)
	}
	getMap := func(name string) (*ebpf.Map, error) {
		value, _ := gc.GetVar(operators.MapPrefix + name)
		m, ok := value.(*ebpf.Map)
		if !ok || m == nil {
			return nil, fmt.Errorf("missing BPF map %s", name)
		}
		return m, nil
	}
	r := &credRecord{walk: walk, free: config.CredFree}
	var err error
	if r.creds, err = getMap(config.MapPrefix + credsMap); err != nil {
		return nil, err
	}
	if r.counts, err = getMap(config.MapPrefix + credCountsMap); err != nil {
		return nil, err
	}
	if r.instance, err = getMap(credInstanceMap); err != nil {
		return nil, err
	}
	if r.creds.Type() != ebpf.Hash || r.creds.KeySize() != 8 || r.creds.ValueSize() != 8 || r.creds.MaxEntries() != CredRecordMax ||
		r.counts.Type() != ebpf.Hash || r.counts.KeySize() != 8 || r.counts.ValueSize() != 8 ||
		r.instance.Type() != ebpf.Array || r.instance.ValueSize() != 4 {
		return nil, fmt.Errorf("invalid credential record layout")
	}
	return r, nil
}

// count reads one counter of the record (0 when it does not exist).
func (r *credRecord) count(key uint64) (uint64, error) {
	var n uint64
	if err := r.counts.Lookup(key, &n); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return 0, fmt.Errorf("reading credential record counter: %w", err)
	}
	return n, nil
}

// prepare runs at start, before any bind. The walk and the probe give the
// kernel thread IDs of this PID namespace, and the programs compare them with
// the initial namespace's: the owner must run in the initial PID namespace
// (hostPID). When no other instance's cred_free runs, the pinned record may
// hold freed addresses (an uninstall that kept the pins, a start after the
// links dropped): it is purged (purged is true), and the caller records the
// adopted bindings again; each bind records its tasks. Then the probe checks
// that a freed credential leaves the record.
func (r *credRecord) prepare() (purged bool, err error) {
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &st); err != nil {
		return false, fmt.Errorf("credential record: reading the PID namespace: %w", err)
	}
	if st.Ino != initPIDNamespace {
		return false, fmt.Errorf("credential record: the owner must run in the initial PID namespace (hostPID)")
	}
	others, err := r.otherInstances()
	if err != nil {
		return false, err
	}
	if !others {
		if err := r.purge(); err != nil {
			return false, err
		}
	}
	return !others, r.probe()
}

// otherInstances reports whether a live link runs another instance's
// cred_free on this record: a program with the section's cred_free name that
// uses the record but not this instance's cred_instance map.
func (r *credRecord) otherInstances() (bool, error) {
	credsID, err := credMapID(r.creds)
	if err != nil {
		return false, err
	}
	instanceID, err := credMapID(r.instance)
	if err != nil {
		return false, err
	}
	// The kernel keeps 15 characters of a program name; the library gives
	// the full name when the program has BTF.
	short := r.free
	if len(short) > unix.BPF_OBJ_NAME_LEN-1 {
		short = short[:unix.BPF_OBJ_NAME_LEN-1]
	}
	for attempt := 0; ; attempt++ {
		found, err := walkLinks(func(pi *ebpf.ProgramInfo) bool {
			ids, _ := pi.MapIDs()
			return (pi.Name == r.free || pi.Name == short) && slices.Contains(ids, credsID) && !slices.Contains(ids, instanceID)
		})
		// A link being created or freed answers EAGAIN and stops the walk.
		if err == nil || !errors.Is(err, unix.EAGAIN) || attempt == 20 {
			return found, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func walkLinks(match func(*ebpf.ProgramInfo) bool) (bool, error) {
	var it link.Iterator
	defer it.Close()
	for it.Next() {
		info, err := it.Link.Info()
		if err != nil {
			continue // detached meanwhile
		}
		prog, err := ebpf.NewProgramFromID(info.Program)
		if err != nil {
			continue
		}
		pi, err := prog.Info()
		_ = prog.Close()
		if err == nil && match(pi) {
			return true, nil
		}
	}
	return false, it.Err()
}

func credMapID(m *ebpf.Map) (ebpf.MapID, error) {
	info, err := m.Info()
	if err != nil {
		return 0, err
	}
	id, ok := info.ID()
	if !ok {
		return 0, fmt.Errorf("map id unavailable")
	}
	return id, nil
}

// purge deletes every entry and counter of the record.
func (r *credRecord) purge() error {
	for _, m := range []*ebpf.Map{r.creds, r.counts} {
		var (
			key  uint64
			keys []uint64
		)
		value := make([]byte, m.ValueSize())
		it := m.Iterate()
		for it.Next(&key, &value) {
			keys = append(keys, key)
		}
		if err := it.Err(); err != nil {
			return fmt.Errorf("listing the credential record: %w", err)
		}
		for _, k := range keys {
			if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("purging the credential record: %w", err)
			}
		}
	}
	return nil
}

// probe checks that the record works: a thread of the owner, marked as the
// probe in cred_instance, commits new credentials twice (capset with the same
// capabilities). Both enter the record under the probe's own counter; the
// first is freed by the second commit and must leave it. It leaves only when
// cred_free runs, which needs an LSM with a cred blob (security_cred_free
// returns early otherwise): without one, the record only grows, so the
// instance refuses to start. The second stays the thread's credentials, so the
// thread is not made to exit (Go never ends its main thread); the probe's
// counter is deleted at the end.
func (r *credRecord) probe() error {
	type result struct {
		key uint64
		err error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		key := credProbe | uint64(unix.Gettid())
		done <- result{key, r.probeThread(key)}
	}()
	res := <-done
	defer r.counts.Delete(res.key)
	if res.err != nil {
		return res.err
	}
	deadline := time.Now().Add(probeTimeout)
	for {
		n, err := r.count(res.key)
		if err != nil {
			return err
		}
		if n <= 1 {
			return nil
		}
		if time.Now().After(deadline) {
			lsm, _ := os.ReadFile("/sys/kernel/security/lsm")
			return fmt.Errorf("freed credentials stay in the credential record (cred_free does not run; it needs an LSM with a cred blob, active LSMs: %q)", string(lsm))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (r *credRecord) probeThread(key uint64) error {
	_ = r.counts.Delete(key) // a counter left by an earlier probe of this thread
	if err := r.instance.Put(uint32(0), uint32(key)); err != nil {
		return fmt.Errorf("marking the credential probe: %w", err)
	}
	defer r.instance.Put(uint32(0), uint32(0))
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return fmt.Errorf("credential probe: %w", err)
	}
	for i := 0; i < 2; i++ {
		if err := unix.Capset(&header, &data[0]); err != nil {
			return fmt.Errorf("credential probe: %w", err)
		}
	}
	n, err := r.count(key)
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("prepared credentials do not enter the credential record")
	}
	return nil
}

// fill sums the counters of the bindings (not the probe's).
func (r *credRecord) fill() (uint64, error) {
	var key, n, sum uint64
	it := r.counts.Iterate()
	for it.Next(&key, &n) {
		if key&credProbe == 0 {
			sum += n
		}
	}
	if err := it.Err(); err != nil {
		return 0, fmt.Errorf("reading the credential record counters: %w", err)
	}
	return sum, nil
}

// record records the credentials of every task of a binding: the tasks of the
// cgroup.threads files of its cgroup and child cgroups, except tasks in the
// runtime's mount namespace (as ArmExisting). A record over the binding's
// quota or into a full record counts a slot fault (Strict) or an unevaluated
// judgement (Audit) in the program; it is not an error here.
func (r *credRecord) record(cgroupID uint64, cgroupPath string, flags, slot uint32) error {
	hostMntns, err := mntnsOf("1")
	if err != nil {
		return err
	}
	root := filepath.Join(host.HostRoot, "sys/fs/cgroup", cgroupPath)
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == root && errors.Is(err, fs.ErrNotExist) {
				return ErrContainerGone
			}
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return fmt.Errorf("listing container tasks: %w", err)
		}
		if !d.IsDir() {
			return nil
		}
		var st unix.Stat_t
		if err := unix.Stat(path, &st); err != nil {
			if errors.Is(err, unix.ENOENT) {
				return nil
			}
			return fmt.Errorf("reading cgroup %s: %w", path, err)
		}
		f, err := os.Open(filepath.Join(path, "cgroup.threads"))
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("listing container tasks: %w", err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			tid, err := strconv.Atoi(scanner.Text())
			if err != nil {
				continue
			}
			if mntns, err := mntnsOf(scanner.Text()); err != nil || mntns == hostMntns {
				continue // exited, or a runtime helper
			}
			args := credWalkArgs{Tid: uint32(tid), Flags: flags, Slot: slot, Cgroup: cgroupID, TaskCgroup: st.Ino}
			if _, err := r.walk.Run(&ebpf.RunOptions{Context: &args}); err != nil {
				return fmt.Errorf("recording the credentials of task %d: %w", tid, err)
			}
		}
		return scanner.Err()
	})
}

// forget deletes the counter of an unbound binding cgroup.
func (r *credRecord) forget(cgroupID uint64) error {
	if err := r.counts.Delete(cgroupID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("removing the credential counter: %w", err)
	}
	return nil
}

// CredRecordFill returns the entries in the credential record and its size.
// Zero when the section keeps no record.
func (b *Bindings) CredRecordFill() (used, size uint64, err error) {
	b.mu.Lock()
	r := b.creds
	b.mu.Unlock()
	if r == nil {
		return 0, 0, nil
	}
	used, err = r.fill()
	return used, CredRecordMax, err
}

// CredRecordHealth fails when the credential record is at least 90% full:
// then a Strict binding may soon be refused new credentials (ENOMEM).
func (b *Bindings) CredRecordHealth() error {
	used, size, err := b.CredRecordFill()
	if err != nil {
		return err
	}
	if size > 0 && used*100 >= size*credFillLimit {
		return fmt.Errorf("credential record is %d%% full (%d of %d)", used*100/size, used, size)
	}
	return nil
}

// recordAdopted records the tasks of the adopted bindings again after a
// purge: an adopted binding has no cgroup path, so one walk of the cgroup
// tree finds them by ID. Called with b.mu held.
func (b *Bindings) recordAdopted() error {
	if len(b.adopted) == 0 {
		return nil
	}
	root := filepath.Join(host.HostRoot, "sys/fs/cgroup")
	paths := map[uint64]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil // a cgroup removed during the walk
		}
		var st unix.Stat_t
		if unix.Stat(path, &st) == nil {
			if _, ok := b.adopted[st.Ino]; ok {
				paths[st.Ino] = "/" + strings.TrimPrefix(strings.TrimPrefix(path, root), "/")
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("finding the adopted bindings' cgroups: %w", err)
	}
	var errs []error
	for id, v := range b.adopted {
		path, ok := paths[id]
		if !ok {
			continue // the cgroup is gone
		}
		if err := b.creds.record(id, path, v.Flags, v.Slot); err != nil && !errors.Is(err, ErrContainerGone) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
