//go:build linux

package integration

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	rf "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/restartfence"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"golang.org/x/sys/unix"
)

type exitProbeFake struct {
	gone    map[uint64]bool
	err     error
	checked []uint64
}

func (p *exitProbeFake) Gone(id uint64) (bool, error) {
	p.checked = append(p.checked, id)
	return p.gone[id], p.err
}
func (p *exitProbeFake) Close() error { return nil }

type gcKernelFake struct {
	runtimeFenceFake
	rows     map[uint64]rf.PodState
	orphans  map[uint64]bool
	removed  []uint64
	children []rf.ChildRef
	fail     error
}

func (f *gcKernelFake) Snapshot() (rf.Snapshot, error) {
	s := rf.Snapshot{LiveIncarnation: 1, PerCgroup: map[uint64]rf.Totals{}}
	for id := range f.rows {
		s.PerCgroup[id] = rf.Totals{}
	}
	for id := range f.orphans {
		s.PerCgroup[id] = rf.Totals{}
	}
	s.PerCgroup[0] = rf.Totals{}
	return s, nil
}
func (f *gcKernelFake) ReadPod(id uint64) (rf.PodState, bool, error) {
	r, ok := f.rows[id]
	return r, ok, nil
}
func (f *gcKernelFake) RemoveExited(p rf.PodRef) error {
	if f.fail != nil {
		return f.fail
	}
	if f.rows[p.ID].PodRef != p {
		return rf.ErrStalePod
	}
	delete(f.rows, p.ID)
	f.removed = append(f.removed, p.ID)
	return nil
}
func (f *gcKernelFake) RemoveExitedOrphanCounters(id uint64) error {
	if _, exists := f.rows[id]; exists {
		return rf.ErrStalePod
	}
	if f.fail != nil {
		return f.fail
	}
	delete(f.orphans, id)
	return nil
}
func (f *gcKernelFake) RemoveExitedChild(p rf.PodRef, c rf.ChildRef) (rf.PodRef, error) {
	if f.fail != nil {
		return rf.PodRef{}, f.fail
	}
	r := f.rows[p.ID]
	if r.PodRef != p {
		return rf.PodRef{}, rf.ErrStalePod
	}
	for i, v := range r.Children {
		if v.ChildRef == c {
			r.Children = append(r.Children[:i:i], r.Children[i+1:]...)
			r.Revision++
			f.rows[p.ID] = r
			f.children = append(f.children, c)
			return r.PodRef, nil
		}
	}
	return rf.PodRef{}, rf.ErrStalePod
}
func gcFixture() (*ExecFenceManager, *gcKernelFake, *exitProbeFake) {
	m, _, _ := testFenceManager()
	f := &gcKernelFake{rows: map[uint64]rf.PodState{}}
	p := &exitProbeFake{gone: map[uint64]bool{}}
	m.kernel = f
	m.exitProbe = func() (fenceExitProbe, error) { return p, nil }
	return m, f, p
}
func gcRow(id uint64, children ...uint64) rf.PodState {
	r := rf.PodState{PodRef: rf.PodRef{ID: id, UIDHash: 100 + id, Revision: 1}, Fallback: rf.Strict}
	for _, c := range children {
		r.Children = append(r.Children, rf.ChildState{ChildRef: rf.ChildRef{ID: c, Identity: c + 1000}, Mode: rf.Audit})
	}
	return r
}
func TestExecFenceGCReclaimsRestartRowsAndChainsReceipts(t *testing.T) {
	m, f, p := gcFixture()
	f.rows[10] = gcRow(10, 11, 12, 13)
	f.rows[20] = gcRow(20, 21)
	p.gone[11] = true
	p.gone[12] = true
	p.gone[20] = true
	m.reclaimExited(nil)
	if len(f.removed) != 1 || f.removed[0] != 20 || len(f.children) != 2 || len(f.rows[10].Children) != 1 || f.rows[10].Revision != 3 {
		t.Fatalf("wrong GC: %+v", f)
	}
	if m.ReclamationError() != nil {
		t.Fatal(m.ReclamationError())
	}
}
func TestExecFenceGCCurrentCensusNeverRemoved(t *testing.T) {
	m, f, p := gcFixture()
	f.rows[10] = gcRow(10, 11)
	p.gone[10] = true
	p.gone[11] = true
	m.reclaimExited(map[uint64][]preparedFenceChild{10: {{cgroups: &FenceCgroups{PodID: 10, ContainerID: 11}}}})
	if len(p.checked) != 0 || len(f.removed) != 0 || len(f.children) != 0 {
		t.Fatal("current pinned census probed or removed")
	}
}
func TestExecFenceGCDegradedNeverRemoves(t *testing.T) {
	for _, err := range []error{unix.EPERM, unix.EINVAL, unix.ENOENT, unix.EOPNOTSUPP, fmt.Errorf("uncertain")} {
		t.Run(err.Error(), func(t *testing.T) {
			m, f, p := gcFixture()
			f.rows[10] = gcRow(10, 11)
			p.gone[10] = true
			p.err = err
			m.reclaimExited(nil)
			if len(f.rows) != 1 || len(f.children) != 0 || !errors.Is(m.ReclamationError(), err) {
				t.Fatal("degraded probe authorized removal")
			}
		})
	}
	m, f, _ := gcFixture()
	f.rows[10] = gcRow(10)
	m.exitProbe = func() (fenceExitProbe, error) { return nil, unix.ESTALE }
	m.reclaimExited(nil)
	if len(f.rows) != 1 || !errors.Is(m.ReclamationError(), unix.ESTALE) {
		t.Fatal("failed calibration authorized removal")
	}
}

func TestFenceRootMountViewAfterExactHandle(t *testing.T) {
	const mount = "687 32 0:28 %s /host/sys/fs/cgroup rw master:8 - cgroup2 cgroup rw"
	for _, root := range []string{"/", "/..", "/../..", "/../../.."} {
		if err := validateFenceRootMountView([]byte(fmt.Sprintf(mount, root)), 687); err != nil {
			t.Fatalf("verified root view %s refused: %v", root, err)
		}
	}
	for _, wrong := range []string{
		fmt.Sprintf(mount, "/some-subtree"),
		fmt.Sprintf(mount, "/../../subtree"),
		fmt.Sprintf(mount, "/..."),
		fmt.Sprintf(mount, "/../"),
		"687 32 0:29 / /host/sys/fs/cgroup rw - tmpfs tmpfs rw",
		"687 32 0:28 / /host/sys/fs/cgroup rw",
		fmt.Sprintf(mount, "/") + "\n" + fmt.Sprintf(mount, "/../.."),
		"88 31 0:28 / /host/sys/fs/cgroup rw - cgroup2 cgroup rw",
	} {
		if err := validateFenceRootMountView([]byte(wrong), 687); err == nil {
			t.Fatalf("ambiguous or non-root mount view accepted: %s", wrong)
		}
	}
}
func TestExecFenceGCStaleMutationRetainsRow(t *testing.T) {
	m, f, p := gcFixture()
	f.rows[10] = gcRow(10, 11)
	p.gone[11] = true
	f.fail = rf.ErrStalePod
	m.reclaimExited(nil)
	if len(f.rows[10].Children) != 1 || !errors.Is(m.ReclamationError(), rf.ErrStalePod) {
		t.Fatal("stale receipt accepted")
	}
}
func TestExecFenceGCReclaimsOnlyProvenExitedOrphanCounters(t *testing.T) {
	m, f, p := gcFixture()
	f.orphans = map[uint64]bool{11: true, 12: true, 13: true}
	p.gone[11], p.gone[13] = true, true
	current := map[uint64][]preparedFenceChild{13: {{cgroups: &FenceCgroups{PodID: 13}}}}
	m.reclaimExited(current)
	if f.orphans[11] || !f.orphans[12] || !f.orphans[13] || m.ReclamationError() != nil {
		t.Fatalf("unsafe counter-only reclamation: %v err=%v", f.orphans, m.ReclamationError())
	}
	p.gone[12] = true
	f.fail = rf.ErrStalePod
	m.reclaimExited(current)
	if !f.orphans[12] || !errors.Is(m.ReclamationError(), rf.ErrStalePod) {
		t.Fatalf("stale orphan receipt did not retain counters: %v err=%v", f.orphans, m.ReclamationError())
	}
}
func TestExecFenceGCBoundedPodChurnEventuallyReclaimed(t *testing.T) {
	m, f, p := gcFixture()
	for i := uint64(1); i <= 100; i++ {
		f.rows[i] = gcRow(i)
		p.gone[i] = true
	}
	m.reclaimExited(nil)
	if len(f.removed) != 32 {
		t.Fatalf("unbounded scan %d", len(f.removed))
	}
	for i := 0; i < 4; i++ {
		m.reclaimExited(nil)
	}
	if len(f.rows) != 0 {
		t.Fatal("rotation starved pod rows")
	}
}
func TestExecFenceGCNativeCleanupRequiresFreshExactProof(t *testing.T) {
	m, f, p := gcFixture()
	b := sandboxpolicy.Binding{PodUID: "p", ContainerID: "c", CgroupID: 11}
	key := fenceBindingID(b)
	m.native = map[uint64]*nativeFenceReceipt{key: {pod: 10, child: rf.ChildRef{ID: 111, Identity: key}}}
	p.gone[111] = true
	if err := m.BeforeNativeChange(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	p.err = unix.EPERM
	f.err = rf.ErrStalePod
	if err := m.BeforeNativeChange(context.Background(), b); err == nil {
		t.Fatal("old exit proof replayed")
	}
	if len(p.checked) != 2 || p.checked[0] != 111 {
		t.Fatal("truncated inode used")
	}
}
func TestExecFenceGCRejectsNonCgroupRoot(t *testing.T) {
	if p, err := openFenceExitProbe(t.TempDir()); err == nil {
		p.Close()
		t.Fatal("accepted non-cgroup mount")
	}
}

func TestExecFenceGCRootHandleRejectsNamespaceSubtree(t *testing.T) {
	for _, tc := range []struct {
		name  string
		arch  string
		kind  int32
		id    uint64
		size  int
		valid bool
	}{
		{"whole", "amd64", 0xfe, 1, 8, true},
		{"subtree", "amd64", 0xfe, 2, 8, false},
		{"generation-not-root", "amd64", 0xfe, 0x100000001, 8, false},
		{"wrong-type", "amd64", 1, 1, 8, false},
		{"short", "amd64", 0xfe, 1, 4, false},
		{"unqualified-arch", "arm64", 0xfe, 1, 8, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := make([]byte, 8)
			binary.NativeEndian.PutUint64(b, tc.id)
			err := validateFenceRootHandle(unix.NewFileHandle(tc.kind, b[:tc.size]), tc.arch)
			if (err == nil) != tc.valid {
				t.Fatalf("validation %v", err)
			}
		})
	}
}
