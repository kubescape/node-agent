package igbackend

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	privruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/runtime"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// fakePins is the host bpffs: the set directories that exist.
type fakePins struct {
	dirs     map[string]bool
	pinErr   error
	removed  []string
	restored []string
	manifest enforcement.PinManifest
}

func (f *fakePins) remove(dir string) error {
	delete(f.dirs, dir)
	f.removed = append(f.removed, dir)
	return nil
}

func (f *fakePins) listUnder(root string) ([]string, error) {
	var out []string
	for d := range f.dirs {
		if strings.HasPrefix(d, root+"/") {
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out, nil
}

type fakePinnedInstance struct {
	*fakePrivilegeInstance
	pins *fakePins
	dir  string
}

func (i *fakePinnedInstance) Pin(_ context.Context, dir string, m enforcement.PinManifest) error {
	if i.pins.pinErr != nil {
		return i.pins.pinErr
	}
	if m.BootID != "boot" {
		return errors.New("no boot id")
	}
	i.pins.dirs[dir], i.dir, i.pins.manifest = true, dir, m
	return nil
}

// pinEngine starts instances on a restored state: seed fills the state a
// previous run left (published slots, adopted bindings).
type pinEngine struct {
	fakePrivilegeEngine
	pins      *fakePins
	instances []*fakePinnedInstance
	seed      func(*fakePrivilegeInstance)
}

func (e *pinEngine) Start(ctx context.Context, id string, c privruntime.Config) (PrivilegeInstance, error) {
	i, err := e.fakePrivilegeEngine.Start(ctx, id, c)
	if err != nil {
		return nil, err
	}
	p := &fakePinnedInstance{fakePrivilegeInstance: i.(*fakePrivilegeInstance), pins: e.pins}
	if e.seed != nil {
		e.seed(p.fakePrivilegeInstance)
		e.seed = nil // the next start runs on this instance's state
	}
	e.instances = append(e.instances, p)
	return p, nil
}

// newPinned enables restart survival over the given sets (nil reason: a
// valid set) and counts the resets of the section's state.
func newPinned(t *testing.T, existing map[string]error, restoreErr error, seed func(*fakePrivilegeInstance)) (*PrivilegeBackend, *pinEngine, *fakePins, *int) {
	t.Helper()
	pins := &fakePins{dirs: map[string]bool{}}
	var sets []enforcement.PinnedSet
	rejected := map[string]error{}
	for dir, reason := range existing {
		pins.dirs[dir] = true
		if reason == nil {
			sets = append(sets, enforcement.PinnedSet{Dir: dir, Manifest: enforcement.PinManifest{Generation: 3,
				Slots: []enforcement.PinnedSlot{{Slot: 5, Generation: 3, Digest: "d5", Policies: []enforcement.PinnedPolicy{{UID: "old", Namespace: "ns", Name: "old", Revision: "r0"}}}}}})
		} else {
			rejected[dir] = reason
		}
	}
	e := &pinEngine{pins: pins, seed: seed}
	b, err := NewPrivilege(e, nil, "n")
	if err != nil {
		t.Fatal(err)
	}
	resets := 0
	b.section.resetState = func() error { resets++; return nil }
	load := func(root, section string) ([]enforcement.PinnedSet, map[string]error, error) {
		if root != "/bpf/privilege" || section != "privilege" {
			t.Fatalf("load %s %s", root, section)
		}
		return sets, rejected, nil
	}
	restore := func(s enforcement.PinnedSet) error {
		pins.restored = append(pins.restored, s.Dir)
		return restoreErr
	}
	if err := b.enablePins("/bpf/privilege", "boot", load, restore, pins.remove, pins.listUnder); err != nil && restoreErr == nil {
		t.Fatal(err)
	}
	b.pins.update = func(dir string, fn func(*enforcement.PinManifest)) error {
		if !pins.dirs[dir] {
			return errors.New("no such set")
		}
		fn(&pins.manifest)
		return nil
	}
	return b, e, pins, &resets
}

// The previous run's state: slot 5 published, two kernel bindings no
// container of the new run took over, one Strict.
func previousRun(i *fakePrivilegeInstance) {
	i.published = map[uint32]any{5: nil}
	i.adopted = map[uint32]int{5: 2}
	i.strictSlots = map[uint32]bool{5: true}
}

func TestRestartRestoresTheStateAndRemovesOldLinks(t *testing.T) {
	b, e, pins, resets := newPinned(t, map[string]error{"/bpf/privilege/old": nil, "/bpf/privilege/bad": errors.New("tag")}, nil, previousRun)
	if pins.dirs["/bpf/privilege/bad"] || len(pins.restored) != 1 {
		t.Fatalf("an invalid set is removed and the valid one restored: %v %v", pins.dirs, pins.restored)
	}
	ctx := context.Background()
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("p1", api.ActionDeny, denyMount))); err != nil {
		t.Fatal(err)
	}
	i := e.instances[0]
	if *resets != 0 {
		t.Fatal("a restored state must not be reset")
	}
	if i.adopted[5] != 2 || i.freed[5] {
		t.Fatal("the adopted bindings and their slot stay until Settle")
	}
	if i.dir == "" || pins.dirs["/bpf/privilege/old"] {
		t.Fatalf("the new instance is pinned and the old links are removed: %v", pins.dirs)
	}
	if got := b.Adopted(); len(got) != 1 || got[0].Slot != 5 || got[0].Digest != "d5" || got[0].Bindings != 2 || got[0].Policies[0].Revision != "r0" {
		t.Fatalf("adopted %+v", got)
	}
	if err := b.Settle(ctx); err != nil {
		t.Fatal(err)
	}
	if len(i.adopted) != 0 || !i.freed[5] || len(b.Adopted()) != 0 || !b.pins.settled {
		t.Fatalf("settle drops the adopted bindings and frees their slot: %v %v", i.adopted, i.freed)
	}
}

func TestRestartDeadlineKeepsOnlyStrictAdopted(t *testing.T) {
	b, e, _, _ := newPinned(t, map[string]error{"/bpf/privilege/old": nil}, nil, func(i *fakePrivilegeInstance) {
		i.published = map[uint32]any{5: nil, 6: nil}
		i.adopted = map[uint32]int{5: 1, 6: 1}
		i.strictSlots = map[uint32]bool{5: true}
	})
	ctx := context.Background()
	if err := b.Prepare(ctx, nil); err != nil {
		t.Fatal(err)
	}
	i := e.instances[0]
	if len(i.adopted) != 2 {
		t.Fatal("before the deadline every adopted binding stays")
	}
	b.pins.start = time.Now().Add(-settleDeadline)
	if err := b.Prepare(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if i.adopted[5] != 1 || i.adopted[6] != 0 || !i.freed[6] || b.pins.settled {
		t.Fatalf("after the deadline only Strict adopted bindings stay: %v freed=%v", i.adopted, i.freed)
	}
}

func TestRestartFailedRestoreStartsFresh(t *testing.T) {
	b, e, pins, resets := newPinned(t, map[string]error{"/bpf/privilege/old": nil}, errors.New("incompatible"), nil)
	ctx := context.Background()
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("p1", api.ActionDeny, denyMount))); err != nil {
		t.Fatal(err)
	}
	if *resets != 1 {
		t.Fatal("without a restored state the first start resets the state")
	}
	if !pins.dirs["/bpf/privilege/old"] {
		t.Fatal("the old links keep their own state until Settle")
	}
	if err := b.Settle(ctx); err != nil {
		t.Fatal(err)
	}
	if pins.dirs["/bpf/privilege/old"] || e.instances[0].dir == "" {
		t.Fatalf("settle removes the old set: %v", pins.dirs)
	}
}

func TestRestartManifestDescribesSlotsAndCloseKeepsPins(t *testing.T) {
	b, e, pins, _ := newPinned(t, nil, nil, nil)
	ctx := context.Background()
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("p1", api.ActionDeny, denyMount))); err != nil {
		t.Fatal(err)
	}
	if m := pins.manifest; len(m.Slots) != 1 || m.Slots[0].Policies[0].Name != "p1" || m.Slots[0].Digest == "" {
		t.Fatalf("manifest %+v", m)
	}
	dir := e.instances[0].dir
	if err := b.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if !pins.dirs[dir] {
		t.Fatal("Close keeps the pinned set: the kernel enforces until the next start")
	}
}

func TestRestartRecoveryMovesThePin(t *testing.T) {
	b, e, pins, _ := newPinned(t, nil, nil, nil)
	ctx := context.Background()
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("p1", api.ActionDeny, denyMount))); err != nil {
		t.Fatal(err)
	}
	first := e.instances[0]
	first.readyErr = errors.New("not ready")
	if _, err := b.Withdraw(ctx, privBinding(1)); err != nil {
		t.Fatal(err)
	}
	if len(e.instances) != 2 || pins.dirs[first.dir] || !pins.dirs[e.instances[1].dir] {
		t.Fatalf("the new instance takes the pin: %v", pins.dirs)
	}
}
