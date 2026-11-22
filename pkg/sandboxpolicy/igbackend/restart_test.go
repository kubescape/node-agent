package igbackend

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	privruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// fakePins is the host bpffs: the set directories that exist.
type fakePins struct {
	dirs   map[string]bool
	pinErr error
	// linkErr is what the link check of an old set returns; removeErr
	// fails the removal of a set.
	linkErr, removeErr error
	removed            []string
	restored           []string
	manifest           enforcement.PinManifest
	// bindings are the old sets' pinned bindings read at start (eviction);
	// deleted records the cgroups removed from an old set's binding map.
	bindings map[string]map[uint64]enforcement.PinnedBinding
	deleted  map[string][]uint64
}

func (f *fakePins) remove(dir string) error {
	if f.removeErr != nil {
		return f.removeErr
	}
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
	return newPinnedBindings(t, existing, nil, restoreErr, seed)
}

// newPinnedBindings is newPinned with the old sets' pinned bindings (read at
// start for the eviction, and by the deadline decisions).
func newPinnedBindings(t *testing.T, existing map[string]error, bindings map[string]map[uint64]enforcement.PinnedBinding, restoreErr error, seed func(*fakePrivilegeInstance)) (*PrivilegeBackend, *pinEngine, *fakePins, *int) {
	t.Helper()
	pins := &fakePins{dirs: map[string]bool{}, bindings: map[string]map[uint64]enforcement.PinnedBinding{}, deleted: map[string][]uint64{}}
	for dir, bs := range bindings {
		pins.bindings[dir] = bs
	}
	oldRead := readPinnedBindings
	readPinnedBindings = func(set enforcement.PinnedSet) (map[uint64]enforcement.PinnedBinding, error) {
		if bs, ok := pins.bindings[set.Dir]; ok {
			return bs, nil
		}
		return nil, errors.New("no pinned bindings")
	}
	t.Cleanup(func() { readPinnedBindings = oldRead })
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
	b.pins.checkLinks = func(enforcement.PinnedSet) error { return pins.linkErr }
	b.pins.missing = func(dir string) bool { return !pins.dirs[dir] }
	b.pins.deleteBinding = func(set enforcement.PinnedSet, cgroup uint64) error {
		pins.deleted[set.Dir] = append(pins.deleted[set.Dir], cgroup)
		delete(pins.bindings[set.Dir], cgroup)
		return nil
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
	b, e, pins, resets := newPinned(t, map[string]error{"/bpf/privilege/old": nil,
		"/bpf/privilege/bad": fmt.Errorf("%w: tag", enforcement.ErrPinnedSetInvalid), "/bpf/privilege/io": errors.New("EIO")}, nil, previousRun)
	if pins.dirs["/bpf/privilege/bad"] || len(pins.restored) != 1 {
		t.Fatalf("an invalid set is removed and the valid one restored: %v %v", pins.dirs, pins.restored)
	}
	// Review 8, S3: a set that could not be read is kept (not restored)
	// until Settle.
	if !pins.dirs["/bpf/privilege/io"] {
		t.Fatalf("a set with an I/O error must be kept: %v", pins.dirs)
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
	// The kept unreadable set is reported apart (Unreadable), sorted first.
	if got := b.Adopted(); len(got) != 2 || !got[0].Unreadable || got[0].LinkError == nil || got[1].Slot != 5 || got[1].Digest != "d5" || got[1].Bindings != 2 || got[1].Policies[0].Revision != "r0" || got[1].LinkError != nil {
		t.Fatalf("adopted %+v", got)
	}
	if err := b.Settle(ctx); err != nil {
		t.Fatal(err)
	}
	if len(i.adopted) != 0 || !i.freed[5] || len(b.Adopted()) != 0 || !b.pins.settled {
		t.Fatalf("settle drops the adopted bindings and frees their slot: %v %v", i.adopted, i.freed)
	}
}

// Review 9, S-a: over the cap, only an old set whose cgroups a newer set
// binds goes; an uncovered one stays (a new attach may then be refused for
// capacity, fail closed). Unreadable sets count against the cap but never
// make the newest readable set go.
func TestRestartEvictionOnlyRemovesCoveredSets(t *testing.T) {
	existing := map[string]error{"/bpf/privilege/a": nil, "/bpf/privilege/b": nil, "/bpf/privilege/c": nil}
	for i := 0; i < maxOldSets; i++ {
		existing[fmt.Sprintf("/bpf/privilege/io%d", i)] = errors.New("EIO")
	}
	bindings := map[string]map[uint64]enforcement.PinnedBinding{
		"/bpf/privilege/a": {7: {Slot: 5, Strict: true}},                             // covered by c
		"/bpf/privilege/b": {8: {Slot: 5, Strict: true}},                             // only b binds 8
		"/bpf/privilege/c": {7: {Slot: 5, Strict: true}, 9: {Slot: 5, Strict: true}}, // the newest
	}
	b, _, pins, _ := newPinnedBindings(t, existing, bindings, nil, previousRun)
	if pins.dirs["/bpf/privilege/a"] || !pins.dirs["/bpf/privilege/b"] || !pins.dirs["/bpf/privilege/c"] {
		t.Fatalf("only the covered set goes; the uncovered and the newest stay: %v", pins.dirs)
	}
	if len(pins.restored) != 1 || pins.restored[0] != "/bpf/privilege/c" || !b.pins.restored {
		t.Fatalf("the newest set is restored: %v", pins.restored)
	}
	if len(b.pins.evicted) != 1 || b.pins.evicted[0] != "a" {
		t.Fatalf("evicted %v", b.pins.evicted)
	}
}

// Review 9, blocking: an old set that was not restored loses each covered
// cgroup on its own. An Audit cgroup goes at once while a Strict cgroup whose
// bind keeps failing stays: the set keeps judging only that one.
func TestRestartOldSetLosesCoveredCgroupsOneByOne(t *testing.T) {
	defer func(d time.Duration) { settleDeadline = d }(settleDeadline)
	settleDeadline = time.Hour // before the deadline: Audit and committed go at once
	bindings := map[string]map[uint64]enforcement.PinnedBinding{
		"/bpf/privilege/old": {1: {Slot: 5, Strict: true}, 2: {Slot: 5, Strict: true}, 3: {Slot: 5, Strict: true}},
	}
	b, _, pins, _ := newPinnedBindings(t, map[string]error{"/bpf/privilege/old": nil}, bindings, errors.New("incompatible"), func(i *fakePrivilegeInstance) {
		i.bindErr = map[uint64]error{2: errors.New("bind"), 3: errors.New("bind")}
	})
	ctx := context.Background()
	strict := privPlan("r1", privPolicy("p1", api.ActionDeny, denyMount))
	auditPolicy := privPolicy("p2", api.ActionDeny)
	auditPolicy.Mode = api.ModeAudit
	_, _ = b.Replace(ctx, privBinding(1), strict) // commits
	_, _ = b.Replace(ctx, privBinding(2), privPlan("r2", auditPolicy))
	_, _ = b.Replace(ctx, privBinding(3), strict)
	if err := b.PoliciesListed(map[string]bool{"old": true, "p1": true, "p2": true}); err != nil {
		t.Fatal(err)
	}
	got := map[uint64]bool{}
	for _, c := range pins.deleted["/bpf/privilege/old"] {
		got[c] = true
	}
	if !got[1] || !got[2] || got[3] {
		t.Fatalf("cgroups 1 (committed) and 2 (Audit) leave the old set, 3 (Strict, bind failing) stays: %v", pins.deleted)
	}
	if !pins.dirs["/bpf/privilege/old"] {
		t.Fatal("the old set stays while it judges cgroup 3")
	}
}

// Review 9, S-b: past the deadline, a binding whose policies are all gone
// from a complete policy listing goes without a complete binding snapshot
// (another policy of the node may keep the node from converging). A listing
// that still names the policy keeps it.
func TestRestartDropsBindingsOfPoliciesGoneFromTheListing(t *testing.T) {
	defer func(d time.Duration) { settleDeadline = d }(settleDeadline)
	settleDeadline = 0
	bindings := map[string]map[uint64]enforcement.PinnedBinding{"/bpf/privilege/old": {4: {Slot: 5, Strict: true}}}
	b, _, pins, _ := newPinnedBindings(t, map[string]error{"/bpf/privilege/old": nil}, bindings, errors.New("incompatible"), nil)
	if err := b.PoliciesListed(map[string]bool{"old": true}); err != nil {
		t.Fatal(err)
	}
	if !pins.dirs["/bpf/privilege/old"] || len(pins.deleted) != 0 {
		t.Fatalf("a listed policy keeps its binding: %v", pins.deleted)
	}
	if err := b.PoliciesListed(map[string]bool{"other": true}); err != nil {
		t.Fatal(err)
	}
	if pins.dirs["/bpf/privilege/old"] || len(b.Adopted()) != 0 {
		t.Fatalf("the policy is gone: the binding and then the set go: %v %+v", pins.dirs, b.Adopted())
	}
}

// Review 9, S-b, restored path with no instance: the section has no plan left
// and every adopted policy is gone from the listing; it settles at the
// deadline without a converged refresh.
func TestRestartSectionWithoutPlanSettlesFromTheListing(t *testing.T) {
	defer func(d time.Duration) { settleDeadline = d }(settleDeadline)
	settleDeadline = 0
	b, _, pins, resets := newPinned(t, map[string]error{"/bpf/privilege/old": nil}, nil, previousRun)
	if err := b.PoliciesListed(map[string]bool{"old": true}); err != nil || !pins.dirs["/bpf/privilege/old"] {
		t.Fatalf("a listed policy keeps the set: %v %v", pins.dirs, err)
	}
	if err := b.PoliciesListed(map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if pins.dirs["/bpf/privilege/old"] || *resets != 1 || !b.pins.settled {
		t.Fatalf("every adopted policy is gone: settled, reset: %v %d", pins.dirs, *resets)
	}
}

// Review 9, open question: a gadget that keeps failing to start on the
// restored state gives the state up after maxRestoredStartFailures; the next
// start resets it, and the old set keeps its links (fail closed).
func TestRestartGivesUpAStateTheGadgetCannotStartOn(t *testing.T) {
	b, e, pins, resets := newPinned(t, map[string]error{"/bpf/privilege/old": nil}, nil, previousRun)
	e.startErr = errors.New("verifier rejects the program")
	ctx := context.Background()
	for n := 1; n <= maxRestoredStartFailures; n++ {
		if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("p1", api.ActionDeny, denyMount))); err == nil {
			t.Fatal("the start must fail")
		}
		if *resets != 0 {
			t.Fatalf("start %d: the restored state must not be reset", n)
		}
		if want := n < maxRestoredStartFailures; b.pins.restored != want {
			t.Fatalf("start %d: restored %v, want %v", n, b.pins.restored, want)
		}
	}
	e.startErr = nil
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("p1", api.ActionDeny, denyMount))); err != nil {
		t.Fatal(err)
	}
	if *resets != 1 || !pins.dirs["/bpf/privilege/old"] {
		t.Fatalf("a fresh start resets the state and keeps the old set: resets %d, %v", *resets, pins.dirs)
	}
}

// Review 9, minor 2: a set removed by another node-agent (an old pod's
// uninstall decision after a DaemonSet rename) turns RestartSurvival off.
func TestRestartStatusSeesARemovedSet(t *testing.T) {
	b, e, pins, _ := newPinned(t, nil, nil, nil)
	if _, err := b.Replace(context.Background(), privBinding(1), privPlan("r1", privPolicy("p1", api.ActionDeny, denyMount))); err != nil {
		t.Fatal(err)
	}
	if st, ok := b.RestartStatus(); !ok || !st.Pinned || st.Err != nil {
		t.Fatalf("pinned: %+v", st)
	}
	delete(pins.dirs, e.instances[0].dir)
	if st, ok := b.RestartStatus(); !ok || st.Pinned || st.Err == nil || !strings.Contains(st.Err.Error(), "removed from the host bpffs") {
		t.Fatalf("removed: %+v", st)
	}
}

// After the settle deadline each adopted binding is decided from the current
// plan of its cgroup: dropped when the plan is now Audit; kept when it is
// Strict, or not known yet (no Replace seen, for example while the binding
// snapshot fails): fail closed; the section then reports itself degraded.
func TestRestartDeadlineDecidesByCurrentPlan(t *testing.T) {
	b, e, _, _ := newPinned(t, map[string]error{"/bpf/privilege/old": nil}, nil, func(i *fakePrivilegeInstance) {
		i.published = map[uint32]any{5: nil, 6: nil}
		// cgroup 1: now Strict; 2: Strict before, Audit now; 3: no plan seen.
		i.adoptedCgroups = map[uint64]uint32{1: 5, 2: 5, 3: 6}
		i.strictSlots = map[uint32]bool{5: true, 6: true}
		// The binds of 1 and 2 fail, so their adopted bindings stay.
		i.bindErr = map[uint64]error{1: errors.New("bind"), 2: errors.New("bind")}
	})
	ctx := context.Background()
	audit := privPolicy("p2", api.ActionDeny)
	audit.Mode = api.ModeAudit
	_, _ = b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("p1", api.ActionDeny, denyMount)))
	_, _ = b.Replace(ctx, privBinding(2), privPlan("r2", audit))
	i := e.instances[0]
	if len(i.adoptedCgroups) != 3 {
		t.Fatalf("before the deadline every adopted binding stays: %v", i.adoptedCgroups)
	}
	b.pins.start = time.Now().Add(-settleDeadline)
	if err := b.Prepare(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := i.adoptedCgroups[2]; ok || len(i.adoptedCgroups) != 2 {
		t.Fatalf("only the adopted binding of a current Audit plan goes: %v", i.adoptedCgroups)
	}
	if i.freed[6] || b.pins.settled {
		t.Fatalf("slot 6 still has an adopted binding; the section is not settled: freed=%v", i.freed)
	}
	if got := b.Adopted(); len(got) == 0 || !got[0].Degraded {
		t.Fatalf("the section reports itself degraded while a binding is kept: %+v", got)
	}
}

// Each status read checks the links of the old sets again (here the old set
// stays because its removal fails).
func TestRestartAdoptedLinksCheckedOnRead(t *testing.T) {
	b, e, pins, _ := newPinned(t, map[string]error{"/bpf/privilege/old": nil}, nil, previousRun)
	pins.removeErr = errors.New("busy")
	ctx := context.Background()
	if err := b.Prepare(ctx, nil); err != nil {
		t.Fatal(err)
	}
	_ = e
	if got := b.Adopted(); len(got) == 0 || got[0].LinkError != nil {
		t.Fatalf("links fine: %+v", got)
	}
	pins.linkErr = errors.New("pinned link gone")
	b.pins.linkAt = time.Time{} // adoptedTTL passed
	if got := b.Adopted(); len(got) == 0 || got[0].LinkError == nil {
		t.Fatalf("a missing pinned link must be reported on the next check: %+v", got)
	}
}

// Review 8, B1: a section whose last policy went away during the downtime
// never starts an instance (no Prepare or Replace). Its old sets are
// reported until a converged refresh, which removes them and resets the
// restored state.
func TestRestartSectionWithoutPlanSettles(t *testing.T) {
	b, e, pins, resets := newPinned(t, map[string]error{"/bpf/privilege/old": nil}, nil, previousRun)
	b.pins.bindingsOf = func(enforcement.PinnedSet) (map[uint64]enforcement.PinnedBinding, error) {
		return map[uint64]enforcement.PinnedBinding{7: {Slot: 5, Strict: true}, 8: {Slot: 5}}, nil
	}
	if got := b.Adopted(); len(got) != 1 || got[0].Slot != 5 || got[0].Bindings != 2 || got[0].Digest != "d5" {
		t.Fatalf("the old set must be reported from its pinned bindings: %+v", got)
	}
	if err := b.Settle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pins.dirs["/bpf/privilege/old"] || *resets != 1 || !b.pins.settled || len(b.Adopted()) != 0 || len(e.instances) != 0 {
		t.Fatalf("settle removes the old set and resets the restored state: %v resets=%d", pins.dirs, *resets)
	}
}

// Review 8, S2: the newest set is the one of the latest run, whatever its
// generation (it restarts at 1 in every run); B3: a state pinned by another
// image is not restored.
func TestRestartPicksTheLatestRunAndChecksTheImage(t *testing.T) {
	pins := &fakePins{dirs: map[string]bool{"/bpf/privilege/a-9": true, "/bpf/privilege/b-10": true}}
	sets := []enforcement.PinnedSet{
		{Dir: "/bpf/privilege/a-9", Manifest: enforcement.PinManifest{Generation: 9, RunStart: 200, ImageDigest: "sha256:1"}},
		{Dir: "/bpf/privilege/b-10", Manifest: enforcement.PinManifest{Generation: 10, RunStart: 100, ImageDigest: "sha256:1"}},
	}
	for _, tc := range []struct {
		digest, want string
	}{{"sha256:1", "/bpf/privilege/a-9"}, {"sha256:2", ""}} {
		b, err := NewPrivilege(&pinEngine{pins: pins}, nil, "n")
		if err != nil {
			t.Fatal(err)
		}
		b.section.resetState = func() error { return nil }
		b.section.image = func(context.Context) (string, string, error) { return "img", tc.digest, nil }
		var restored []string
		load := func(string, string) ([]enforcement.PinnedSet, map[string]error, error) { return sets, nil, nil }
		restore := func(s enforcement.PinnedSet) error { restored = append(restored, s.Dir); return nil }
		err = b.enablePins("/bpf/privilege", "boot", load, restore, pins.remove, pins.listUnder)
		switch {
		case tc.want != "" && (err != nil || len(restored) != 1 || restored[0] != tc.want || !b.pins.restored):
			t.Fatalf("digest %s: restored %v (%v), want %s", tc.digest, restored, err, tc.want)
		case tc.want == "" && (err == nil || len(restored) != 0 || b.pins.restored || len(b.pins.old) != 2):
			t.Fatalf("digest %s: another image must not be restored, and the old sets stay: %v %v %v", tc.digest, restored, err, b.pins.old)
		}
	}
}

// A failed pin of this run's instance shows in the restart status: the next
// restart would not keep enforcing.
func TestRestartStatusReportsPinFailure(t *testing.T) {
	b, _, pins, _ := newPinned(t, nil, nil, nil)
	pins.pinErr = errors.New("bpffs full")
	if err := b.Prepare(context.Background(), []sandboxpolicy.Plan{privPlan("r1", privPolicy("p1", api.ActionDeny))}); err != nil {
		t.Fatal(err)
	}
	if st, ok := b.RestartStatus(); !ok || st.Pinned || st.Err == nil {
		t.Fatalf("a failed pin must be reported: %+v %v", st, ok)
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

// Review 8, B2: without a restored state, the deadline keeps an old set while
// a cgroup it binds has no committed binding of this run (fail closed), and
// reports it from its manifest; after a complete binding snapshot that cgroup
// has no plan (its policy is gone), and the old set goes.
func TestRestartFailedRestoreKeepsOldSetsPastTheDeadline(t *testing.T) {
	defer func(d time.Duration) { settleDeadline = d }(settleDeadline)
	settleDeadline = 0
	b, _, pins, _ := newPinned(t, map[string]error{"/bpf/privilege/old": nil, "/bpf/privilege/unreadable": nil}, errors.New("incompatible"), nil)
	b.pins.bindingsOf = func(set enforcement.PinnedSet) (map[uint64]enforcement.PinnedBinding, error) {
		if set.Dir == "/bpf/privilege/unreadable" {
			return nil, errors.New("EIO")
		}
		return map[uint64]enforcement.PinnedBinding{1: {Slot: 5, Strict: true}, 99: {Slot: 5, Strict: true}}, nil
	}
	ctx := context.Background()
	plan := privPlan("r1", privPolicy("p1", api.ActionDeny, denyMount))
	if _, err := b.Replace(ctx, privBinding(1), plan); err != nil {
		t.Fatal(err)
	}
	prepare := func() {
		t.Helper()
		if err := b.Prepare(ctx, []sandboxpolicy.Plan{plan}); err != nil {
			t.Fatal(err)
		}
	}
	prepare()
	if !pins.dirs["/bpf/privilege/old"] {
		t.Fatal("cgroup 99 has no binding of this run: the old set must stay past the deadline")
	}
	// Both kept sets are reported: the readable one from its manifest, the
	// one whose bindings cannot be read as unreadable.
	a := b.Adopted()
	if len(a) != 2 || !a[0].Unreadable || !a[1].Degraded || a[1].Bindings != 2 || len(a[1].Policies) != 1 || a[1].Policies[0].Revision != "r0" {
		t.Fatalf("the kept old sets must be reported, degraded: %+v", a)
	}
	b.SnapshotComplete()
	prepare()
	if pins.dirs["/bpf/privilege/old"] {
		t.Fatal("after a complete snapshot cgroup 99 has no plan: the old set must go")
	}
	if !pins.dirs["/bpf/privilege/unreadable"] {
		t.Fatal("a set whose bindings cannot be read must stay (fail closed)")
	}
	if a := b.Adopted(); len(a) != 1 || !a[0].Unreadable {
		t.Fatalf("only the unreadable set is still reported: %+v", a)
	}
}

// The restored path at the deadline: an old set of another state (a fresh
// start that crashed before Settle) keeps judging with its own state. It
// stays, and is reported from its pinned bindings, while a cgroup it binds
// has no binding of this run; after a complete snapshot that cgroup has no
// plan, and the set goes.
func TestRestartRestoredDeadlineKeepsAnotherStatesSet(t *testing.T) {
	defer func(d time.Duration) { settleDeadline = d }(settleDeadline)
	settleDeadline = 0
	b, _, pins, _ := newPinned(t, map[string]error{"/bpf/privilege/a": nil, "/bpf/privilege/b": nil}, nil, nil)
	other := b.pins.sets["/bpf/privilege/a"]
	other.StateMaps = []enforcement.PinnedMap{{Pin: "map_bindings", Name: "bindings", MapID: 77}}
	b.pins.sets["/bpf/privilege/a"] = other
	b.pins.bindingsOf = func(set enforcement.PinnedSet) (map[uint64]enforcement.PinnedBinding, error) {
		if set.Dir == "/bpf/privilege/a" {
			return map[uint64]enforcement.PinnedBinding{99: {Slot: 5, Strict: true}}, nil
		}
		return nil, nil
	}
	ctx := context.Background()
	plan := privPlan("r1", privPolicy("p1", api.ActionDeny, denyMount))
	if _, err := b.Replace(ctx, privBinding(1), plan); err != nil {
		t.Fatal(err)
	}
	if pins.dirs["/bpf/privilege/b"] || !pins.dirs["/bpf/privilege/a"] {
		t.Fatalf("the restored state's set goes when the new instance is pinned; the other state's stays: %v", pins.dirs)
	}
	prepare := func() {
		t.Helper()
		if err := b.Prepare(ctx, []sandboxpolicy.Plan{plan}); err != nil {
			t.Fatal(err)
		}
	}
	prepare()
	if !pins.dirs["/bpf/privilege/a"] {
		t.Fatal("cgroup 99 has no binding of this run: the other state's set must stay past the deadline")
	}
	a := b.Adopted()
	if len(a) != 1 || a[0].Slot != 5 || a[0].Bindings != 1 || !a[0].Degraded || len(a[0].Policies) != 1 || a[0].Policies[0].Revision != "r0" {
		t.Fatalf("the other state's set must be reported from its pinned bindings, degraded: %+v", a)
	}
	b.SnapshotComplete()
	prepare()
	if pins.dirs["/bpf/privilege/a"] {
		t.Fatal("after a complete snapshot cgroup 99 has no plan: the set must go")
	}
	if a := b.Adopted(); len(a) != 0 {
		t.Fatalf("nothing is adopted any more: %+v", a)
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

// A reload before Settle keeps the restored state: the previous run's slot is
// not freed, no adopted binding is dropped, and the fault counts stay.
func TestRestartReloadBeforeSettleKeepsAdoptedState(t *testing.T) {
	b, e, _, _ := newPinned(t, map[string]error{"/bpf/privilege/old": nil}, nil, previousRun)
	e.shared = true
	ctx := context.Background()
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("p1", api.ActionDeny, denyMount))); err != nil {
		t.Fatal(err)
	}
	e.instances[0].readyErr = errors.New("lost")
	if _, err := b.Replace(ctx, privBinding(2), privPlan("r2", privPolicy("p2", api.ActionDeny))); err != nil {
		t.Fatal(err)
	}
	if len(e.instances) != 2 {
		t.Fatalf("expected a reload, got %d instances", len(e.instances))
	}
	second := e.instances[1].fakePrivilegeInstance
	if _, ok := second.published[5]; !ok || second.freed[5] || second.drops != 0 || second.resets != 0 {
		t.Fatalf("the restored state must stay until Settle: published=%v freed=%v drops=%d resets=%d", second.published, second.freed, second.drops, second.resets)
	}
}

// Review 9, own item: the denies of the old sets' programs have no verdict
// event (no process reads their ring buffers), so they count as lost
// verdicts. The total only grows: a removed set keeps its last count, and an
// unreadable set adds nothing new.
func TestRestartOldSetDeniesCountAsLostVerdicts(t *testing.T) {
	b, _, _, _ := newPinned(t, map[string]error{"/bpf/privilege/a": nil, "/bpf/privilege/b": nil}, errors.New("incompatible"), nil)
	denied := map[string]uint64{"/bpf/privilege/a": 5, "/bpf/privilege/b": 2}
	var readErr error
	b.pins.countersOf = func(set enforcement.PinnedSet) (enforcement.VerdictCounters, error) {
		if readErr != nil && set.Dir == "/bpf/privilege/b" {
			return enforcement.VerdictCounters{}, readErr
		}
		return enforcement.VerdictCounters{Denied: denied[set.Dir]}, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if n := b.oldSetLost(); n != 7 {
		t.Fatalf("lost %d, want 7", n)
	}
	denied["/bpf/privilege/a"] = 9
	readErr = errors.New("map gone")
	if n := b.oldSetLost(); n != 11 {
		t.Fatalf("an unreadable set keeps its last count: lost %d, want 11", n)
	}
	b.pins.old = []string{"/bpf/privilege/b"} // a was removed
	if n := b.oldSetLost(); n != 11 {
		t.Fatalf("a removed set keeps its count: lost %d, want 11", n)
	}
}
