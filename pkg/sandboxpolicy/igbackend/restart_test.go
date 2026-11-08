package igbackend

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	privruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/runtime"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// fakePins is a bpffs: the set directories that exist.
type fakePins struct {
	dirs    map[string]bool
	pinErr  error
	removed []string
}

func (f *fakePins) remove(dir string) error {
	delete(f.dirs, dir)
	f.removed = append(f.removed, dir)
	return nil
}

func (f *fakePins) list() []string {
	var out []string
	for d := range f.dirs {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
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
	i.pins.dirs[dir], i.dir = true, dir
	return nil
}

type pinEngine struct {
	fakePrivilegeEngine
	pins      *fakePins
	instances []*fakePinnedInstance
}

func (e *pinEngine) Start(ctx context.Context, id string, c privruntime.Config) (PrivilegeInstance, error) {
	i, err := e.fakePrivilegeEngine.Start(ctx, id, c)
	if err != nil {
		return nil, err
	}
	p := &fakePinnedInstance{fakePrivilegeInstance: i.(*fakePrivilegeInstance), pins: e.pins}
	e.instances = append(e.instances, p)
	return p, nil
}

func newPinned(t *testing.T, existing map[string]error) (*PrivilegeBackend, *pinEngine, *fakePins) {
	t.Helper()
	pins := &fakePins{dirs: map[string]bool{}}
	var sets []enforcement.PinnedSet
	rejected := map[string]error{}
	for dir, reason := range existing {
		pins.dirs[dir] = true
		if reason == nil {
			sets = append(sets, enforcement.PinnedSet{Dir: dir})
		} else {
			rejected[dir] = reason
		}
	}
	e := &pinEngine{pins: pins}
	b, err := NewPrivilege(e, nil, "n")
	if err != nil {
		t.Fatal(err)
	}
	load := func(root, section string) ([]enforcement.PinnedSet, map[string]error, error) {
		if root != "/bpf/privilege" || section != "privilege" {
			t.Fatalf("load %s %s", root, section)
		}
		return sets, rejected, nil
	}
	if err := b.enablePins("/bpf/privilege", "boot", load, pins.remove); err != nil {
		t.Fatal(err)
	}
	return b, e, pins
}

func TestRestartAdoptedSetsStayUntilSettle(t *testing.T) {
	b, e, pins := newPinned(t, map[string]error{"/bpf/privilege/old": nil, "/bpf/privilege/broken": errors.New("tag changed")})
	ctx := context.Background()
	plan := privPlan("r1", privPolicy("p1", api.ActionAllow, denyMount))
	if _, err := b.Replace(ctx, privBinding(1), plan); err != nil {
		t.Fatal(err)
	}
	// A second combination before settle replaces the instance: still no pin,
	// and the previous run's sets keep enforcing.
	if _, err := b.Replace(ctx, privBinding(2), privPlan("r2", privPolicy("p2", api.ActionDeny))); err != nil {
		t.Fatal(err)
	}
	if got := pins.list(); len(got) != 2 || len(pins.removed) != 0 {
		t.Fatalf("before settle the pinned sets must not change: %v removed %v", got, pins.removed)
	}
	if err := b.Settle(ctx); err != nil {
		t.Fatal(err)
	}
	current := e.instances[len(e.instances)-1]
	if got := pins.list(); len(got) != 1 || got[0] != current.dir {
		t.Fatalf("after settle only the current instance is pinned: %v (current %q)", got, current.dir)
	}
	// Idempotent.
	if err := b.Settle(ctx); err != nil || len(pins.list()) != 1 {
		t.Fatalf("second settle: %v %v", err, pins.list())
	}
}

func TestRestartSettleWaitsForReadyInstance(t *testing.T) {
	b, e, pins := newPinned(t, map[string]error{"/bpf/privilege/old": nil})
	ctx := context.Background()
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("p1", api.ActionAllow, denyMount))); err != nil {
		t.Fatal(err)
	}
	e.instances[0].readyErr = errors.New("detached")
	if err := b.Settle(ctx); err != nil || !pins.dirs["/bpf/privilege/old"] || len(pins.dirs) != 1 {
		t.Fatalf("an instance that is not ready must not replace the last-good set: %v %v", err, pins.list())
	}
}

func TestRestartPinFailureKeepsLastGood(t *testing.T) {
	b, _, pins := newPinned(t, map[string]error{"/bpf/privilege/old": nil})
	ctx := context.Background()
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("p1", api.ActionAllow, denyMount))); err != nil {
		t.Fatal(err)
	}
	pins.pinErr = errors.New("no bpffs")
	if err := b.Settle(ctx); err == nil || !pins.dirs["/bpf/privilege/old"] {
		t.Fatalf("a failed pin must keep the adopted set: %v %v", err, pins.list())
	}
	pins.pinErr = nil
	if err := b.Settle(ctx); err != nil || pins.dirs["/bpf/privilege/old"] || len(pins.dirs) != 1 {
		t.Fatalf("the next settle retries: %v %v", err, pins.list())
	}
}

func TestRestartAfterSettleReplacementMovesThePin(t *testing.T) {
	b, e, pins := newPinned(t, nil)
	ctx := context.Background()
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("p1", api.ActionAllow, denyMount))); err != nil {
		t.Fatal(err)
	}
	if err := b.Settle(ctx); err != nil {
		t.Fatal(err)
	}
	first := e.instances[0]
	if _, err := b.Replace(ctx, privBinding(2), privPlan("r2", privPolicy("p2", api.ActionDeny))); err != nil {
		t.Fatal(err)
	}
	second := e.instances[1]
	if first.stops != 1 || pins.dirs[first.dir] || !pins.dirs[second.dir] || len(pins.dirs) != 1 {
		t.Fatalf("the replacement must be pinned and the old instance unpinned: %v", pins.list())
	}
	// Exit: the current instance stops but stays pinned.
	if err := b.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if second.stops != 1 || !pins.dirs[second.dir] {
		t.Fatalf("close must keep the current pins: stops %d %v", second.stops, pins.list())
	}
}

func TestRestartSettleWithNoPolicyRemovesAdopted(t *testing.T) {
	pins := &fakePins{dirs: map[string]bool{"/bpf/network/old": true}}
	b, err := NewNetwork(&fakeNetworkEngine{}, nil, "n")
	if err != nil {
		t.Fatal(err)
	}
	load := func(string, string) ([]enforcement.PinnedSet, map[string]error, error) {
		return []enforcement.PinnedSet{{Dir: "/bpf/network/old"}}, nil, nil
	}
	if err := b.enablePins("/bpf/network", "boot", load, pins.remove); err != nil {
		t.Fatal(err)
	}
	// The policy was deleted while node-agent was down: no instance, no binding.
	if err := b.Settle(context.Background()); err != nil || len(pins.dirs) != 0 {
		t.Fatalf("with no policy the old set must go: %v %v", err, pins.list())
	}
}
