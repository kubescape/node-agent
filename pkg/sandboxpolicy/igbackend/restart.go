package igbackend

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	fileruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/runtime"
	netruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/runtime"
	privruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"k8s.io/apimachinery/pkg/types"
)

// Restart survival. The section's state (bindings, slot state, policy, task
// marks, fault counts) lives in maps pinned by name (common/pin.h), which the
// next load of the gadget re-opens. node-agent's own /sys/fs/bpf ends with its
// container, so the owner also pins the state maps and the instance's links
// on the host bpffs, one set per run (root/<section>/<run>). The kernel keeps
// enforcing through the pinned links while node-agent is down.
//
// At the next start the owner pins the state maps of the newest valid set
// back for the first load (enforcement.RestoreState), when the set was pinned
// by the same gadget image and layout: the new instance judges with the same
// state from its first program on, and the old sets that ran on those maps are
// removed as soon as the new instance is pinned. The containers then bind
// again with live writes; the kernel bindings of the previous run that no
// container takes over are "adopted". Settle drops them after a refresh in
// which the section's own bindings converged (and the binding snapshot was
// complete). After settleDeadline it decides per adopted binding from the
// current plan of its cgroup: it keeps the binding when a current binding of
// this section covers that cgroup with a Strict plan, or when no plan is known
// and no complete snapshot was seen yet (fail closed); it drops it when the
// plan is now Audit, or when no plan exists after a complete snapshot (the
// policy was removed). The section reports itself degraded while any remains.
// Until then the section reports AdoptedLastGood.
//
// When the state is not restored (another image or layout, a failed restore,
// a set that could not be validated because of an I/O error), the first start
// is fresh and the old sets keep judging with their own state: each one is
// removed once every cgroup it binds has a committed binding of this run or an
// Audit plan (or no plan after a complete snapshot, past the deadline), or at
// a converged Settle. Adopted reports them from their pinned bindings.

// settleDeadline bounds how long adopted bindings stay undecided after a start.
var settleDeadline = 2 * time.Minute

// pinner is a NodeInstance that can pin itself (see enforcement.PinInstance).
type pinner interface {
	Pin(ctx context.Context, dir string, m enforcement.PinManifest) error
}

// pinning is the restart survival state of a node owner.
type pinning struct {
	// root is the section's directory on the host bpffs.
	root   string
	bootID string
	// run makes the set names of this process unique.
	run    int64
	remove func(string) error
	// missing tells whether a pinned set's directory is gone
	// (pinnedDirMissing; replaced in tests).
	missing func(string) bool
	list    func(string) ([]string, error)
	// restored: the state of a previous run was pinned back for the first
	// start, which must then keep it (no reset).
	restored bool
	// old are the sets of previous runs: removed once this run's instance is
	// pinned when the state was restored (same maps), else at Settle (their
	// links still judge with the previous state).
	old []string
	// adopted are the slots the previous run published, from its manifest.
	adopted map[uint32]enforcement.PinnedSlot
	start   time.Time
	settled bool
	// update rewrites a pinned set's manifest (enforcement.UpdateManifest).
	update func(dir string, fn func(*enforcement.PinManifest)) error
	// dirs are the pinned instances of this run.
	dirs map[NodeInstance]string
	// sets are the manifests of the old sets, to check their links on each
	// status read (Adopted).
	sets map[string]enforcement.PinManifest
	// checkLinks checks a set's pinned links (enforcement.CheckPinnedLinks).
	checkLinks func(enforcement.PinnedSet) error
	// deadline: settleDeadline passed and adopted bindings remain, kept
	// only for Strict current plans: the section is degraded.
	deadline bool
	// pinErr: the last pin of this run's instance failed; the next restart
	// would not keep enforcing. manifestErr: the last manifest update
	// failed; the next run would report a stale revision.
	pinErr, manifestErr error
	// restoredMaps are the state map IDs of the restored set: pinStarted
	// removes only the old sets that ran on those same maps.
	restoredMaps map[uint32]bool
	// image and digest name the running gadget image (written to each
	// manifest; a state is restored only into the same image).
	image, digest string
	// linkErr and linkAt bound the cost of Adopted: it checks every pinned
	// link of the old sets at most once per adoptedTTL (a status read asks
	// once per policy).
	linkErr error
	linkAt  time.Time
	// oldReport is the cached report of the old sets (oldSetReport) for the
	// old sets named by oldKey.
	oldReport []sandboxpolicy.AdoptedSlot
	oldKey    string
	// evicted names the old sets removed at start over maxOldSets (each
	// covered by a newer set, so status does not report them).
	evicted []string
	// startFailures counts the failed first starts on the restored state
	// (restoredStartFailed).
	startFailures int
	// bindingsOf reads an old set's pinned bindings
	// (enforcement.PinnedBindings; replaced in tests).
	bindingsOf func(enforcement.PinnedSet) (map[uint64]enforcement.PinnedBinding, error)
	// snapshotSeen: the controller saw a complete binding snapshot since
	// the start, so a cgroup with no plan has no policy any more.
	snapshotSeen bool
	// listed and listedNames hold the UIDs and the "namespace/name" of the
	// policies in the last complete policy listing (PoliciesListed); listed
	// is nil while no complete listing was seen.
	listed, listedNames map[string]bool
	// countersOf reads an old set's verdict counters
	// (enforcement.PinnedSetCounters; replaced in tests). oldBase holds each
	// old set's deny count at its first read in this run (the previous run
	// read the events before), oldDenied its growth since, goneDenied the
	// growth of removed sets (oldSetLost); counterWarned: an unreadable set
	// was logged.
	countersOf func(enforcement.PinnedSet) (enforcement.VerdictCounters, error)
	oldBase    map[string]uint64
	oldDenied  map[string]uint64
	// oldLoss is the old sets' share of the section's lost verdicts
	// (rates.go names it in the note).
	oldLoss       lossWindow
	goneDenied    uint64
	counterWarned map[string]bool
	// deleteBinding removes one cgroup from an old set's pinned binding map
	// (enforcement.DeletePinnedBinding; replaced in tests).
	deleteBinding func(enforcement.PinnedSet, uint64) error
	// unvalidated are old sets that could not be validated because of an
	// I/O or transient error (S3): kept, never restored, reported.
	unvalidated map[string]error
}

// adoptedTTL bounds how often Adopted re-checks the old sets' links.
const adoptedTTL = 5 * time.Second

// maxOldSets bounds the old sets a start keeps: each keeps one link per hook,
// and the hook limit is enforcement.MaxFamilyLinksPerHook for every instance
// of the family (two more for the running instance and a replacement).
const maxOldSets = enforcement.MaxFamilyLinksPerHook - 2

// RestartSurvival pins the section's instance under root/<section> and
// restores the state a previous node-agent pinned there. Call it once, before
// the first Prepare or Replace.
//
// When the boot id or the sets cannot be read (an I/O error, which proves
// nothing about them), restart survival stays off for this run and the sets
// are kept: they may enforce, and the next run decides.
func (b *nodeOwner[C]) RestartSurvival(root string) error {
	bootID, err := enforcement.BootID()
	if err != nil {
		err = fmt.Errorf("%s restart survival off for this run, pinned sets kept: %w", b.section.name, err)
		b.mu.Lock()
		b.survivalOff = err
		b.mu.Unlock()
		return err
	}
	return b.enablePins(filepath.Join(root, b.section.name), bootID, enforcement.LoadPinned, enforcement.RestoreState, enforcement.RemovePinned, listDirs)
}

func listDirs(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	var dirs []string
	for _, e := range entries {
		dirs = append(dirs, filepath.Join(root, e.Name()))
	}
	return dirs, err
}

func (b *nodeOwner[C]) enablePins(root, bootID string, load func(root, section string) ([]enforcement.PinnedSet, map[string]error, error),
	restore func(enforcement.PinnedSet) error, remove func(string) error, list func(string) ([]string, error)) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pins != nil {
		return fmt.Errorf("%s restart survival already enabled", b.section.name)
	}
	sets, rejected, err := load(root, b.section.name)
	if err != nil {
		b.survivalOff = fmt.Errorf("%s restart survival off for this run, pinned sets kept: %w", b.section.name, err)
		return b.survivalOff
	}
	p := &pinning{root: root, bootID: bootID, run: bootClock(), remove: remove, list: list, dirs: map[NodeInstance]string{},
		adopted: map[uint32]enforcement.PinnedSlot{}, start: time.Now(), update: enforcement.UpdateManifest,
		sets: map[string]enforcement.PinManifest{}, checkLinks: enforcement.CheckPinnedLinks, restoredMaps: map[uint32]bool{},
		bindingsOf: readPinnedBindings, unvalidated: map[string]error{}, missing: pinnedDirMissing,
		deleteBinding: enforcement.DeletePinnedBinding, countersOf: enforcement.PinnedSetCounters}
	if b.section.image != nil {
		// An unknown digest restores nothing (a state is restored only
		// into the image that pinned it).
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		name, digest, err := b.section.image(ctx)
		cancel()
		p.image, p.digest = name, digest
		if err != nil {
			logger.L().Warning("sandbox "+b.section.name+" gadget image digest unknown: no pinned state is restored", helpers.Error(err))
		}
	}
	var errs []error
	for dir, reason := range rejected {
		if !errors.Is(reason, enforcement.ErrPinnedSetInvalid) {
			// An I/O or transient error proves nothing: keep the set (its
			// links may enforce), never restore it, and report it until
			// Settle.
			logger.L().Warning("sandbox "+b.section.name+" pinned set not validated, kept until Settle", helpers.String("dir", dir), helpers.Error(reason))
			p.old = append(p.old, dir)
			p.unvalidated[dir] = reason
			continue
		}
		logger.L().Warning("sandbox "+b.section.name+" pinned set not adopted, removed", helpers.String("dir", dir), helpers.Error(reason))
		errs = append(errs, remove(dir))
	}
	// Oldest first: by run, then generation, then directory (a strict order).
	// A run start later than the boot clock now is not from this boot's
	// clock (a wall-clock start from an earlier development build): it
	// sorts as the oldest.
	now := bootClock()
	sort.Slice(sets, func(i, j int) bool {
		a, c := sets[i].Manifest, sets[j].Manifest
		// Wall-clock starts first (older), in their own order.
		if wa, wc := a.RunStart > now, c.RunStart > now; wa != wc {
			return wa
		}
		if a.RunStart != c.RunStart {
			return a.RunStart < c.RunStart
		}
		if a.Generation != c.Generation {
			return a.Generation < c.Generation
		}
		return sets[i].Dir < sets[j].Dir
	})
	// Each old set keeps a link per hook, a kept unreadable one too: over
	// maxOldSets, the oldest sets go, but only a set whose cgroups are all
	// bound in a newer kept set (nothing loses its enforcement). Other sets
	// stay; if the hook then fills up, the new instance's attach is refused
	// (AttachCapacity, fail closed). The newest readable set always stays
	// (it holds the state to restore).
	for i := 0; i < len(sets)-1 && len(sets)+len(p.unvalidated) > maxOldSets; {
		if !coveredByNewer(p.bindingsOf, sets[i], sets[i+1:]) {
			i++
			continue
		}
		logger.L().Warning("sandbox "+b.section.name+" too many pinned sets: an old set whose bindings a newer set holds is removed", helpers.String("dir", sets[i].Dir))
		if err := remove(sets[i].Dir); err != nil {
			// Still pinned: keep tracking it.
			errs = append(errs, err)
			i++
			continue
		}
		p.evicted = append(p.evicted, filepath.Base(sets[i].Dir))
		sets = append(sets[:i], sets[i+1:]...)
	}
	if len(sets)+len(p.unvalidated) > maxOldSets {
		logger.L().Warning("sandbox "+b.section.name+" more pinned sets than the link budget: kept (a new attach may be refused for capacity)",
			helpers.Int("sets", len(sets)+len(p.unvalidated)), helpers.Int("budget", maxOldSets))
	}
	for _, s := range sets {
		p.old = append(p.old, s.Dir)
		p.sets[s.Dir] = s.Manifest
	}
	if len(sets) > 0 {
		// The newest set holds the state to keep.
		newest := sets[len(sets)-1]
		if why := b.restorable(newest.Manifest, p.digest); why != "" {
			// Another image or layout: start fresh and keep the old links
			// until Settle; the old layout's state pins go.
			errs = append(errs, fmt.Errorf("%s: pinned state not restored: %s", b.section.name, why))
			for _, sm := range newest.Manifest.StateMaps {
				if !strings.HasPrefix(sm.Name, b.section.mapPrefix) {
					if err := os.Remove(filepath.Join(enforcement.PinRoot, sm.Name)); err != nil && !errors.Is(err, os.ErrNotExist) {
						errs = append(errs, err)
					}
				}
			}
		} else if err := restore(newest); err != nil {
			// Start from fresh state; the old links keep their own state
			// until Settle.
			errs = append(errs, fmt.Errorf("%s: restoring the pinned state: %w", b.section.name, err))
		} else {
			p.restored = true
			for _, sm := range newest.Manifest.StateMaps {
				p.restoredMaps[sm.MapID] = true
			}
			for _, s := range newest.Manifest.Slots {
				p.adopted[s.Slot] = s
			}
			logger.L().Info("sandbox "+b.section.name+" restored the pinned state", helpers.String("dir", newest.Dir),
				helpers.Int("slots", len(newest.Manifest.Slots)))
		}
	}
	b.pins = p
	return errors.Join(errs...)
}

// readPinnedBindings is enforcement.PinnedBindings (replaced in tests).
var readPinnedBindings = enforcement.PinnedBindings

// coveredByNewer reports whether every cgroup an old set binds is bound in
// one of the newer sets. A set whose bindings cannot be read is never
// covered, and a newer set that cannot be read covers nothing.
func coveredByNewer(read func(enforcement.PinnedSet) (map[uint64]enforcement.PinnedBinding, error), old enforcement.PinnedSet, newer []enforcement.PinnedSet) bool {
	bindings, err := read(old)
	if err != nil {
		return false
	}
	held := map[uint64]bool{}
	for _, s := range newer {
		nb, err := read(s)
		if err != nil {
			continue
		}
		for cgroup := range nb {
			held[cgroup] = true
		}
	}
	for cgroup := range bindings {
		if !held[cgroup] {
			return false
		}
	}
	return true
}

// restorable returns why a pinned set's state must not be restored into the
// running gadget, or "": another image digest, or state maps outside the
// section's prefix (another layout, pin.h).
func (b *nodeOwner[C]) restorable(m enforcement.PinManifest, digest string) string {
	if b.section.image != nil && (digest == "" || m.ImageDigest != digest) {
		return fmt.Sprintf("pinned by image %q, running %q", m.ImageDigest, digest)
	}
	for _, sm := range m.StateMaps {
		if b.section.mapPrefix != "" && !strings.HasPrefix(sm.Name, b.section.mapPrefix) {
			return fmt.Sprintf("state map %s is not of the layout %s", sm.Name, b.section.mapPrefix)
		}
	}
	return ""
}

// adopting reports whether a start must keep the restored state: the first
// start, and every start until Settle resolved the previous run's slots (a
// reload before it must not drop the slots and bindings Settle decides on). A
// failing removal of an old link set alone does not keep it adopting.
func (b *nodeOwner[C]) adopting() bool {
	return b.pins != nil && b.pins.restored && !b.pins.settled && (!b.started || len(b.pins.adopted) > 0)
}

// maxRestoredStartFailures bounds the failed first starts on a restored
// state: then the owner gives the state up and starts fresh.
const maxRestoredStartFailures = 3

// restoredStartFailed counts a failed first start on the restored state (not
// an attach capacity refusal, which has its own backoff). After
// maxRestoredStartFailures the restored state is given up: the next start
// resets it, and the old sets follow the path of a failed restore (they keep
// their links until every cgroup they bind is covered: fail closed). Without
// this a state the gadget cannot load on would leave every new container of
// the section unenforced. Runs under mu.
func (b *nodeOwner[C]) restoredStartFailed(err error) {
	if b.started || !b.adopting() {
		return
	}
	var full *enforcement.AttachCapacityError
	if errors.As(err, &full) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	b.pins.startFailures++
	if b.pins.startFailures < maxRestoredStartFailures {
		return
	}
	logger.L().Warning("sandbox "+b.section.name+" gadget does not start on the restored state: starting fresh, the old sets keep enforcing until covered",
		helpers.Int("failures", b.pins.startFailures), helpers.Error(err))
	b.pins.restored = false
	b.pins.adopted = map[uint32]enforcement.PinnedSlot{}
	b.pins.restoredMaps = map[uint32]bool{}
	b.pins.linkAt = time.Time{} // report the old sets again
}

// pinStarted pins the instance that just started, and removes the sets of
// previous runs when they ran on the same (restored) state. Runs under mu. A
// failed pin loses only the survival of the next restart.
func (b *nodeOwner[C]) pinStarted(ctx context.Context) error {
	if b.pins == nil || b.instance == nil {
		return nil
	}
	if err := b.pin(ctx, b.instance); err != nil {
		return err
	}
	if !b.pins.restored {
		return nil
	}
	// Only the old sets that ran on the restored maps go now (their state
	// lives on in this instance); another set (an older run, a fresh start
	// that crashed before Settle) keeps judging with its own state until
	// Settle. A set that cannot be removed now is removed at Settle; it is
	// not a failed pin.
	var kept []string
	for _, dir := range b.pins.old {
		if _, bad := b.pins.unvalidated[dir]; bad || !b.sameState(b.pins.sets[dir]) {
			kept = append(kept, dir)
			continue
		}
		if err := b.pins.remove(dir); err != nil {
			kept = append(kept, dir)
			logger.L().Warning("sandbox "+b.section.name+" old pinned set not removed yet", helpers.String("dir", dir), helpers.Error(err))
		}
	}
	b.pins.old = kept
	return nil
}

// sameState reports whether a pinned set ran on the restored state maps.
func (b *nodeOwner[C]) sameState(m enforcement.PinManifest) bool {
	if len(m.StateMaps) == 0 {
		return len(b.pins.restoredMaps) == 0
	}
	for _, sm := range m.StateMaps {
		if !b.pins.restoredMaps[sm.MapID] {
			return false
		}
	}
	return true
}

// pin pins instance once, with the slot manifest.
func (b *nodeOwner[C]) pin(ctx context.Context, instance NodeInstance) error {
	if _, done := b.pins.dirs[instance]; done {
		return b.writeManifest()
	}
	p, ok := instance.(pinner)
	if !ok {
		return fmt.Errorf("%s instance cannot be pinned", b.section.name)
	}
	generation, ok := b.generations[instance]
	if !ok {
		generation = b.generation
	}
	dir := filepath.Join(b.pins.root, fmt.Sprintf("%s-%d-%d", b.section.name, b.pins.run, generation))
	if err := p.Pin(ctx, dir, enforcement.PinManifest{BootID: b.pins.bootID, Slots: b.pinnedSlots(),
		Image: b.pins.image, ImageDigest: b.pins.digest, RunStart: b.pins.run}); err != nil {
		return fmt.Errorf("pinning %s instance: %w", b.section.name, err)
	}
	b.pins.dirs[instance] = dir
	return nil
}

// pinnedSlots describes the published slots for the manifest. Runs under mu.
func (b *nodeOwner[C]) pinnedSlots() []enforcement.PinnedSlot {
	var out []enforcement.PinnedSlot
	for c, slot := range b.slots {
		s := enforcement.PinnedSlot{Slot: slot, Generation: b.content[c]}
		var revisions []sandboxpolicy.PolicyRevision
		for _, p := range b.combinations[c] {
			s.Policies = append(s.Policies, enforcement.PinnedPolicy{UID: string(p.Identity.UID), Namespace: p.Identity.Namespace, Name: p.Identity.Name, Revision: p.Revision})
			revisions = append(revisions, sandboxpolicy.PolicyRevision{Policy: p.Identity, Revision: p.Revision})
		}
		s.Digest = sandboxpolicy.RevisionDigest(revisions)
		out = append(out, s)
	}
	for slot, s := range b.pins.adopted {
		if !b.slotUsed(slot) {
			out = append(out, s) // adopted slots stay described until freed
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slot < out[j].Slot })
	return out
}

func (b *nodeOwner[C]) slotUsed(slot uint32) bool {
	for _, s := range b.slots {
		if s == slot {
			return true
		}
	}
	return false
}

// writeManifest keeps the manifest of the current instance's set current
// (after a publication or a freed slot). Runs under mu.
func (b *nodeOwner[C]) writeManifest() error {
	if b.pins == nil || b.instance == nil {
		return nil
	}
	dir, ok := b.pins.dirs[b.instance]
	if !ok {
		return nil
	}
	slots := b.pinnedSlots()
	// A manifest that does not follow the slots would make the next run
	// report a stale revision: a failed pin for status (RestartStatus).
	b.pins.manifestErr = b.pins.update(dir, func(m *enforcement.PinManifest) { m.Slots = slots })
	if b.pins.manifestErr != nil {
		b.pins.manifestErr = fmt.Errorf("updating the pinned manifest: %w", b.pins.manifestErr)
	}
	return b.pins.manifestErr
}

// Settle runs after a refresh that converged: every binding of the current
// plans is committed. It drops the adopted kernel bindings, frees the slots
// only they used, and removes the sets of previous runs. It assumes one
// node-agent per node (a DaemonSet starts the new pod after the old one is
// gone).
func (b *nodeOwner[C]) Settle(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pins == nil || b.closed || b.pins.settled {
		return nil
	}
	if b.instance == nil {
		return b.settleWithoutPlan()
	}
	if b.instance.Ready() != nil {
		return nil // a failed instance protects nothing: keep the last-good state
	}
	return b.settleAdopted(nil)
}

// settleWithoutPlan settles a section that has no plan at a converged
// refresh (its last policy went away during the downtime): it never starts an
// instance, so nothing else would remove the old sets, and their links would
// keep denying stale policy. A section that has plans but no running instance
// (its start keeps failing) keeps them: fail closed. Runs under mu.
func (b *nodeOwner[C]) settleWithoutPlan() error {
	if len(b.desired) > 0 || len(b.bindings) > 0 || len(b.pods) > 0 || len(b.prepared) > 0 {
		return nil
	}
	var errs []error
	var kept []string
	for _, dir := range b.pins.old {
		if err := b.pins.remove(dir); err != nil {
			kept = append(kept, dir)
			errs = append(errs, err)
		}
	}
	b.pins.old = kept
	if b.pins.restored && b.section.resetState != nil {
		// The restored state was for policies that are gone: a later
		// start begins fresh.
		errs = append(errs, b.section.resetState())
		b.pins.restored = false
	}
	if len(kept) == 0 {
		b.pins.adopted = map[uint32]enforcement.PinnedSlot{}
		b.pins.settled = true
		logger.L().Info("sandbox " + b.section.name + " settled after restart: no policy uses the section")
	}
	return errors.Join(errs...)
}

// settleAdopted drops the adopted kernel bindings that keep does not accept,
// frees the adopted slots no binding uses any more, and, when none remains,
// removes the old sets and marks the section settled. Runs under mu.
func (b *nodeOwner[C]) settleAdopted(keep func(cgroup uint64, slot uint32, strict bool) bool) error {
	var errs []error
	remaining, err := b.instance.DropAdopted(keep)
	if err != nil {
		errs = append(errs, err)
	}
	// The published slots this run does not use: free those no kept
	// adopted binding holds.
	held := b.instance.AdoptedBindings()
	for slot := range b.instance.PublishedSlots() {
		if b.slotUsed(slot) {
			delete(b.pins.adopted, slot)
			continue
		}
		if held[slot] > 0 {
			continue
		}
		if err := b.instance.Free(slot); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(b.pins.adopted, slot)
		delete(b.orphans, slot)
	}
	// At the deadline (keep set), another state's old set (an older run, a
	// fresh start that crashed before Settle) loses each cgroup that is
	// covered, and goes when none is left; an unreadable set stays.
	var kept []string
	for _, dir := range b.pins.old {
		if keep == nil || (b.sameState(b.pins.sets[dir]) && !b.isUnvalidated(dir)) {
			kept = append(kept, dir)
			continue
		}
		empty, err := b.pruneOldSet(dir, true)
		errs = append(errs, err)
		if !empty {
			kept = append(kept, dir)
			continue
		}
		if err := b.pins.remove(dir); err != nil {
			kept = append(kept, dir)
			errs = append(errs, err)
		}
	}
	b.pins.old = kept
	if remaining > 0 {
		return errors.Join(append(errs, b.writeManifest())...)
	}
	// No adopted binding is left: the sets that ran on the restored maps go
	// (at a converged Settle, every old set goes).
	kept = nil
	for _, dir := range b.pins.old {
		if keep != nil && (b.isUnvalidated(dir) || !b.sameState(b.pins.sets[dir])) {
			kept = append(kept, dir)
			continue
		}
		if err := b.pins.remove(dir); err != nil {
			kept = append(kept, dir)
			errs = append(errs, err)
		}
	}
	b.pins.old = kept
	if !b.pins.settled && len(kept) == 0 && len(b.pins.adopted) == 0 {
		b.pins.settled = true
		logger.L().Info("sandbox " + b.section.name + " settled after restart")
	}
	return errors.Join(append(errs, b.writeManifest())...)
}

func (b *nodeOwner[C]) isUnvalidated(dir string) bool {
	_, bad := b.pins.unvalidated[dir]
	return bad
}

// settleByDeadline runs at each Prepare and after each complete policy
// listing. Without a restored state it removes from each old set the cgroups
// that are covered, and the set when none is left (settleOldSets). With one,
// once settleDeadline passed without a converged Settle, it decides on the
// adopted bindings: one is dropped when the current plan of its cgroup is
// Audit (Audit never blocks), or when no plan exists and either a complete
// snapshot was seen or its policies are all gone from a complete policy
// listing (the policy was removed); it is kept when the plan is Strict, or
// not known (fail closed). A section with no plan and no instance settles at
// the deadline when every adopted policy is gone from the listing. While any
// remains, the section is degraded. Runs under mu.
func (b *nodeOwner[C]) settleByDeadline() error {
	if b.pins == nil || b.pins.settled || b.closed {
		return nil
	}
	past := time.Since(b.pins.start) >= settleDeadline
	if !b.pins.restored {
		err := b.settleOldSets(past)
		b.pins.deadline = past && len(b.pins.old) > 0
		return err
	}
	// The sets of another state (an older run) judge with their own state:
	// prune them as on the not-restored path, also before the deadline and
	// while the instance is not ready (a committed binding covers only while
	// it is ready).
	pruneErr := b.pruneOtherStates(past)
	if !past {
		return pruneErr
	}
	if b.instance == nil {
		return errors.Join(pruneErr, b.settleGoneWithoutInstance())
	}
	if b.instance.Ready() != nil {
		return pruneErr
	}
	err := b.settleAdopted(func(cgroup uint64, slot uint32, _ bool) bool {
		strict, ok := b.currentStrict(cgroup)
		if !ok {
			return !b.pins.snapshotSeen && !b.policiesGone(b.pins.adopted[slot].Policies)
		}
		return strict
	})
	remaining := 0
	for _, n := range b.instance.AdoptedBindings() {
		remaining += n
	}
	b.pins.deadline = remaining > 0 || len(b.pins.old) > 0
	return errors.Join(pruneErr, err)
}

// pruneOtherStates prunes each validated old set of another state than the
// restored one (pruneOldSet), and removes it when no entry is left. Runs
// under mu.
func (b *nodeOwner[C]) pruneOtherStates(past bool) error {
	var errs []error
	var kept []string
	for _, dir := range b.pins.old {
		if b.isUnvalidated(dir) || b.sameState(b.pins.sets[dir]) {
			kept = append(kept, dir)
			continue
		}
		empty, err := b.pruneOldSet(dir, past)
		errs = append(errs, err)
		if !empty {
			kept = append(kept, dir)
			continue
		}
		if err := b.pins.remove(dir); err != nil {
			kept = append(kept, dir)
			errs = append(errs, err)
		}
	}
	b.pins.old = kept
	return errors.Join(errs...)
}

// settleGoneWithoutInstance settles, past the deadline, a section with a
// restored state but no instance and no plan, when every adopted slot's
// policies are gone from a complete listing: its policies were removed during
// the downtime, and no converged refresh may come (another policy of the node
// keeps failing). Otherwise it keeps everything (fail closed). Runs under mu.
func (b *nodeOwner[C]) settleGoneWithoutInstance() error {
	if len(b.desired) > 0 || len(b.bindings) > 0 || len(b.pods) > 0 || len(b.prepared) > 0 || b.pins.listed == nil {
		b.pins.deadline = true
		return nil
	}
	for _, s := range b.pins.adopted {
		if !b.policiesGone(s.Policies) {
			b.pins.deadline = true
			return nil
		}
	}
	for _, dir := range b.pins.old {
		if b.isUnvalidated(dir) {
			b.pins.deadline = true
			return nil
		}
		if !b.sameState(b.pins.sets[dir]) {
			if empty, err := b.pruneOldSet(dir, true); err != nil || !empty {
				b.pins.deadline = true
				return err
			}
			continue
		}
		// The restored state's own bindings: each must name a slot whose
		// policies the manifest lists and the listing no longer has (a stale
		// manifest proves nothing).
		bindings, err := b.pins.bindingsOf(enforcement.PinnedSet{Dir: dir, Manifest: b.pins.sets[dir]})
		if err != nil {
			b.pins.deadline = true
			return nil
		}
		for _, v := range bindings {
			if s, ok := b.pins.adopted[v.Slot]; !ok || !b.policiesGone(s.Policies) {
				b.pins.deadline = true
				return nil
			}
		}
	}
	return b.settleWithoutPlan()
}

// policiesGone reports whether a complete policy listing was seen and none
// of the policies is in it, by UID or by namespace and name (a policy deleted
// and created again under the same name may select the same container: keep
// its binding, fail closed). Unknown policies (none named) are never gone.
// Runs under mu.
func (b *nodeOwner[C]) policiesGone(policies []enforcement.PinnedPolicy) bool {
	if b.pins.listed == nil || len(policies) == 0 {
		return false
	}
	for _, p := range policies {
		if b.pins.listed[p.UID] || b.pins.listedNames[p.Namespace+"/"+p.Name] {
			return false
		}
	}
	return true
}

// PoliciesListed gives the owner the UIDs of a complete policy listing (the
// controller listed every policy source). Past the settle deadline, an
// adopted binding or an old set's binding whose policies are all gone from it
// is dropped, without waiting for the whole node to converge. It runs the
// deadline decision at once, also for a section with no instance.
func (b *nodeOwner[C]) PoliciesListed(uids, names map[string]bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pins == nil || b.pins.settled {
		return nil
	}
	b.pins.listed, b.pins.listedNames = uids, names
	return b.settleByDeadline()
}

// settleOldSets removes from each old set (of a state that was not restored)
// the cgroups that are covered, and the set when none is left (pruneOldSet).
// A set whose bindings cannot be read is kept (fail closed). When none
// remains, the section is settled. Runs under mu.
func (b *nodeOwner[C]) settleOldSets(past bool) error {
	var errs, kept = []error{}, []string{}
	for _, dir := range b.pins.old {
		empty, err := b.pruneOldSet(dir, past)
		errs = append(errs, err)
		if !empty {
			kept = append(kept, dir)
			continue
		}
		if err := b.pins.remove(dir); err != nil {
			kept = append(kept, dir)
			errs = append(errs, err)
		}
	}
	b.pins.old = kept
	if len(kept) == 0 && len(b.pins.adopted) == 0 && !b.pins.settled {
		b.pins.settled = true
		logger.L().Info("sandbox " + b.section.name + " settled after restart: every old set is covered")
	}
	return errors.Join(errs...)
}

// pruneOldSet removes from an old set's pinned binding map each cgroup that
// is covered (covered), so the set's links stop judging it, and reports
// whether no binding is left. One uncovered Strict cgroup no longer keeps
// the set judging the others (an Audit or removed policy never blocks). A set
// that was not validated, or whose bindings cannot be read, is kept whole
// (fail closed). Runs under mu.
func (b *nodeOwner[C]) pruneOldSet(dir string, past bool) (empty bool, err error) {
	if b.isUnvalidated(dir) {
		return false, nil
	}
	set := enforcement.PinnedSet{Dir: dir, Manifest: b.pins.sets[dir]}
	bindings, err := b.pins.bindingsOf(set)
	if err != nil {
		return false, nil
	}
	policies := map[uint32][]enforcement.PinnedPolicy{}
	for _, s := range set.Manifest.Slots {
		policies[s.Slot] = s.Policies
	}
	var errs []error
	left, changed := 0, false
	for cgroup, v := range bindings {
		if !b.covered(cgroup, policies[v.Slot], past) {
			left++
			continue
		}
		changed = true
		if err := b.pins.deleteBinding(set, cgroup); err != nil {
			left++
			errs = append(errs, fmt.Errorf("%s: removing cgroup %d: %w", filepath.Base(dir), cgroup, err))
		}
	}
	if changed {
		b.pins.linkAt = time.Time{} // report the old sets again
	}
	return left == 0, errors.Join(errs...)
}

// covered reports whether an old set's binding of cgroup may go: this run has
// a committed binding of the cgroup, or its plan is Audit, or, past the
// deadline with no plan, a complete snapshot was seen or the binding's
// policies are all gone from a complete listing. Runs under mu.
func (b *nodeOwner[C]) covered(cgroup uint64, policies []enforcement.PinnedPolicy, past bool) bool {
	// A committed binding protects only while the instance runs. When the
	// cgroup's wanted plan is Strict, only a committed Strict combination
	// covers it (a committed Audit binding whose Strict publish failed does
	// not).
	ready := b.instance != nil && b.instance.Ready() == nil
	wantStrict := false
	if want, ok := b.desired[cgroup]; ok {
		wantStrict = strictPolicies(want)
	}
	enough := func(combination string) bool {
		if !wantStrict {
			return true
		}
		policies, known := b.combinations[combination]
		return known && strictPolicies(policies)
	}
	for _, v := range b.bindings {
		if !ready {
			break
		}
		if v.binding.CgroupID == cgroup && !v.pendingUnbind && !v.bindFailed && enough(v.combination) {
			return true
		}
	}
	for _, p := range b.pods {
		if ready && p.pod.CgroupID == cgroup && !p.bindPending && !p.pendingUnbind && enough(p.combination) {
			return true
		}
	}
	strict, ok := b.currentStrict(cgroup)
	if ok {
		return !strict
	}
	return past && (b.pins.snapshotSeen || b.policiesGone(policies))
}

// SnapshotComplete tells the owner that the controller saw a complete
// binding snapshot: a cgroup with no plan of this section has no policy.
func (b *nodeOwner[C]) SnapshotComplete() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pins != nil {
		b.pins.snapshotSeen = true
	}
}

// currentStrict reports whether a current binding of this section covers the
// cgroup (ok), and whether its plan is Strict. A plan whose class is not
// known yet (no slot) counts as Strict: the kept binding fails closed.
// Runs under mu.
func (b *nodeOwner[C]) currentStrict(cgroup uint64) (strict, ok bool) {
	// The last plan the controller asked for, bound or not (a container
	// whose bind keeps failing still wants it).
	if policies, ok := b.desired[cgroup]; ok {
		return strictPolicies(policies), true
	}
	class := func(combination string) bool {
		policies, known := b.combinations[combination]
		return !known || strictPolicies(policies)
	}
	for _, v := range b.bindings {
		if v.binding.CgroupID == cgroup && !v.pendingUnbind {
			return class(v.combination), true
		}
	}
	for _, p := range b.pods {
		if p.pod.CgroupID == cgroup {
			return class(p.combination), true
		}
	}
	return false, false
}

// Adopted returns the policies of the previous run that adopted kernel
// bindings still enforce (sandboxpolicy.AdoptionReporter).
func (b *nodeOwner[C]) Adopted() []sandboxpolicy.AdoptedSlot {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pins == nil && b.survivalOff != nil {
		// Earlier runs' sets are kept and may enforce; this run cannot
		// tell what they hold.
		return []sandboxpolicy.AdoptedSlot{{Section: b.section.name, Unreadable: true, LinkError: b.survivalOff}}
	}
	if b.pins == nil || b.pins.settled {
		return nil
	}
	return b.adoptedNow()
}

// adoptedNow computes Adopted. Runs under mu.
func (b *nodeOwner[C]) adoptedNow() []sandboxpolicy.AdoptedSlot {
	// Each read at most once per adoptedTTL (a status read asks once per
	// policy), and again when the old sets change: the links of the old
	// sets must still run their programs (by link and program ID), so a
	// stale state is never reported as enforcing; and the old sets that
	// still judge with their own state are read from their pinned bindings.
	key := strings.Join(b.pins.old, "\x00")
	if b.pins.linkAt.IsZero() || time.Since(b.pins.linkAt) >= adoptedTTL || key != b.pins.oldKey {
		var linkErrs []error
		for _, dir := range b.pins.old {
			if m, ok := b.pins.sets[dir]; ok && b.pins.checkLinks != nil {
				if err := b.pins.checkLinks(enforcement.PinnedSet{Dir: dir, Manifest: m}); err != nil {
					linkErrs = append(linkErrs, fmt.Errorf("%s: %w", filepath.Base(dir), err))
				}
			}
		}
		b.pins.linkErr, b.pins.linkAt = errors.Join(linkErrs...), time.Now()
		b.pins.oldReport, b.pins.oldKey = b.oldSetReport(), key
	}
	linkErr := b.pins.linkErr
	var out []sandboxpolicy.AdoptedSlot
	if b.instance != nil && b.pins.restored {
		for slot, n := range b.instance.AdoptedBindings() {
			a := sandboxpolicy.AdoptedSlot{Section: b.section.name, Slot: slot, Bindings: n, Degraded: b.pins.deadline, LinkError: linkErr}
			if s, ok := b.pins.adopted[slot]; ok {
				fillAdopted(&a, s)
			} else if !b.slotUsed(slot) {
				// The previous run's manifest does not list the slot
				// (its update failed): its policies are not known.
				a.Unreadable = true
				a.LinkError = errors.Join(fmt.Errorf("adopted slot %d: the previous run's manifest does not list its policies", slot), linkErr)
			}
			out = append(out, a)
		}
	}
	for _, a := range b.pins.oldReport {
		a.Degraded = b.pins.deadline
		if !a.Unreadable {
			a.LinkError = linkErr
		}
		out = append(out, a)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Slot < out[j].Slot })
	return out
}

// oldSetReport reports the old sets that still judge with their own state:
// on the restored path the sets of another state (the restored state's own
// sets hold the instance's adopted bindings), otherwise every old set. Each
// set reports one entry per slot from its pinned bindings and its manifest;
// a set that was not validated, or whose bindings cannot be read, reports an
// Unreadable entry. Runs under mu.
func (b *nodeOwner[C]) oldSetReport() []sandboxpolicy.AdoptedSlot {
	var out []sandboxpolicy.AdoptedSlot
	var readErrs []error
	restored := b.instance != nil && b.pins.restored
	for _, dir := range b.pins.old {
		if err, bad := b.pins.unvalidated[dir]; bad {
			readErrs = append(readErrs, fmt.Errorf("%s not validated: %w", filepath.Base(dir), err))
			continue
		}
		m := b.pins.sets[dir]
		if restored && b.sameState(m) {
			continue
		}
		bindings, err := b.pins.bindingsOf(enforcement.PinnedSet{Dir: dir, Manifest: m})
		if err != nil {
			readErrs = append(readErrs, fmt.Errorf("%s bindings: %w", filepath.Base(dir), err))
			continue
		}
		counts := map[uint32]int{}
		for _, v := range bindings {
			counts[v.Slot]++
		}
		for slot, n := range counts {
			a := sandboxpolicy.AdoptedSlot{Section: b.section.name, Slot: slot, Bindings: n}
			found := false
			for _, s := range m.Slots {
				if s.Slot == slot {
					fillAdopted(&a, s)
					found = true
				}
			}
			if !found {
				a.Unreadable = true
				a.LinkError = fmt.Errorf("%s slot %d: the manifest does not list its policies", filepath.Base(dir), slot)
			}
			out = append(out, a)
		}
	}
	if len(readErrs) > 0 {
		out = append(out, sandboxpolicy.AdoptedSlot{Section: b.section.name, Unreadable: true, LinkError: errors.Join(readErrs...)})
	}
	return out
}

// fillAdopted sets the manifest fields of an adopted slot.
func fillAdopted(a *sandboxpolicy.AdoptedSlot, s enforcement.PinnedSlot) {
	a.Generation, a.Digest = s.Generation, s.Digest
	for _, p := range s.Policies {
		a.Policies = append(a.Policies, sandboxpolicy.PolicyRevision{Policy: sandboxpolicy.PolicyIdentity{UID: types.UID(p.UID), Namespace: p.Namespace, Name: p.Name}, Revision: p.Revision})
	}
}

// unpin removes the pins of a retiring instance before it stops.
func (b *nodeOwner[C]) unpin(instance NodeInstance) error {
	if b.pins == nil {
		return nil
	}
	dir, ok := b.pins.dirs[instance]
	if !ok {
		return nil
	}
	if err := b.pins.remove(dir); err != nil {
		return err
	}
	delete(b.pins.dirs, instance)
	return nil
}

// keepPinned makes Close keep the pins of instance: node-agent exits, and the
// kernel keeps enforcing until the next start.
func (b *nodeOwner[C]) keepPinned(instance NodeInstance) {
	if b.pins != nil {
		delete(b.pins.dirs, instance)
	}
}

// statePrefixes names the prefix of each section's state maps at
// enforcement.PinRoot (a restored state is pinned there again).
var statePrefixes = map[string]string{
	sandboxpolicy.SectionPrivilege: privruntime.MapPrefix,
	sandboxpolicy.SectionNetwork:   netruntime.MapPrefix,
	sandboxpolicy.SectionFile:      fileruntime.MapPrefix,
}

// RemoveRestartPins removes every pinned set under root, and the sections'
// state map pins at enforcement.PinRoot (the feature or a section is off, or
// an uninstall). With no section named, it removes them for every section.
// A running gadget keeps its maps: its programs hold them.
func RemoveRestartPins(root string, sections ...string) error {
	var errs []error
	if len(sections) == 0 {
		errs = append(errs, enforcement.RemovePinned(root))
		for _, prefix := range statePrefixes {
			errs = append(errs, removePinnedMaps(prefix))
		}
		return errors.Join(errs...)
	}
	for _, s := range sections {
		errs = append(errs, enforcement.RemovePinned(filepath.Join(root, s)))
		if prefix, ok := statePrefixes[s]; ok {
			errs = append(errs, removePinnedMaps(prefix))
		}
	}
	return errors.Join(errs...)
}

// RestartStatus reports whether this section's enforcement survives a
// node-agent restart: on (restart survival enabled), and the error of the
// last pin of this run's instance (the next restart would not keep
// enforcing).
func (b *nodeOwner[C]) RestartStatus() (sandboxpolicy.SectionRestart, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pins == nil {
		if b.survivalOff != nil {
			return sandboxpolicy.SectionRestart{Section: b.section.name, Err: b.survivalOff}, true
		}
		return sandboxpolicy.SectionRestart{}, false
	}
	err := errors.Join(b.pins.pinErr, b.pins.manifestErr)
	// Another node-agent may have removed the sets (an uninstall decision
	// of an old pod after the DaemonSet was renamed, or deleted and
	// recreated): look again on each read.
	var gone []string
	for _, dir := range b.pins.dirs {
		if b.pins.missing(dir) {
			gone = append(gone, filepath.Base(dir))
		}
	}
	if len(gone) > 0 {
		sort.Strings(gone)
		err = errors.Join(err, fmt.Errorf("pinned set %s removed from the host bpffs (an uninstall, or the DaemonSet renamed or recreated): enforcement does not survive the next restart", strings.Join(gone, ", ")))
	}
	return sandboxpolicy.SectionRestart{Section: b.section.name, Pinned: err == nil && len(b.pins.dirs) > 0, Err: err}, true
}

// pinnedDirMissing tells whether a pinned set's directory is gone (an
// unreadable one is not: that proves nothing).
func pinnedDirMissing(dir string) bool {
	_, err := os.Stat(dir)
	return errors.Is(err, os.ErrNotExist)
}

// oldSetLost is the denies counted by the old sets' programs: no process
// reads their ring buffers, so each is a verdict with no event. The total
// only grows: a removed set keeps its last count. readable is false while an
// old set's counters cannot be read, or an old set is not validated: the loss
// is then unknown, never zero (rates.go). Runs under mu.
func (b *nodeOwner[C]) oldSetLost() (total uint64, readable bool) {
	if b.pins == nil || b.pins.countersOf == nil {
		return 0, true
	}
	if b.pins.oldDenied == nil {
		b.pins.oldDenied, b.pins.oldBase = map[string]uint64{}, map[string]uint64{}
	}
	readable = true
	current := map[string]bool{}
	for _, dir := range b.pins.old {
		current[dir] = true
		if b.isUnvalidated(dir) {
			// Its links may judge, but its maps cannot be trusted: its
			// denies are not known.
			readable = false
			continue
		}
		c, err := b.pins.countersOf(enforcement.PinnedSet{Dir: dir, Manifest: b.pins.sets[dir]})
		if err != nil {
			if !b.pins.counterWarned[dir] {
				logger.L().Warning("sandbox "+b.section.name+" old set verdict counters unreadable: the lost verdicts are unknown", helpers.String("dir", dir), helpers.Error(err))
				if b.pins.counterWarned == nil {
					b.pins.counterWarned = map[string]bool{}
				}
				b.pins.counterWarned[dir] = true
			}
			readable = false
			continue
		}
		base, seen := b.pins.oldBase[dir]
		if !seen {
			// The denies before the first read: the previous run read
			// their events, or they happened while node-agent was down.
			b.pins.oldBase[dir] = c.Denied
			continue
		}
		if c.Denied > base && c.Denied-base > b.pins.oldDenied[dir] {
			b.pins.oldDenied[dir] = c.Denied - base
		}
	}
	total = b.pins.goneDenied
	for dir, n := range b.pins.oldDenied {
		if !current[dir] {
			b.pins.goneDenied += n
			total += n
			delete(b.pins.oldDenied, dir)
			delete(b.pins.oldBase, dir)
			continue
		}
		total += n
	}
	return total, readable
}
