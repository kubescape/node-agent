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
	list   func(string) ([]string, error)
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
	// evicted names the old sets removed at start over maxOldSets.
	evicted []string
	// bindingsOf reads an old set's pinned bindings
	// (enforcement.PinnedBindings; replaced in tests).
	bindingsOf func(enforcement.PinnedSet) (map[uint64]enforcement.PinnedBinding, error)
	// snapshotSeen: the controller saw a complete binding snapshot since
	// the start, so a cgroup with no plan has no policy any more.
	snapshotSeen bool
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
	p := &pinning{root: root, bootID: bootID, run: time.Now().UnixNano(), remove: remove, list: list, dirs: map[NodeInstance]string{},
		adopted: map[uint32]enforcement.PinnedSlot{}, start: time.Now(), update: enforcement.UpdateManifest,
		sets: map[string]enforcement.PinManifest{}, checkLinks: enforcement.CheckPinnedLinks, restoredMaps: map[uint32]bool{},
		bindingsOf: enforcement.PinnedBindings, unvalidated: map[string]error{}}
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
	sort.Slice(sets, func(i, j int) bool {
		a, c := sets[i].Manifest, sets[j].Manifest
		if a.RunStart != c.RunStart {
			return a.RunStart < c.RunStart
		}
		if a.Generation != c.Generation {
			return a.Generation < c.Generation
		}
		return sets[i].Dir < sets[j].Dir
	})
	// Each old set keeps a link per hook, a kept unreadable one too: keep
	// the newest maxOldSets. A removed set may hold the only binding of a
	// container: until the section settles, status reports it. The newest
	// readable set always stays (it holds the state to restore), even when
	// the unreadable ones alone fill the budget.
	for len(sets) > 1 && len(sets)+len(p.unvalidated) > maxOldSets {
		logger.L().Warning("sandbox "+b.section.name+" too many pinned sets: the oldest is removed", helpers.String("dir", sets[0].Dir))
		errs = append(errs, remove(sets[0].Dir))
		p.evicted = append(p.evicted, filepath.Base(sets[0].Dir))
		sets = sets[1:]
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
	if remaining > 0 {
		return errors.Join(append(errs, b.writeManifest())...)
	}
	// At a converged Settle every old set goes. At the deadline (keep set),
	// only the sets that ran on the restored maps go; another state's set
	// (an older run, a fresh start that crashed before Settle) or an
	// unreadable set stays until every cgroup it binds is covered.
	var kept []string
	for _, dir := range b.pins.old {
		if keep != nil {
			if _, bad := b.pins.unvalidated[dir]; bad || !b.sameState(b.pins.sets[dir]) {
				if !b.oldSetCovered(dir, true) {
					kept = append(kept, dir)
					continue
				}
			}
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

// settleByDeadline runs at each Prepare. Without a restored state it removes
// each old set whose cgroups are all covered (settleOldSets). With one, once
// settleDeadline passed without a converged Settle, it decides on the adopted
// bindings: one is dropped when the current plan of its cgroup is Audit
// (Audit never blocks) or when no plan exists after a complete snapshot (the
// policy was removed); it is kept when the plan is Strict, or not known before
// a complete snapshot (fail closed). While any remains, the section is
// degraded. Runs under mu.
func (b *nodeOwner[C]) settleByDeadline() error {
	if b.pins == nil || b.pins.settled {
		return nil
	}
	past := time.Since(b.pins.start) >= settleDeadline
	if !b.pins.restored {
		err := b.settleOldSets(past)
		b.pins.deadline = past && len(b.pins.old) > 0
		return err
	}
	if b.instance == nil || b.instance.Ready() != nil || !past {
		return nil
	}
	err := b.settleAdopted(func(cgroup uint64, _ uint32, _ bool) bool {
		strict, ok := b.currentStrict(cgroup)
		if !ok {
			return !b.pins.snapshotSeen
		}
		return strict
	})
	remaining := 0
	for _, n := range b.instance.AdoptedBindings() {
		remaining += n
	}
	b.pins.deadline = remaining > 0 || len(b.pins.old) > 0
	return err
}

// settleOldSets removes each old set (of a state that was not restored)
// whose cgroups all have a committed binding of this run or an Audit plan, or,
// past the deadline, no plan after a complete snapshot. A set whose bindings
// cannot be read is kept (fail closed). When none remains, the section is
// settled. Runs under mu.
func (b *nodeOwner[C]) settleOldSets(past bool) error {
	var errs, kept = []error{}, []string{}
	for _, dir := range b.pins.old {
		if !b.oldSetCovered(dir, past) {
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

// oldSetCovered reports whether every cgroup the old set binds is covered. A
// set that was not validated, or whose bindings cannot be read, is never
// covered (fail closed). Runs under mu.
func (b *nodeOwner[C]) oldSetCovered(dir string, past bool) bool {
	if _, bad := b.pins.unvalidated[dir]; bad {
		return false
	}
	bindings, err := b.pins.bindingsOf(enforcement.PinnedSet{Dir: dir, Manifest: b.pins.sets[dir]})
	if err != nil {
		return false
	}
	for cgroup := range bindings {
		if !b.covered(cgroup, past) {
			return false
		}
	}
	return true
}

// covered reports whether an old set's binding of cgroup may go: this run has
// a committed binding of the cgroup, or its plan is Audit, or (past the
// deadline) no plan exists after a complete snapshot. Runs under mu.
func (b *nodeOwner[C]) covered(cgroup uint64, past bool) bool {
	for _, v := range b.bindings {
		if v.binding.CgroupID == cgroup && !v.pendingUnbind && !v.bindFailed {
			return true
		}
	}
	for _, p := range b.pods {
		if p.pod.CgroupID == cgroup && !p.bindPending && !p.pendingUnbind {
			return true
		}
	}
	strict, ok := b.currentStrict(cgroup)
	if ok {
		return !strict
	}
	return past && b.pins.snapshotSeen
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
	if len(b.pins.evicted) > 0 {
		readErrs = append(readErrs, fmt.Errorf("removed at start over the limit of %d old sets (their bindings may be unprotected until re-bound): %s", maxOldSets, strings.Join(b.pins.evicted, ", ")))
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

// RemoveRestartPins removes every pinned set under root (the feature or a
// section is off).
func RemoveRestartPins(root string, sections ...string) error {
	if len(sections) == 0 {
		return enforcement.RemovePinned(root)
	}
	var errs []error
	for _, s := range sections {
		errs = append(errs, enforcement.RemovePinned(filepath.Join(root, s)))
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
	return sandboxpolicy.SectionRestart{Section: b.section.name, Pinned: err == nil && len(b.pins.dirs) > 0, Err: err}, true
}
