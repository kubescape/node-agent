package igbackend

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
// back for the first load (enforcement.RestoreState): the new instance judges
// with the same state from its first program on, and the old set's links are
// removed as soon as the new instance is pinned. The containers then bind
// again with live writes; the kernel bindings of the previous run that no
// container takes over are "adopted". Settle drops them after a refresh that
// converged. After settleDeadline it decides per adopted binding from the
// current plan of its cgroup: it keeps the binding only when a current binding
// of this section covers that cgroup with a Strict plan (fail closed), drops
// it when the plan is now Audit or the container has no plan of this section
// any more, and the section reports itself degraded while any remains. Until
// then the section reports AdoptedLastGood.

// settleDeadline bounds how long adopted bindings stay undecided after a start.
const settleDeadline = 2 * time.Minute

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
	// would not keep enforcing.
	pinErr error
}

// RestartSurvival pins the section's instance under root/<section> and
// restores the state a previous node-agent pinned there. Call it once, before
// the first Prepare or Replace.
//
// When the sets cannot be read, restart survival stays off for this run and
// the section's sets are removed, as with the feature off: kept, nothing would
// settle them, and they would deny stale policy until a reboot.
func (b *nodeOwner[C]) RestartSurvival(root string) error {
	bootID, err := enforcement.BootID()
	if err != nil {
		dir := filepath.Join(root, b.section.name)
		return errors.Join(err, enforcement.RemovePinned(dir))
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
		return errors.Join(err, remove(root))
	}
	p := &pinning{root: root, bootID: bootID, run: time.Now().UnixNano(), remove: remove, list: list, dirs: map[NodeInstance]string{},
		adopted: map[uint32]enforcement.PinnedSlot{}, start: time.Now(), update: enforcement.UpdateManifest,
		sets: map[string]enforcement.PinManifest{}, checkLinks: enforcement.CheckPinnedLinks}
	var errs []error
	for dir, reason := range rejected {
		logger.L().Warning("sandbox "+b.section.name+" pinned set not adopted, removed", helpers.String("dir", dir), helpers.Error(reason))
		errs = append(errs, remove(dir))
	}
	for _, s := range sets {
		p.old = append(p.old, s.Dir)
		p.sets[s.Dir] = s.Manifest
	}
	if len(sets) > 0 {
		// The newest set holds the state to keep.
		sort.Slice(sets, func(i, j int) bool {
			return sets[i].Manifest.Generation < sets[j].Manifest.Generation || sets[i].Dir < sets[j].Dir
		})
		newest := sets[len(sets)-1]
		if err := restore(newest); err != nil {
			// Start from fresh state; the old links keep their own state
			// until Settle.
			errs = append(errs, fmt.Errorf("%s: restoring the pinned state: %w", b.section.name, err))
		} else {
			p.restored = true
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
	var errs []error
	var kept []string
	for _, dir := range b.pins.old {
		if err := b.pins.remove(dir); err != nil {
			kept = append(kept, dir)
			errs = append(errs, err)
		}
	}
	b.pins.old = kept
	return errors.Join(errs...)
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
	if err := p.Pin(ctx, dir, enforcement.PinManifest{BootID: b.pins.bootID, Slots: b.pinnedSlots()}); err != nil {
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
	return b.pins.update(dir, func(m *enforcement.PinManifest) { m.Slots = slots })
}

// Settle runs after a refresh that converged: every binding of the current
// plans is committed. It drops the adopted kernel bindings, frees the slots
// only they used, and removes the sets of previous runs. It assumes one
// node-agent per node (a DaemonSet starts the new pod after the old one is
// gone).
func (b *nodeOwner[C]) Settle(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pins == nil || b.closed || b.instance == nil || b.instance.Ready() != nil {
		return nil // a failed instance protects nothing: keep the last-good state
	}
	return b.settleAdopted(nil)
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
	var kept []string
	for _, dir := range b.pins.old {
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

// settleByDeadline decides on the adopted bindings once settleDeadline
// passed without a converged refresh: one is kept only when a current
// binding of this section covers its cgroup with a Strict plan (fail
// closed); it is dropped when that plan is now Audit, or when no current
// binding covers the cgroup (the container is gone or has no policy of this
// section). Audit never blocks. While any remains, the section is degraded.
// Runs under mu.
func (b *nodeOwner[C]) settleByDeadline() error {
	if b.pins == nil || b.pins.settled || b.instance == nil || b.instance.Ready() != nil || time.Since(b.pins.start) < settleDeadline {
		return nil
	}
	err := b.settleAdopted(func(cgroup uint64, _ uint32, _ bool) bool {
		strict, ok := b.currentStrict(cgroup)
		return ok && strict
	})
	remaining := 0
	for _, n := range b.instance.AdoptedBindings() {
		remaining += n
	}
	b.pins.deadline = remaining > 0
	return err
}

// currentStrict reports whether a current binding of this section covers the
// cgroup (ok), and whether its plan is Strict. A plan whose class is not
// known yet (no slot) counts as Strict: the kept binding fails closed.
// Runs under mu.
func (b *nodeOwner[C]) currentStrict(cgroup uint64) (strict, ok bool) {
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
	if b.pins == nil || b.pins.settled || b.instance == nil {
		return nil
	}
	counts := b.instance.AdoptedBindings()
	// Each read: the links of the old sets that still exist must still run
	// their programs (by link and program ID), so a stale state is never
	// reported as enforcing.
	var linkErrs []error
	for _, dir := range b.pins.old {
		if m, ok := b.pins.sets[dir]; ok && b.pins.checkLinks != nil {
			if err := b.pins.checkLinks(enforcement.PinnedSet{Dir: dir, Manifest: m}); err != nil {
				linkErrs = append(linkErrs, fmt.Errorf("%s: %w", filepath.Base(dir), err))
			}
		}
	}
	linkErr := errors.Join(linkErrs...)
	var out []sandboxpolicy.AdoptedSlot
	for slot, n := range counts {
		s, ok := b.pins.adopted[slot]
		a := sandboxpolicy.AdoptedSlot{Section: b.section.name, Slot: slot, Bindings: n, Degraded: b.pins.deadline, LinkError: linkErr}
		if ok {
			a.Generation, a.Digest = s.Generation, s.Digest
			for _, p := range s.Policies {
				a.Policies = append(a.Policies, sandboxpolicy.PolicyRevision{Policy: sandboxpolicy.PolicyIdentity{UID: types.UID(p.UID), Namespace: p.Namespace, Name: p.Name}, Revision: p.Revision})
			}
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slot < out[j].Slot })
	return out
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
		return sandboxpolicy.SectionRestart{}, false
	}
	return sandboxpolicy.SectionRestart{Section: b.section.name, Pinned: b.pins.pinErr == nil && len(b.pins.dirs) > 0, Err: b.pins.pinErr}, true
}
