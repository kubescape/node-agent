package igbackend

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
)

// Restart survival. A node owner pins its current instance on bpffs, so the
// kernel keeps enforcing when node-agent exits (clean, SIGKILL or OOM). At the
// next start the owner adopts the pinned sets as last-good protection: they
// keep enforcing while the new instance starts and the containers bind again
// (both enforce, as in a replacement). A set that does not authenticate is not
// trusted to run and is removed at once. Settle removes the adopted sets once
// the controller has converged, and from then on the owner pins each new
// instance and unpins the one it replaces. Pins change only at start, settle
// and replacement, so a crash loop does not add sets.

// pinner is a NodeInstance that can pin itself (see enforcement.PinInstance).
type pinner interface {
	Pin(ctx context.Context, dir string, m enforcement.PinManifest) error
}

// pinning is the restart survival state of a node owner.
type pinning struct {
	// root is the section's directory on bpffs.
	root   string
	bootID string
	// run makes the set names of this process unique.
	run    int64
	remove func(string) error
	// list returns the set directories under root.
	list func(string) ([]string, error)
	// adopted are the authenticated sets of a previous run, removed at settle.
	adopted []string
	settled bool
	// dirs are the pinned instances of this run.
	dirs map[NodeInstance]string
}

// RestartSurvival pins the section's instance under root/<section> and adopts
// the sets a previous node-agent pinned there. Call it once, before the first
// Prepare or Replace.
func (b *nodeOwner[C]) RestartSurvival(root string) error {
	bootID, err := enforcement.BootID()
	if err != nil {
		return err
	}
	return b.enablePins(filepath.Join(root, b.section.name), bootID, enforcement.LoadPinned, enforcement.RemovePinned, listDirs)
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

func (b *nodeOwner[C]) enablePins(root, bootID string, load func(root, section string) ([]enforcement.PinnedSet, map[string]error, error), remove func(string) error, list func(string) ([]string, error)) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pins != nil {
		return fmt.Errorf("%s restart survival already enabled", b.section.name)
	}
	sets, rejected, err := load(root, b.section.name)
	if err != nil {
		return err
	}
	p := &pinning{root: root, bootID: bootID, run: time.Now().UnixNano(), remove: remove, list: list, dirs: map[NodeInstance]string{}}
	for _, s := range sets {
		p.adopted = append(p.adopted, s.Dir)
		logger.L().Info("sandbox "+b.section.name+" adopted a pinned instance", helpers.String("dir", s.Dir),
			helpers.String("instance", s.Manifest.Instance), helpers.String("generation", fmt.Sprint(s.Manifest.Generation)))
	}
	var errs []error
	for dir, reason := range rejected {
		logger.L().Warning("sandbox "+b.section.name+" pinned set not adopted, removed", helpers.String("dir", dir), helpers.Error(reason))
		errs = append(errs, remove(dir))
	}
	b.pins = p
	return errors.Join(errs...)
}

// Settle runs after a refresh that converged: every binding of the current
// plans is committed. It pins the current instance and removes every other set
// in the section directory: the adopted ones, and any left by a run that could
// not settle. Until then they stay: removing them earlier could leave a
// container without the protection it had. It assumes one node-agent per node
// (a DaemonSet starts the new pod after the old one is gone).
func (b *nodeOwner[C]) Settle(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pins == nil || b.closed {
		return nil
	}
	if b.instance != nil {
		if err := b.instance.Ready(); err != nil {
			return nil // a failed instance protects nothing: keep the last-good sets
		}
		if err := b.pin(ctx, b.instance); err != nil {
			return err
		}
	} else if len(b.bindings) > 0 || len(b.pods) > 0 {
		return nil
	}
	dirs, err := b.pins.list(b.pins.root)
	if err != nil {
		return err
	}
	own := map[string]bool{}
	for _, dir := range b.pins.dirs {
		own[dir] = true
	}
	var kept []string
	var errs []error
	for _, dir := range dirs {
		if own[dir] {
			continue
		}
		if err := b.pins.remove(dir); err != nil {
			kept = append(kept, dir)
			errs = append(errs, err)
		}
	}
	b.pins.adopted = kept
	if !b.pins.settled && len(kept) == 0 {
		b.pins.settled = true
		logger.L().Info("sandbox " + b.section.name + " settled after restart")
	}
	return errors.Join(errs...)
}

// pin pins instance once. A failure keeps enforcement as it is; only the
// survival of the next restart is missing, and the next Settle retries.
func (b *nodeOwner[C]) pin(ctx context.Context, instance NodeInstance) error {
	if _, done := b.pins.dirs[instance]; done {
		return nil
	}
	p, ok := instance.(pinner)
	if !ok {
		return fmt.Errorf("%s instance cannot be pinned", b.section.name)
	}
	dir := filepath.Join(b.pins.root, fmt.Sprintf("%s-%d-%d", b.section.name, b.pins.run, b.generation))
	if err := p.Pin(ctx, dir, enforcement.PinManifest{BootID: b.pins.bootID}); err != nil {
		return fmt.Errorf("pinning %s instance: %w", b.section.name, err)
	}
	b.pins.dirs[instance] = dir
	return nil
}

// pinReplacement pins a new current instance after settle (before settle the
// adopted sets are the last-good state).
func (b *nodeOwner[C]) pinReplacement(ctx context.Context) {
	if b.pins == nil || !b.pins.settled {
		return
	}
	if err := b.pin(ctx, b.instance); err != nil {
		logger.L().Warning("sandbox "+b.section.name+" instance not pinned", helpers.Error(err))
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
// kernel keeps enforcing until the next start settles.
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
