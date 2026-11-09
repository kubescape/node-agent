// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// Restart survival. The eBPF operator holds the links of an instance only as
// file descriptors, so the programs detach when the process exits. PinInstance
// pins them on bpffs: the kernel keeps them attached, with the maps they use,
// until the pins are removed. A later process authenticates the set with
// LoadPinned and removes it with RemovePinned once its own instance covers.

// BootID returns the host boot id.
func BootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// IsBPFFS reports whether dir is on a bpffs mount.
func IsBPFFS(dir string) bool {
	var st unix.Statfs_t
	return unix.Statfs(dir, &st) == nil && uint32(st.Type) == unix.BPF_FS_MAGIC
}

type ownedLink struct {
	link    link.Link
	linkID  link.ID
	program ebpf.ProgramID
	name    string
	tag     string
	kind    ebpf.ProgramType
}

// ownedLinks returns the links on the host whose program uses only maps in
// maps (and at least one). The maps of a gadget instance are created for it
// alone, so these are exactly the instance's links; a program that also used a
// shared map would be left out, and the receipt count in PinInstance fails.
//
// The walk covers every link on the host, and the kernel answers EAGAIN for a
// link that is being created or freed (another gadget, or a set removed just
// before). The link iterator stops at that error, so the walk is retried.
func ownedLinks(maps map[ebpf.MapID]bool) ([]ownedLink, error) {
	for attempt := 0; ; attempt++ {
		out, err := walkOwnedLinks(maps)
		if err == nil || !errors.Is(err, unix.EAGAIN) || attempt == ownedLinksRetries {
			return out, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// ownedLinksRetries bounds the walk retries (about one second in all).
const ownedLinksRetries = 20

func walkOwnedLinks(maps map[ebpf.MapID]bool) ([]ownedLink, error) {
	var out []ownedLink
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
		if err != nil {
			continue
		}
		ids, _ := pi.MapIDs()
		if len(ids) == 0 || slices.ContainsFunc(ids, func(id ebpf.MapID) bool { return !maps[id] }) {
			continue
		}
		out = append(out, ownedLink{link: it.Take(), linkID: it.ID, program: info.Program, name: pi.Name, tag: pi.Tag, kind: pi.Type})
	}
	if err := it.Err(); err != nil {
		closeLinks(out)
		return nil, err
	}
	return out, nil
}

func closeLinks(links []ownedLink) {
	for _, l := range links {
		_ = l.link.Close()
	}
}

func mapID(m *ebpf.Map) (ebpf.MapID, error) {
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

// PinInstance pins the attached programs and the binding map of the running
// instance of gc under dir, then writes the manifest. It fills Format,
// Instance, MapIDs, BindingMapID and Links of m. Call it only when the instance is ready:
// every program is attached then. The set is built under dir+"_tmp" and renamed
// last, so a crash leaves no set that looks complete.
func PinInstance(gc operators.GadgetContext, dir string, m PinManifest) (err error) {
	value, _ := gc.GetVar(operators.NativeResourcesKey)
	resources, ok := value.(*operators.NativeResources)
	if !ok || resources == nil {
		return fmt.Errorf("no native resource manifest")
	}
	owned := map[ebpf.MapID]bool{}
	m.MapIDs = nil
	var bindings *ebpf.Map
	for name := range resources.Maps {
		value, _ := gc.GetVar(operators.MapPrefix + name)
		bpfMap, ok := value.(*ebpf.Map)
		if !ok || bpfMap == nil {
			return fmt.Errorf("missing BPF map %s", name)
		}
		id, err := mapID(bpfMap)
		if err != nil {
			return fmt.Errorf("map %s: %w", name, err)
		}
		owned[id] = true
		m.MapIDs = append(m.MapIDs, uint32(id))
		if name == "bindings" {
			bindings, m.BindingMapID = bpfMap, uint32(id)
		}
	}
	if bindings == nil {
		return fmt.Errorf("missing BPF map bindings")
	}
	// IG publishes one receipt for each attached LSM or tracing program.
	receipts := 0
	for name := range resources.Programs {
		value, _ := gc.GetVar(operators.NativeAttachmentPrefix + name)
		if receipt, ok := value.(*operators.NativeAttachment); ok && receipt != nil {
			receipts++
		}
	}
	links, err := ownedLinks(owned)
	if err != nil {
		return err
	}
	defer closeLinks(links)
	traced := 0
	for _, l := range links {
		if l.kind == ebpf.LSM || l.kind == ebpf.Tracing {
			traced++
		}
	}
	if receipts == 0 || traced != receipts {
		return fmt.Errorf("found %d LSM or tracing links of the instance, IG attached %d", traced, receipts)
	}

	pending := dir + pendingSuffix
	if err := RemovePinned(pending); err != nil {
		return err
	}
	if err := os.MkdirAll(pending, 0o700); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, RemovePinned(pending))
		}
	}()
	m.Links = m.Links[:0]
	for i, l := range links {
		pin := fmt.Sprintf("%s%02d_%s", linkPin, i, l.name)
		if err := l.link.Pin(filepath.Join(pending, pin)); err != nil {
			return fmt.Errorf("pinning link of %s: %w", l.name, err)
		}
		m.Links = append(m.Links, PinnedLink{Pin: pin, LinkID: uint32(l.linkID), ProgramID: uint32(l.program), Program: l.name, Tag: l.tag})
	}
	clone, err := bindings.Clone()
	if err != nil {
		return err
	}
	err = clone.Pin(filepath.Join(pending, bindingPin))
	_ = clone.Close()
	if err != nil {
		return fmt.Errorf("pinning binding map: %w", err)
	}
	m.Format, m.Instance = PinFormat, filepath.Base(dir)
	data, err := m.encode()
	if err != nil {
		return err
	}
	manifest, err := ebpf.NewMap(&ebpf.MapSpec{Name: "ks_pin_manifest", Type: ebpf.Array, KeySize: 4, ValueSize: manifestSize, MaxEntries: 1})
	if err != nil {
		return err
	}
	defer manifest.Close()
	if err := manifest.Put(uint32(0), data); err != nil {
		return err
	}
	if err := manifest.Freeze(); err != nil {
		return err
	}
	if err := manifest.Pin(filepath.Join(pending, manifestPin)); err != nil {
		return err
	}
	return os.Rename(pending, dir)
}

// PinnedSet is a pinned instance set that passed LoadPinned's checks.
type PinnedSet struct {
	Dir      string
	Manifest PinManifest
}

// LoadPinned reads the pinned sets of a section under root (one directory per
// instance). It returns the sets that authenticate, and the directories that do
// not, with the reason. A set authenticates when its manifest is readable and
// matches the section, the directory and the boot; each pinned link still runs
// the program and tag of the manifest, and that program uses only maps of the
// instance; the pinned binding map is the manifest's; and the directory holds no pin the manifest does not list.
func LoadPinned(root, section string) ([]PinnedSet, map[string]error, error) {
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	bootID, err := BootID()
	if err != nil {
		return nil, nil, err
	}
	var sets []PinnedSet
	rejected := map[string]error{}
	for _, e := range entries {
		dir := filepath.Join(root, e.Name())
		if !e.IsDir() || strings.HasSuffix(e.Name(), pendingSuffix) {
			rejected[dir] = fmt.Errorf("incomplete pinned set")
			continue
		}
		m, err := authenticate(dir, section, bootID)
		if err != nil {
			rejected[dir] = err
			continue
		}
		sets = append(sets, PinnedSet{Dir: dir, Manifest: m})
	}
	return sets, rejected, nil
}

func authenticate(dir, section, bootID string) (PinManifest, error) {
	readOnly := &ebpf.LoadPinOptions{ReadOnly: true}
	manifest, err := ebpf.LoadPinnedMap(filepath.Join(dir, manifestPin), readOnly)
	if err != nil {
		return PinManifest{}, err
	}
	defer manifest.Close()
	if manifest.Type() != ebpf.Array || manifest.KeySize() != 4 || manifest.ValueSize() != manifestSize || manifest.MaxEntries() != 1 {
		return PinManifest{}, fmt.Errorf("invalid manifest map layout")
	}
	data := make([]byte, manifestSize)
	if err := manifest.Lookup(uint32(0), &data); err != nil {
		return PinManifest{}, err
	}
	m, err := decodeManifest(data)
	if err != nil {
		return m, err
	}
	if err := m.check(section, filepath.Base(dir), bootID); err != nil {
		return m, err
	}
	bindings, err := ebpf.LoadPinnedMap(filepath.Join(dir, bindingPin), readOnly)
	if err != nil {
		return m, err
	}
	id, err := mapID(bindings)
	_ = bindings.Close()
	if err != nil {
		return m, err
	}
	if uint32(id) != m.BindingMapID {
		return m, fmt.Errorf("pinned binding map is %d, manifest says %d", id, m.BindingMapID)
	}
	maps := map[uint32]bool{}
	for _, id := range m.MapIDs {
		maps[id] = true
	}
	listed := map[string]bool{manifestPin: true, bindingPin: true}
	for _, want := range m.Links {
		listed[want.Pin] = true
		if err := checkLink(filepath.Join(dir, want.Pin), want, maps); err != nil {
			return m, err
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return m, err
	}
	for _, e := range entries {
		if !listed[e.Name()] {
			return m, fmt.Errorf("unlisted pin %s", e.Name())
		}
	}
	return m, nil
}

func checkLink(path string, want PinnedLink, maps map[uint32]bool) error {
	// Links refuse the read-only open flag.
	l, err := link.LoadPinnedLink(path, nil)
	if err != nil {
		return err
	}
	defer l.Close()
	info, err := l.Info()
	if err != nil {
		return err
	}
	if uint32(info.ID) != want.LinkID || uint32(info.Program) != want.ProgramID {
		return fmt.Errorf("pinned link %s is link %d program %d, manifest says link %d program %d", want.Pin, info.ID, info.Program, want.LinkID, want.ProgramID)
	}
	prog, err := ebpf.NewProgramFromID(info.Program)
	if err != nil {
		return err
	}
	pi, err := prog.Info()
	_ = prog.Close()
	if err != nil {
		return err
	}
	ids, _ := pi.MapIDs()
	if pi.Tag != want.Tag {
		return fmt.Errorf("pinned link %s: program tag %s, manifest says %s", want.Pin, pi.Tag, want.Tag)
	}
	if len(ids) == 0 || slices.ContainsFunc(ids, func(id ebpf.MapID) bool { return !maps[uint32(id)] }) {
		return fmt.Errorf("pinned link %s: program uses a map outside the instance", want.Pin)
	}
	return nil
}

// RemovePinned removes a pinned set or a directory of sets. The links detach
// when their last pin and file descriptor are gone. A missing path is not an
// error.
func RemovePinned(path string) error {
	return os.RemoveAll(path)
}
