// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// PinFormat is the layout version of a pinned instance set. A set with another
// version is never adopted.
const PinFormat = 3

// manifestSize is the value size of the manifest map.
const manifestSize = 16384

// Names inside one pinned set directory. bpffs refuses names with a dot.
const (
	linkPin     = "link_"
	mapPin      = "map_"
	manifestPin = "manifest"
	// pendingSuffix marks a set whose manifest is not written yet.
	pendingSuffix = "_tmp"
)

// PinManifest identifies one pinned gadget instance. It is written last, so a
// set without it is incomplete. The identity fields (all but Slots) are
// written once, when the set is pinned; the owner rewrites Slots after each
// publication (UpdateManifest), so the map is not frozen. Authentication uses
// only the identity fields.
type PinManifest struct {
	Format     int    `json:"format"`
	Section    string `json:"section"`
	Instance   string `json:"instance"`
	Generation uint64 `json:"generation"`
	// Image and ImageDigest name the gadget image that pinned the set; a
	// state is restored only into the same image.
	Image       string `json:"image,omitempty"`
	ImageDigest string `json:"imageDigest,omitempty"`
	// RunStart is when the node-agent process that pinned the set started
	// (Unix nanoseconds): it orders the sets of different runs (Generation
	// restarts at 1 in every process).
	RunStart int64 `json:"runStart"`
	// BootID is the host boot id. bpffs does not survive a reboot; a set
	// with another boot id is not this host's.
	BootID       string `json:"bootID"`
	BindingMapID uint32 `json:"bindingMapID"`
	// MapIDs are the maps of the instance. Each pinned program uses one.
	MapIDs []uint32     `json:"mapIDs"`
	Links  []PinnedLink `json:"links"`
	// StateMaps are the section's state maps (../pin.h), pinned in the set
	// so the next start can pin them back for its load (RestoreState).
	StateMaps []PinnedMap `json:"stateMaps"`
	// Slots are the published slots and the policies they hold, for the
	// status of an adopted state. The owner keeps it current.
	Slots []PinnedSlot `json:"slots,omitempty"`
}

// PinnedMap is one pinned state map of the instance.
type PinnedMap struct {
	Pin   string `json:"pin"`
	Name  string `json:"name"`
	MapID uint32 `json:"mapID"`
}

// PinnedSlot is one published slot of the instance.
type PinnedSlot struct {
	Slot       uint32         `json:"slot"`
	Generation uint64         `json:"generation"`
	Digest     string         `json:"digest"`
	Policies   []PinnedPolicy `json:"policies"`
}

// PinnedPolicy names one policy of a slot.
type PinnedPolicy struct {
	UID       string `json:"uid"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Revision  string `json:"revision"`
}

// PinnedLink is one attached program of the instance.
type PinnedLink struct {
	Pin       string `json:"pin"`
	LinkID    uint32 `json:"linkID"`
	ProgramID uint32 `json:"programID"`
	Program   string `json:"program"`
	Tag       string `json:"tag"`
}

func (m PinManifest) encode() ([]byte, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if len(data) > manifestSize {
		return nil, fmt.Errorf("pin manifest is %d bytes, more than %d", len(data), manifestSize)
	}
	out := make([]byte, manifestSize)
	copy(out, data)
	return out, nil
}

func decodeManifest(value []byte) (PinManifest, error) {
	var m PinManifest
	if err := json.Unmarshal(bytes.TrimRight(value, "\x00"), &m); err != nil {
		return m, fmt.Errorf("pin manifest: %w", err)
	}
	return m, nil
}

// check validates the manifest fields that do not need the kernel.
func (m PinManifest) check(section, instance, bootID string) error {
	switch {
	case m.Format != PinFormat:
		return fmt.Errorf("pin format %d, want %d", m.Format, PinFormat)
	case m.Section != section:
		return fmt.Errorf("pinned section %q, want %q", m.Section, section)
	case m.Instance != instance:
		return fmt.Errorf("pinned instance %q in directory %q", m.Instance, instance)
	case m.BootID == "" || m.BootID != bootID:
		return fmt.Errorf("pinned set from boot %q, host boot is %q", m.BootID, bootID)
	case m.Generation == 0 || m.BindingMapID == 0 || len(m.Links) == 0 || !slices.Contains(m.MapIDs, m.BindingMapID) || len(m.StateMaps) == 0:
		return fmt.Errorf("incomplete pin manifest")
	}
	bindingState := false
	for _, sm := range m.StateMaps {
		if sm.Pin != mapPin+sm.Name || sm.MapID == 0 || !slices.Contains(m.MapIDs, sm.MapID) {
			return fmt.Errorf("invalid pinned state map %+v", sm)
		}
		if strings.HasSuffix(sm.Name, BindingsMap) {
			if sm.MapID != m.BindingMapID {
				return fmt.Errorf("pinned binding map %s is map %d, manifest binding map is %d", sm.Name, sm.MapID, m.BindingMapID)
			}
			bindingState = true
		}
	}
	if !bindingState {
		return fmt.Errorf("the pinned state has no binding map")
	}
	pins := map[string]bool{}
	for _, l := range m.Links {
		if l.Pin == "" || pins[l.Pin] || l.LinkID == 0 || l.ProgramID == 0 || l.Tag == "" {
			return fmt.Errorf("invalid pinned link %+v", l)
		}
		pins[l.Pin] = true
	}
	return nil
}

// PinnedBinding is one kernel binding of a pinned set.
type PinnedBinding struct {
	Slot   uint32
	Strict bool
}
