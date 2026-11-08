// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"strings"
	"testing"
)

func validManifest() PinManifest {
	return PinManifest{Format: PinFormat, Section: "privilege", Instance: "privilege-1-1", Generation: 1, BootID: "boot",
		BindingMapID: 7, MapIDs: []uint32{7, 8},
		Links: []PinnedLink{{Pin: "link_00_a", LinkID: 1, ProgramID: 2, Program: "a", Tag: "t"}}}
}

func TestPinManifestRoundTrip(t *testing.T) {
	m := validManifest()
	data, err := m.encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != manifestSize {
		t.Fatalf("encoded size %d", len(data))
	}
	got, err := decodeManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.check("privilege", "privilege-1-1", "boot"); err != nil {
		t.Fatal(err)
	}
	if got.Links[0] != m.Links[0] || got.BindingMapID != 7 {
		t.Fatalf("round trip changed the manifest: %+v", got)
	}
}

func TestPinManifestTooLarge(t *testing.T) {
	m := validManifest()
	m.Image = strings.Repeat("x", manifestSize)
	if _, err := m.encode(); err == nil {
		t.Fatal("an oversized manifest must fail")
	}
}

func TestPinManifestCheckRejects(t *testing.T) {
	cases := map[string]func(*PinManifest){
		"other format":           func(m *PinManifest) { m.Format = PinFormat + 1 },
		"other section":          func(m *PinManifest) { m.Section = "file" },
		"other directory":        func(m *PinManifest) { m.Instance = "privilege-2-1" },
		"other boot":             func(m *PinManifest) { m.BootID = "old" },
		"no boot":                func(m *PinManifest) { m.BootID = "" },
		"no generation":          func(m *PinManifest) { m.Generation = 0 },
		"no links":               func(m *PinManifest) { m.Links = nil },
		"binding map not listed": func(m *PinManifest) { m.MapIDs = []uint32{8} },
		"duplicate pin":          func(m *PinManifest) { m.Links = append(m.Links, m.Links[0]) },
		"no tag":                 func(m *PinManifest) { m.Links[0].Tag = "" },
	}
	for name, change := range cases {
		m := validManifest()
		m.Links = append([]PinnedLink(nil), m.Links...)
		change(&m)
		if err := m.check("privilege", "privilege-1-1", "boot"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := decodeManifest([]byte("{not json")); err == nil {
		t.Error("a broken manifest must fail")
	}
}
