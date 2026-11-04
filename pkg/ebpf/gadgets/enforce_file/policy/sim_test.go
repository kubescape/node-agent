// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package filepolicy

import (
	"strings"
	"testing"
)

// A Go copy of the kernel matcher and decision (../file_policy.h), working on
// the compiled map content only: literal lookups by {slot, hash}, globs by
// prefix and suffix hashes, the same NFA step. harness_test.go checks that
// the C code gives the same results.

type sim struct {
	c        Compiled
	literals map[LiteralKey]Bits
}

func newSim(c Compiled) *sim {
	s := &sim{c: c, literals: map[LiteralKey]Bits{}}
	for _, l := range c.Literals {
		s.literals[l.Key] = l.Bits
	}
	return s
}

func components(path string) []string {
	var out []string
	for _, c := range strings.Split(path, "/") {
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

// match returns the accept bits of every pattern of the slot that matches.
func (s *sim) match(slot uint32, path string) Bits {
	v := &s.c.Slots[slot]
	d := v.Init
	first := true
	for _, comp := range components(path) {
		b := v.Wild.or(s.literals[LiteralKey{Slot: slot, Hash: Hash(v.Seed, comp)}])
		for _, g := range v.Globs[:v.NGlobs] {
			pl, sl := int(g.PreLen), int(g.SufLen)
			if pl+sl > len(comp) {
				continue
			}
			if Hash(v.Seed, comp[:pl]) == g.PreHash && HashReverse(v.Seed, comp[len(comp)-sl:]) == g.SufHash {
				b = b.or(g.Bits)
			}
		}
		shl := d.shl1().andNot(v.First)
		if first {
			shl = shl.or(v.First)
		}
		d = shl.and(b).or(d.and(v.Star))
		d = d.or(d.shl1().and(v.Star).andNot(v.First))
		first = false
	}
	return d.and(v.Accept)
}

type outcome struct {
	rank      uint8
	ruleID    uint32
	isDefault bool
}

// decide mirrors file_decide; access AccessMoveSource is the guard.
func (s *sim) decide(slot uint32, access int, matched Bits, fromImage bool) outcome {
	v := &s.c.Slots[slot]
	var out outcome
	docs, allowed := uint32(0), false
	for _, r := range v.Rules[:v.NRules] {
		var hit bool
		if access < KernelAccessKinds {
			if r.Access&(1<<access) == 0 {
				continue
			}
			hit = r.Flags&RuleAnyPath != 0 || matched.intersects(r.Match)
		} else {
			if r.Flags&RuleGuard == 0 {
				continue
			}
			hit = matched.intersects(r.Guard)
		}
		if !hit || matched.intersects(r.Except) || (r.Flags&RuleFromImage != 0 && !fromImage) {
			continue
		}
		docs |= 1 << (r.Doc & 31)
		if r.Rank == RankAllow {
			allowed = true
		}
		if r.Rank > out.rank {
			out = outcome{rank: r.Rank, ruleID: r.RuleID}
		}
	}
	if access >= KernelAccessKinds {
		return out
	}
	def := v.Defaults[access]
	if out.rank == RankNone {
		return outcome{rank: def.Rank, ruleID: def.RuleID, isDefault: true}
	}
	if !allowed && v.DenyEnforceDocs[access]&^docs != 0 && out.rank < RankDenyEnforce {
		return outcome{rank: RankDenyEnforce, ruleID: def.RuleID, isDefault: true}
	}
	return out
}

// decideMask mirrors file_decide_mask: the most limiting result over the
// access kinds (bits) in mask, and the kind that gave it.
func (s *sim) decideMask(slot uint32, mask int, matched Bits, fromImage bool) (outcome, int) {
	var best outcome
	access := 0
	for a := 0; a <= AccessMoveSource; a++ {
		if mask&(1<<a) == 0 {
			continue
		}
		if o := s.decide(slot, a, matched, fromImage); o.rank > best.rank {
			best, access = o, a
		}
	}
	return best, access
}

// moveSource judges a path as the old name of a rename or a hard link.
func (s *sim) moveSource(slot uint32, path string, fromImage bool) (outcome, int) {
	return s.decideMask(slot, MoveSourceMask, s.match(slot, path), fromImage)
}

// judge returns the rank of one access kind on a path.
func (s *sim) judge(slot uint32, access string, path string, fromImage bool) outcome {
	return s.decide(slot, accessIndex(access), s.match(slot, path), fromImage)
}

func compileOne(t *testing.T, d Document) *sim {
	t.Helper()
	c, err := CompileKernel(d, 1)
	if err != nil {
		t.Fatal(err)
	}
	return newSim(c)
}
