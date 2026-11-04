// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package filepolicy

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sort"
)

// Map ABI of ../file_policy.h and ../../common/policy.h. Keep in sync.
const (
	KernelMaxSlots    = 64
	KernelSegBits     = 256
	KernelSegWords    = KernelSegBits / 64
	KernelMaxRules    = 64
	KernelMaxGlobs    = 16
	KernelMaxLiterals = 16384
	KernelGlobPartMax = 16
	KernelMaxDocs     = 32
	KernelAccessKinds = 6
	KernelPathMax     = 4096
	KernelNameMax     = 255

	KernelSlotSize         = 8696
	KernelLiteralKeySize   = 16
	KernelLiteralValueSize = 32

	RankNone          = 0
	RankAllow         = 1
	RankDenyAudit     = 2
	RankDenyEnforce   = 3
	KernelModeOff     = 0
	KernelModeAudit   = 1
	KernelModeEnforce = 2

	RuleFromImage    = 1
	RuleAnyPath      = 2
	RuleGuard        = 4
	RuleNewNameGuard = 8

	// SlotFromImage is set by the owner, not the compiler, when the
	// kernel's overlay inode layout is the one the program reads.
	SlotFromImage = 1

	RuleIDDefault    = 1
	RuleIDUnresolved = 2

	// AccessMoveSource and AccessNewName index Unresolved, RuleUnion and
	// the event access field for the move-source and the new-name guard.
	AccessMoveSource = 6
	AccessNewName    = 7

	// MoveSourceMask is FILE_MOVE_SOURCE_MASK: the access kinds (bits)
	// judged on a move source. ReplacedMask is FILE_REPLACED_MASK: added
	// on a name whose file is replaced. NewFileMask is FILE_NEW_FILE_MASK:
	// added on a new name that does not exist yet. NewNameGuardMask is
	// FILE_NEW_NAME_GUARD_MASK: added on every new name.
	MoveSourceMask   = 1<<0 | 1<<1 | 1<<4 | 1<<AccessMoveSource
	ReplacedMask     = 1<<1 | 1<<3
	NewFileMask      = 1<<1 | 1<<2
	NewNameGuardMask = 1 << AccessNewName

	FNVPrime = 0x100000001b3
)

// Bits is struct file_bits: bit k is segment k.
type Bits [KernelSegWords]uint64

func (b *Bits) set(k int) { b[k/64] |= 1 << (k % 64) }
func (b Bits) and(o Bits) (r Bits) {
	for i := range b {
		r[i] = b[i] & o[i]
	}
	return
}
func (b Bits) or(o Bits) (r Bits) {
	for i := range b {
		r[i] = b[i] | o[i]
	}
	return
}
func (b Bits) andNot(o Bits) (r Bits) {
	for i := range b {
		r[i] = b[i] &^ o[i]
	}
	return
}
func (b Bits) shl1() (r Bits) {
	var c uint64
	for i := range b {
		r[i] = b[i]<<1 | c
		c = b[i] >> 63
	}
	return
}
func (b Bits) any() bool              { return b[0]|b[1]|b[2]|b[3] != 0 }
func (b Bits) intersects(o Bits) bool { return b.and(o).any() }

// PolicyValue matches struct policy_value.
type PolicyValue struct {
	Rank       uint8
	_          [3]uint8
	RuleID     uint32
	OriginID   uint32
	Mode       uint32
	Generation uint64
}

// GlobEntry matches struct file_glob.
type GlobEntry struct {
	Bits    Bits
	PreHash uint64
	SufHash uint64
	PreLen  uint8
	SufLen  uint8
	_       [6]uint8
}

// RuleEntry matches struct file_rule.
type RuleEntry struct {
	Match    Bits
	Except   Bits
	Guard    Bits
	RuleID   uint32
	OriginID uint32
	Access   uint8
	Rank     uint8
	Doc      uint8
	Flags    uint8
	_        uint32
}

// SlotValue matches struct file_slot.
type SlotValue struct {
	Generation uint64
	Seed       uint64
	Mode       uint32
	NRules     uint32
	NGlobs     uint32
	// Flags: SlotFromImage.
	Flags    uint32
	First    Bits
	Star     Bits
	Wild     Bits
	Accept   Bits
	Init     Bits
	Defaults [KernelAccessKinds]PolicyValue
	// Bit i: policy i of the slot has an enforce default deny.
	DenyEnforceDocs [KernelAccessKinds]uint32
	// Rank for an unresolved path, per access kind and guard.
	Unresolved [8]uint8
	// Per access kind and guard: a rule without paths judges it (never a
	// guard); the union of its rules' match bits (guard bits for a guard).
	AnyPath   [8]uint8
	RuleUnion [8]Bits
	Globs     [KernelMaxGlobs]GlobEntry
	Rules     [KernelMaxRules]RuleEntry
}

// LiteralKey matches struct file_literal_key.
type LiteralKey struct {
	Slot uint32
	_    uint32
	Hash uint64
}

type LiteralEntry struct {
	Key  LiteralKey
	Bits Bits
}

// Compiled is the frozen map content plus the id tables events refer to.
// RuleNames[0] and Origins[0] are empty: id 0 means none. RuleNames[1] is
// "default", RuleNames[2] is "unresolved-path".
type Compiled struct {
	Generation uint64
	// Slots holds one entry per policy slot (combination of policies).
	Slots     []SlotValue
	Literals  []LiteralEntry
	RuleNames []string
	Origins   []string
}

// Hash is the component hash of the kernel (file_hash_byte): FNV-1a 64 with
// the offset basis replaced by the slot seed.
func Hash(seed uint64, b string) uint64 {
	h := seed
	for i := 0; i < len(b); i++ {
		h = (h ^ uint64(b[i])) * FNVPrime
	}
	return h
}

// HashReverse hashes the bytes of b from the last to the first.
func HashReverse(seed uint64, b string) uint64 {
	h := seed
	for i := len(b) - 1; i >= 0; i-- {
		h = (h ^ uint64(b[i])) * FNVPrime
	}
	return h
}

// randomSeed picks a slot's hash seed; tests replace it.
var randomSeed = func() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b[:]), nil
}

func rank(action, mode string) uint8 {
	switch {
	case action == "allow":
		return RankAllow
	case mode == "enforce":
		return RankDenyEnforce
	default:
		return RankDenyAudit
	}
}

// accessMask returns the access bits of a rule: none listed means all.
func accessMask(kinds []string) uint8 {
	if len(kinds) == 0 {
		return 1<<KernelAccessKinds - 1
	}
	var m uint8
	for _, k := range kinds {
		m |= 1 << accessIndex(k)
	}
	return m
}

// CompileKernel compiles one policy into slot 0.
func CompileKernel(d Document, generation uint64) (Compiled, error) {
	return CompileSlots([][]Document{{d}}, generation)
}

// CompileSlots compiles one node instance. Each slot holds one combination of
// documents, merged per access kind by the shared contract
// (../../common/merge/CONTRACT.md):
//   - rules are the union, each with its own name, origin and mode; the most
//     limiting matching rule wins (deny enforce > deny audit > allow);
//   - the default of an access kind is deny if any document's default for it
//     is deny, else allow; its mode is the strictest among the documents
//     whose default equals it;
//   - when every matching rule denies, the enforce default deny of each
//     document without a matching rule still applies; an explicit allow still
//     beats another document's default deny.
func CompileSlots(slots [][]Document, generation uint64) (Compiled, error) {
	if generation == 0 {
		return Compiled{}, fmt.Errorf("generation must be nonzero")
	}
	if len(slots) == 0 || len(slots) > KernelMaxSlots {
		return Compiled{}, fmt.Errorf("%d policy combinations: need 1 to %d per node", len(slots), KernelMaxSlots)
	}
	c := &compiler{
		out:       Compiled{Generation: generation, RuleNames: []string{"", "default", "unresolved-path"}, Origins: []string{""}},
		originIDs: map[string]uint32{},
	}
	for slot, docs := range slots {
		if err := c.slot(uint32(slot), docs); err != nil {
			return Compiled{}, fmt.Errorf("policy combination %d: %w", slot, err)
		}
	}
	if len(c.out.Literals) > KernelMaxLiterals {
		return Compiled{}, fmt.Errorf("policies expand to %d literal path components (max %d)", len(c.out.Literals), KernelMaxLiterals)
	}
	return c.out, nil
}

type compiler struct {
	out       Compiled
	originIDs map[string]uint32
}

func (c *compiler) originID(o string) uint32 {
	if o == "" {
		return 0
	}
	if id, ok := c.originIDs[o]; ok {
		return id
	}
	c.out.Origins = append(c.out.Origins, o)
	c.originIDs[o] = uint32(len(c.out.Origins) - 1)
	return c.originIDs[o]
}

// segments allocates segment bits to distinct patterns of one slot.
type segments struct {
	ids      map[string]int // normalised pattern -> first bit
	next     int
	value    *SlotValue
	literals map[string]Bits
	globs    map[[2]string]Bits
}

// add returns the accept bit of a pattern, allocating its bits once.
func (s *segments) add(p Pattern) (int, error) {
	key := p.String()
	if first, ok := s.ids[key]; ok {
		return first + len(p.Segments) - 1, nil
	}
	if s.next+len(p.Segments) > KernelSegBits {
		return 0, fmt.Errorf("patterns need more than %d segments per policy combination", KernelSegBits)
	}
	first := s.next
	s.ids[key] = first
	s.next += len(p.Segments)
	v := s.value
	for i, seg := range p.Segments {
		bit := first + i
		var one Bits
		one.set(bit)
		switch seg.Kind {
		case SegLiteral:
			s.literals[seg.Lit] = s.literals[seg.Lit].or(one)
		case SegStar:
			v.Wild = v.Wild.or(one)
		case SegDoubleStar:
			v.Wild = v.Wild.or(one)
			v.Star = v.Star.or(one)
			if i == 0 {
				v.Init = v.Init.or(one)
			}
		case SegGlob:
			k := [2]string{seg.Pre, seg.Suf}
			s.globs[k] = s.globs[k].or(one)
		}
	}
	v.First.set(first)
	v.Accept.set(first + len(p.Segments) - 1)
	return first + len(p.Segments) - 1, nil
}

func (s *segments) bits(patterns []Pattern) (Bits, error) {
	var b Bits
	for _, p := range patterns {
		bit, err := s.add(p)
		if err != nil {
			return b, err
		}
		b.set(bit)
	}
	return b, nil
}

// guard returns the guard bits of a deny rule pattern (see guardLengths) and
// adds them to the slot's accept mask. A pattern without parents has none.
func (s *segments) guard(p Pattern) (Bits, error) {
	var b Bits
	last, err := s.add(p)
	if err != nil {
		return b, err
	}
	first := last - len(p.Segments) + 1
	for _, n := range p.guardLengths() {
		b.set(first + n - 1)
	}
	s.value.Accept = s.value.Accept.or(b)
	return b, nil
}

func parseAll(paths []string) ([]Pattern, error) {
	out := make([]Pattern, 0, len(paths))
	for _, s := range paths {
		p, err := ParsePattern(s)
		if err != nil {
			return nil, fmt.Errorf("path %q: %w", s, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func (c *compiler) slot(slot uint32, docs []Document) error {
	if len(docs) == 0 {
		return fmt.Errorf("no policy")
	}
	value := SlotValue{Generation: c.out.Generation}
	var active []Document
	for _, d := range docs {
		if err := d.Validate(); err != nil {
			return err
		}
		if d.Policy.Mode != "off" {
			active = append(active, d)
		}
	}
	if len(active) > KernelMaxDocs {
		return fmt.Errorf("%d policies (max %d)", len(active), KernelMaxDocs)
	}
	if len(active) == 0 {
		c.out.Slots = append(c.out.Slots, value) // mode off: the slot is not judged
		return nil
	}

	enforce := false
	for a, kind := range AccessKinds {
		mode := func(d Document) string {
			if m := d.Policy.File.Defaults[kind].Mode; m != "" {
				return m
			}
			return d.Policy.Mode
		}
		merged, merMode, origin := "allow", "audit", ""
		for _, d := range active {
			if d.Policy.File.Defaults[kind].Action == "deny" {
				merged = "deny"
			}
		}
		for i, d := range active {
			if d.Policy.File.Defaults[kind].Action == merged && mode(d) == "enforce" {
				merMode = "enforce"
				if merged == "deny" {
					value.DenyEnforceDocs[a] |= 1 << i
				}
			}
		}
		// The origin of the first policy whose default decides.
		for _, d := range active {
			def := d.Policy.File.Defaults[kind]
			if def.Action == merged && mode(d) == merMode {
				origin = def.Origin
				break
			}
		}
		value.Defaults[a] = PolicyValue{Rank: rank(merged, merMode), RuleID: RuleIDDefault, OriginID: c.originID(origin)}
		value.Unresolved[a] = value.Defaults[a].Rank
		enforce = enforce || value.Defaults[a].Rank == RankDenyEnforce
	}

	seg := &segments{ids: map[string]int{}, value: &value, literals: map[string]Bits{}, globs: map[[2]string]Bits{}}
	n := 0
	// Allow rules that are the same in access, paths and fromImage judge
	// the same: the first one stands for all (its name and origin are
	// reported). Merge rule 5 is not affected: a matching allow rule lifts
	// it whichever document the rule belongs to.
	allows := map[string]bool{}
	for i, d := range active {
		for _, r := range d.Policy.File.Rules {
			if r.Action == "allow" {
				key, err := allowKey(r)
				if err != nil {
					return fmt.Errorf("rule %q: %w", r.Name, err)
				}
				if allows[key] {
					continue
				}
				allows[key] = true
			}
			if n >= KernelMaxRules {
				return fmt.Errorf("more than %d file rules", KernelMaxRules)
			}
			e, err := c.rule(i, d, r, seg)
			if err != nil {
				return fmt.Errorf("rule %q: %w", r.Name, err)
			}
			value.Rules[n] = e
			n++
			anyPath := uint8(0)
			if e.Flags&RuleAnyPath != 0 {
				anyPath = 1
			}
			for a := 0; a < KernelAccessKinds; a++ {
				if e.Access&(1<<a) != 0 {
					value.Unresolved[a] = max(value.Unresolved[a], e.Rank)
					value.RuleUnion[a] = value.RuleUnion[a].or(e.Match)
					value.AnyPath[a] |= anyPath
				}
			}
			for flag, guard := range map[uint8]int{RuleGuard: AccessMoveSource, RuleNewNameGuard: AccessNewName} {
				if e.Flags&flag != 0 {
					value.Unresolved[guard] = max(value.Unresolved[guard], e.Rank)
					value.RuleUnion[guard] = value.RuleUnion[guard].or(e.Guard)
				}
			}
			enforce = enforce || e.Rank == RankDenyEnforce
		}
	}
	value.NRules = uint32(n)
	if len(seg.globs) > KernelMaxGlobs {
		return fmt.Errorf("%d distinct glob segments (max %d)", len(seg.globs), KernelMaxGlobs)
	}
	value.Mode = KernelModeAudit
	if enforce {
		value.Mode = KernelModeEnforce
	}
	return c.finish(slot, value, seg)
}

// finish picks a seed under which the slot's literal hashes are distinct and
// writes the literal and glob tables.
func (c *compiler) finish(slot uint32, value SlotValue, seg *segments) error {
	lits := make([]string, 0, len(seg.literals))
	for l := range seg.literals {
		lits = append(lits, l)
	}
	sort.Strings(lits)
	globs := make([][2]string, 0, len(seg.globs))
	for g := range seg.globs {
		globs = append(globs, g)
	}
	sort.Slice(globs, func(i, j int) bool {
		return globs[i][0] < globs[j][0] || globs[i][0] == globs[j][0] && globs[i][1] < globs[j][1]
	})
	for attempt := 0; ; attempt++ {
		if attempt == 8 {
			return fmt.Errorf("no hash seed without a literal collision")
		}
		seed, err := randomSeed()
		if err != nil {
			return fmt.Errorf("picking a hash seed: %w", err)
		}
		hashes := map[uint64]bool{}
		for _, l := range lits {
			hashes[Hash(seed, l)] = true
		}
		if len(hashes) != len(lits) {
			continue
		}
		value.Seed = seed
		break
	}
	for _, l := range lits {
		c.out.Literals = append(c.out.Literals, LiteralEntry{Key: LiteralKey{Slot: slot, Hash: Hash(value.Seed, l)}, Bits: seg.literals[l]})
	}
	for i, g := range globs {
		value.Globs[i] = GlobEntry{Bits: seg.globs[g], PreHash: Hash(value.Seed, g[0]), SufHash: HashReverse(value.Seed, g[1]),
			PreLen: uint8(len(g[0])), SufLen: uint8(len(g[1]))}
	}
	value.NGlobs = uint32(len(globs))
	c.out.Slots = append(c.out.Slots, value)
	return nil
}

// allowKey identifies what an allow rule judges: its access kinds, its
// normalised paths and fromImage.
func allowKey(r Rule) (string, error) {
	paths, err := parseAll(r.Paths)
	if err != nil {
		return "", err
	}
	norm := make([]string, len(paths))
	for i, p := range paths {
		norm[i] = p.String()
	}
	sort.Strings(norm)
	return fmt.Sprintf("%d|%v|%q", accessMask(r.Access), r.FromImage, norm), nil
}

func (c *compiler) rule(doc int, d Document, r Rule, seg *segments) (RuleEntry, error) {
	mode := r.Mode
	if mode == "" {
		mode = d.Policy.Mode
	}
	name := r.Name
	if d.Name != "" {
		name = d.Name + "/" + r.Name
	}
	c.out.RuleNames = append(c.out.RuleNames, name)
	e := RuleEntry{RuleID: uint32(len(c.out.RuleNames) - 1), OriginID: c.originID(r.Origin), Access: accessMask(r.Access),
		Rank: rank(r.Action, mode), Doc: uint8(doc)}
	if r.FromImage {
		e.Flags |= RuleFromImage
	}
	paths, err := parseAll(r.Paths)
	if err != nil {
		return e, err
	}
	excepts, err := parseAll(r.Except)
	if err != nil {
		return e, err
	}
	if len(paths) == 0 {
		e.Flags |= RuleAnyPath
	}
	if e.Match, err = seg.bits(paths); err != nil {
		return e, err
	}
	if e.Except, err = seg.bits(excepts); err != nil {
		return e, err
	}
	// The guard: parents of the paths of a deny rule. It guards move
	// sources for a rule of read or write, and new names for a rule of
	// write or create. Both are judged with the full decision of those
	// access kinds too, so the rule's own paths need no guard.
	moveSource := e.Access&(1<<accessIndex(AccessRead)|1<<accessIndex(AccessWrite)) != 0
	newName := e.Access&(1<<accessIndex(AccessWrite)|1<<accessIndex(AccessCreate)) != 0
	if r.Action == "deny" && (moveSource || newName) {
		for _, p := range paths {
			g, err := seg.guard(p)
			if err != nil {
				return e, err
			}
			e.Guard = e.Guard.or(g)
		}
		if e.Guard.any() && moveSource {
			e.Flags |= RuleGuard
		}
		if e.Guard.any() && newName {
			e.Flags |= RuleNewNameGuard
		}
	}
	return e, nil
}
