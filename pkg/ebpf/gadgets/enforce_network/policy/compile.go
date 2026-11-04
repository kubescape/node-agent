// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package netpolicy

import (
	"bytes"
	"fmt"
	"net/netip"
	"sort"
)

// Map ABI of ../network_policy.h and ../../common/policy.h. Keep in sync.
const (
	KernelMaxSlots    = 64
	KernelMaxPrefixes = 16384
	KernelMaxLists    = 1024
	KernelListLen     = 32
	// Policies per slot: a bit mask in struct net_slot.
	KernelMaxDocs = 32

	KernelSlotSize      = 32
	KernelPrefixKeySize = 24
	KernelListSize      = 8 + KernelListLen*16

	RankNone          = 0
	RankAllow         = 1
	RankDenyAudit     = 2
	RankDenyEnforce   = 3
	KernelModeOff     = 0
	KernelModeAudit   = 1
	KernelModeEnforce = 2

	ProtoAny = 0
	ProtoTCP = 1
	ProtoUDP = 2
)

var protos = map[string]uint8{"": ProtoAny, "any": ProtoAny, "tcp": ProtoTCP, "udp": ProtoUDP}

// SlotValue matches struct net_slot.
type SlotValue struct {
	Rank       uint8
	_          [3]uint8
	RuleID     uint32
	OriginID   uint32
	Mode       uint32
	Generation uint64
	// Bit i: policy i of the slot has an enforce default deny.
	DenyEnforceDocs uint32
	_               uint32
}

// PrefixKey matches struct net_prefix_key.
type PrefixKey struct {
	PrefixLen uint32
	Slot      uint32
	Addr      [16]byte
}

// RuleEntry matches struct net_rule.
type RuleEntry struct {
	PortLo, PortHi uint16
	Proto          uint8
	Rank           uint8
	Doc            uint8
	_              uint8
	RuleID         uint32
	OriginID       uint32
}

// RuleList matches struct net_list.
type RuleList struct {
	Len   uint32
	_     uint32
	Rules [KernelListLen]RuleEntry
}

type PrefixEntry struct {
	Key PrefixKey
	// List indexes Compiled.Lists.
	List uint32
}

// Compiled is the frozen map content plus the id tables events refer to.
// RuleNames[0] and Origins[0] are empty: id 0 means none. RuleNames[1] is
// "default".
type Compiled struct {
	Generation uint64
	// Slots holds one entry per policy slot (combination of policies).
	Slots     []SlotValue
	Prefixes  []PrefixEntry
	Lists     []RuleList
	RuleNames []string
	Origins   []string
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

// CompileKernel compiles one policy into slot 0.
func CompileKernel(d Document, generation uint64) (Compiled, error) {
	return CompileSlots([][]Document{{d}}, generation)
}

// CompileSlots compiles one node instance. Each slot holds one combination of
// documents, merged by the shared contract (../../common/merge/CONTRACT.md):
//   - rules are the union, each with its own name, origin and mode; the most
//     limiting matching rule wins (deny enforce > deny audit > allow);
//   - the default is deny if any document's default is deny, else allow; its
//     mode is the strictest among the documents whose default equals it;
//   - when every matching rule denies, the enforce default deny of each
//     document without a matching rule still applies; an explicit allow still
//     beats another document's default deny.
//
// Rules match by longest prefix in the kernel, so every prefix entry carries
// every rule that covers it (see network_policy.h).
func CompileSlots(slots [][]Document, generation uint64) (Compiled, error) {
	if generation == 0 {
		return Compiled{}, fmt.Errorf("generation must be nonzero")
	}
	if len(slots) == 0 || len(slots) > KernelMaxSlots {
		return Compiled{}, fmt.Errorf("%d policy combinations: need 1 to %d per node", len(slots), KernelMaxSlots)
	}
	c := &compiler{
		out:       Compiled{Generation: generation, RuleNames: []string{"", "default"}, Origins: []string{""}},
		originIDs: map[string]uint32{},
		listIDs:   map[RuleList]uint32{},
	}
	for slot, docs := range slots {
		if err := c.slot(uint32(slot), docs); err != nil {
			return Compiled{}, fmt.Errorf("policy combination %d: %w", slot, err)
		}
	}
	if len(c.out.Prefixes) > KernelMaxPrefixes {
		return Compiled{}, fmt.Errorf("policies expand to %d prefixes (max %d)", len(c.out.Prefixes), KernelMaxPrefixes)
	}
	if len(c.out.Lists) > KernelMaxLists {
		return Compiled{}, fmt.Errorf("policies expand to %d distinct rule lists (max %d)", len(c.out.Lists), KernelMaxLists)
	}
	return c.out, nil
}

type compiler struct {
	out       Compiled
	originIDs map[string]uint32
	listIDs   map[RuleList]uint32
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

// compiledRule is one rule of a slot with its prefixes and kernel entries.
type compiledRule struct {
	cidrs, excepts []prefix
	entries        []RuleEntry
}

func (r compiledRule) covers(p prefix) bool {
	for _, e := range r.excepts {
		if e.contains(p) {
			return false
		}
	}
	for _, cidr := range r.cidrs {
		if cidr.contains(p) {
			return true
		}
	}
	return false
}

func (c *compiler) slot(slot uint32, docs []Document) error {
	if len(docs) == 0 {
		return fmt.Errorf("no policy")
	}
	value := SlotValue{Generation: c.out.Generation, RuleID: 1}
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
	c.out.Slots = append(c.out.Slots, value)
	if len(active) == 0 {
		return nil // mode off: the slot is not judged
	}

	defaultMode := func(d Document) string {
		if d.Policy.Egress.DefaultMode != "" {
			return d.Policy.Egress.DefaultMode
		}
		return d.Policy.Mode
	}
	merged, mode := "allow", "audit"
	for _, d := range active {
		if d.Policy.Egress.Default == "deny" {
			merged = "deny"
		}
	}
	for i, d := range active {
		if d.Policy.Egress.Default != merged {
			continue
		}
		if defaultMode(d) == "enforce" {
			mode = "enforce"
			if merged == "deny" {
				value.DenyEnforceDocs |= 1 << i
			}
		}
	}
	value.Rank = rank(merged, mode)

	var rules []compiledRule
	set := map[prefix]bool{}
	needRoot := false
	for i, d := range active {
		for _, r := range d.Policy.Egress.Rules {
			cr, err := c.rule(i, d, r)
			if err != nil {
				return fmt.Errorf("rule %q: %w", r.Name, err)
			}
			for _, p := range append(append([]prefix(nil), cr.cidrs...), cr.excepts...) {
				set[p] = true
				needRoot = needRoot || (!p.v4 && p.containsBits(mappedRoot))
			}
			rules = append(rules, cr)
		}
	}
	// An IPv6 prefix that spans ::ffff:0:0/96 must not reach IPv4
	// destinations: the IPv4 root entry holds the IPv4 rules only.
	if needRoot {
		set[mappedRoot] = true
	}

	prefixes := make([]prefix, 0, len(set))
	for p := range set {
		prefixes = append(prefixes, p)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].bits != prefixes[j].bits {
			return prefixes[i].bits < prefixes[j].bits
		}
		return bytes.Compare(prefixes[i].addr[:], prefixes[j].addr[:]) < 0
	})
	for _, p := range prefixes {
		var list RuleList
		for _, r := range rules {
			if !r.covers(p) {
				continue
			}
			if int(list.Len)+len(r.entries) > KernelListLen {
				return fmt.Errorf("prefix %s is covered by more than %d rule entries (one per rule and port range)", p, KernelListLen)
			}
			copy(list.Rules[list.Len:], r.entries)
			list.Len += uint32(len(r.entries))
		}
		for _, e := range list.Rules[:list.Len] {
			if e.Rank == RankDenyEnforce {
				mode = "enforce"
			}
		}
		id, ok := c.listIDs[list]
		if !ok {
			id = uint32(len(c.out.Lists))
			c.listIDs[list] = id
			c.out.Lists = append(c.out.Lists, list)
		}
		c.out.Prefixes = append(c.out.Prefixes, PrefixEntry{Key: PrefixKey{PrefixLen: 32 + uint32(p.bits), Slot: slot, Addr: p.addr}, List: id})
	}
	value.Mode = KernelModeAudit
	if mode == "enforce" {
		value.Mode = KernelModeEnforce
	}
	c.out.Slots[slot] = value
	return nil
}

func (c *compiler) rule(doc int, d Document, r Rule) (compiledRule, error) {
	mode := r.Mode
	if mode == "" {
		mode = d.Policy.Mode
	}
	name := r.Name
	if d.Name != "" {
		name = d.Name + "/" + r.Name
	}
	c.out.RuleNames = append(c.out.RuleNames, name)
	base := RuleEntry{Proto: protos[r.Proto], Rank: rank(r.Action, mode), Doc: uint8(doc),
		RuleID: uint32(len(c.out.RuleNames) - 1), OriginID: c.originID(r.Origin)}
	var out compiledRule
	var err error
	if out.cidrs, err = parsePrefixes(r.CIDRs); err != nil {
		return out, err
	}
	if out.excepts, err = parsePrefixes(r.Except); err != nil {
		return out, err
	}
	if len(r.Ports) == 0 {
		e := base
		e.PortLo, e.PortHi = 0, 65535
		out.entries = append(out.entries, e)
	}
	for _, p := range r.Ports {
		e := base
		e.PortLo, e.PortHi = p.From, p.To
		if p.To == 0 {
			e.PortHi = p.From
		}
		out.entries = append(out.entries, e)
	}
	if len(out.entries) > KernelListLen {
		return out, fmt.Errorf("%d port ranges (max %d)", len(out.entries), KernelListLen)
	}
	return out, nil
}

// String formats the prefix as a CIDR.
func (p prefix) String() string {
	if p.v4 {
		return netip.PrefixFrom(netip.AddrFrom16(p.addr).Unmap(), p.bits-96).String()
	}
	return netip.PrefixFrom(netip.AddrFrom16(p.addr), p.bits).String()
}
