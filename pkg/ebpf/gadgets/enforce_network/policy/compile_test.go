// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package netpolicy

import (
	"encoding/binary"
	"net/netip"
	"os"
	"strings"
	"testing"
)

// decide mirrors net_decide in ../network_policy.h: longest prefix of the
// slot, the most limiting matching rule, else the default, and the raise for
// enforce default denies of policies without a matching rule.
func decide(t *testing.T, c Compiled, slot uint32, dst string, port uint16, proto uint8) (rank uint8, rule string) {
	t.Helper()
	addr := netip.MustParseAddr(dst).As16()
	best, found := -1, PrefixEntry{}
	for _, p := range c.Prefixes {
		if p.Key.Slot != slot {
			continue
		}
		bits := int(p.Key.PrefixLen) - 32
		if (prefix{addr: p.Key.Addr, bits: bits}).containsBits(prefix{addr: addr, bits: 128}) && bits > best {
			best, found = bits, p
		}
	}
	s := c.Slots[slot]
	var docs uint32
	allowed := false
	var m RuleEntry
	if best >= 0 {
		list := c.Lists[found.List]
		for _, r := range list.Rules[:list.Len] {
			if (r.Proto != ProtoAny && r.Proto != proto) || port < r.PortLo || port > r.PortHi {
				continue
			}
			docs |= 1 << r.Doc
			allowed = allowed || r.Rank == RankAllow
			if r.Rank > m.Rank {
				m = r
			}
		}
	}
	switch {
	case m.Rank == RankNone:
		return s.Rank, c.RuleNames[s.RuleID]
	case !allowed && s.DenyEnforceDocs&^docs != 0 && m.Rank < RankDenyEnforce:
		return RankDenyEnforce, "default"
	}
	return m.Rank, c.RuleNames[m.RuleID]
}

func mustParse(t *testing.T, y string) Document {
	t.Helper()
	d, err := Parse(strings.NewReader(y))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestKernelABISizes(t *testing.T) {
	for name, got := range map[string]int{
		"net_slot":       binary.Size(SlotValue{}) - KernelSlotSize,
		"net_prefix_key": binary.Size(PrefixKey{}) - KernelPrefixKeySize,
		"net_list":       binary.Size(RuleList{}) - KernelListSize,
		"net_rule":       binary.Size(RuleEntry{}) - 16,
	} {
		if got != 0 {
			t.Errorf("%s size off by %d", name, got)
		}
	}
}

func TestExampleParses(t *testing.T) {
	f, err := os.Open("../examples/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CompileKernel(d, 1); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejects(t *testing.T) {
	for name, rule := range map[string]string{
		"no cidr":           `{name: r, action: deny}`,
		"bad cidr":          `{name: r, action: deny, cidrs: [192.0.2.1]}`,
		"mapped cidr":       `{name: r, action: deny, cidrs: ["::ffff:192.0.2.0/120"]}`,
		"except on allow":   `{name: r, action: allow, cidrs: [192.0.2.0/24], except: [192.0.2.7/32]}`,
		"except outside":    `{name: r, action: deny, cidrs: [192.0.2.0/24], except: [198.51.100.0/24]}`,
		"except other fam":  `{name: r, action: deny, cidrs: ["::/0"], except: [192.0.2.0/24]}`,
		"port zero":         `{name: r, action: deny, cidrs: [192.0.2.0/24], ports: [{from: 0}]}`,
		"port range order":  `{name: r, action: deny, cidrs: [192.0.2.0/24], ports: [{from: 90, to: 80}]}`,
		"port out of range": `{name: r, action: deny, cidrs: [192.0.2.0/24], ports: [{from: 70000}]}`,
		"bad proto":         `{name: r, action: deny, cidrs: [192.0.2.0/24], proto: icmp}`,
		"bad mode":          `{name: r, action: deny, cidrs: [192.0.2.0/24], mode: warn}`,
		"unknown field":     `{name: r, action: deny, cidrs: [192.0.2.0/24], host: example.com}`,
	} {
		y := "version: 1\npolicy:\n  mode: enforce\n  egress:\n    default: allow\n    rules:\n      - " + rule + "\n"
		if _, err := Parse(strings.NewReader(y)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

const flattenPolicy = `
version: 1
policy:
  mode: enforce
  egress:
    default: allow
    rules:
      - name: deny-doc
        action: deny
        cidrs: [192.0.2.0/24, "2001:db8::/32"]
        except: [192.0.2.0/28, "2001:db8:1::/48"]
      - name: allow-host
        action: allow
        cidrs: [192.0.2.7/32]
      - name: deny-inner
        action: deny
        cidrs: [192.0.2.4/30]
      - name: audit-all-v6
        action: deny
        mode: audit
        cidrs: ["::/0"]
      - name: dns-only
        action: deny
        proto: udp
        cidrs: [198.51.100.0/24]
        ports: [{from: 53}, {from: 5300, to: 5399}]
`

func TestCompileFlattensPrefixes(t *testing.T) {
	c, err := CompileKernel(mustParse(t, flattenPolicy), 3)
	if err != nil {
		t.Fatal(err)
	}
	if c.Slots[0].Generation != 3 || c.Slots[0].Mode != KernelModeEnforce || c.Slots[0].Rank != RankAllow {
		t.Fatalf("slot %+v", c.Slots[0])
	}
	for _, tc := range []struct {
		dst   string
		port  uint16
		proto uint8
		rank  uint8
		rule  string
	}{
		{"192.0.2.200", 80, ProtoTCP, RankDenyEnforce, "deny-doc"},
		// except: lifts deny-doc only; deny-inner still covers .4/30.
		{"192.0.2.1", 80, ProtoTCP, RankAllow, "default"},
		{"192.0.2.5", 80, ProtoTCP, RankDenyEnforce, "deny-inner"},
		// .7 is in the except and in deny-inner: deny beats the allow.
		{"192.0.2.7", 80, ProtoTCP, RankDenyEnforce, "deny-inner"},
		{"::ffff:192.0.2.200", 80, ProtoTCP, RankDenyEnforce, "deny-doc"},
		{"2001:db8::1", 443, ProtoTCP, RankDenyEnforce, "deny-doc"},
		// IPv6 except: only the audit ::/0 rule stays.
		{"2001:db8:1::1", 443, ProtoTCP, RankDenyAudit, "audit-all-v6"},
		{"2001:db9::1", 443, ProtoUDP, RankDenyAudit, "audit-all-v6"},
		// ::/0 does not reach IPv4 or IPv4-mapped destinations.
		{"203.0.113.1", 80, ProtoTCP, RankAllow, "default"},
		{"::ffff:203.0.113.1", 80, ProtoTCP, RankAllow, "default"},
		// Ports and ranges, protocol.
		{"198.51.100.1", 53, ProtoUDP, RankDenyEnforce, "dns-only"},
		{"198.51.100.1", 5350, ProtoUDP, RankDenyEnforce, "dns-only"},
		{"198.51.100.1", 5400, ProtoUDP, RankAllow, "default"},
		{"198.51.100.1", 53, ProtoTCP, RankAllow, "default"},
	} {
		rank, rule := decide(t, c, 0, tc.dst, tc.port, tc.proto)
		if rank != tc.rank || rule != tc.rule {
			t.Errorf("%s:%d/%d = rank %d %s, want %d %s", tc.dst, tc.port, tc.proto, rank, rule, tc.rank, tc.rule)
		}
	}
	// Equal rule lists share one entry in the rules array.
	if len(c.Lists) >= len(c.Prefixes) {
		t.Errorf("%d lists for %d prefixes: equal lists must be shared", len(c.Lists), len(c.Prefixes))
	}
}

func TestCompileRuleListLimit(t *testing.T) {
	d := Document{Version: 1, Policy: Policy{Mode: "enforce", Egress: Section{Default: "allow"}}}
	for i := 0; i < KernelListLen+1; i++ {
		d.Policy.Egress.Rules = append(d.Policy.Egress.Rules, Rule{Name: string(rune('a'+i%26)) + string(rune('a'+i/26)), Action: "deny", CIDRs: []string{"192.0.2.0/24"}})
	}
	_, err := CompileKernel(d, 1)
	if err == nil || !strings.Contains(err.Error(), "192.0.2.0/24 is covered by more than 32 rule entries") {
		t.Fatalf("want a clear rule-list limit error, got %v", err)
	}
}

func TestCompileSlotsAndOff(t *testing.T) {
	off := Document{Version: 1, Policy: Policy{Mode: "off", Egress: Section{Default: "deny"}}}
	deny := Document{Version: 1, Name: "b", Policy: Policy{Mode: "audit", Egress: Section{Default: "deny", DefaultMode: "enforce"}}}
	c, err := CompileSlots([][]Document{{off}, {deny}}, 9)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Slots) != 2 || c.Slots[0].Mode != KernelModeOff || c.Slots[0].Generation != 9 {
		t.Fatalf("off slot %+v", c.Slots)
	}
	// defaultMode overrides the policy mode for the default.
	if s := c.Slots[1]; s.Rank != RankDenyEnforce || s.Mode != KernelModeEnforce || s.DenyEnforceDocs != 1 {
		t.Fatalf("deny slot %+v", s)
	}
	if _, err := CompileSlots(nil, 1); err == nil {
		t.Fatal("no slot must fail")
	}
}
