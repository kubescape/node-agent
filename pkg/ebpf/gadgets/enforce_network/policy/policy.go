// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

// Package netpolicy defines the enforce_network policy document (YAML or JSON,
// see ../examples/policy.yaml), parses it, and compiles one or more documents
// into the gadget's map entries.
package netpolicy

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	MaxBytes = 64 * 1024
	MaxRules = 128
)

type Document struct {
	// Name qualifies rule names in events when several policies merge.
	Name    string `yaml:"name,omitempty" json:"name,omitempty"`
	Version int    `yaml:"version" json:"version"`
	Policy  Policy `yaml:"policy" json:"policy"`
}

type Policy struct {
	// Mode is audit, enforce or off. Rules and the default without their own
	// mode take it.
	Mode   string  `yaml:"mode" json:"mode"`
	Egress Section `yaml:"egress" json:"egress"`
}

// Section holds the rules of one direction (egress: connect and send).
type Section struct {
	Default     string `yaml:"default" json:"default"`
	DefaultMode string `yaml:"defaultMode,omitempty" json:"defaultMode,omitempty"`
	Rules       []Rule `yaml:"rules,omitempty" json:"rules,omitempty"`
}

type Rule struct {
	Name   string `yaml:"name" json:"name"`
	Action string `yaml:"action" json:"action"`
	Mode   string `yaml:"mode,omitempty" json:"mode,omitempty"`
	Origin string `yaml:"origin,omitempty" json:"origin,omitempty"`
	// CIDRs are IPv4 or IPv6 prefixes. An IPv4 rule also matches IPv4-mapped
	// IPv6 destinations; write IPv4 ranges as IPv4.
	CIDRs []string `yaml:"cidrs" json:"cidrs"`
	// Except lifts this deny rule for prefixes inside its CIDRs. The other
	// rules and the default still apply there.
	Except []string `yaml:"except,omitempty" json:"except,omitempty"`
	// Ports are destination port ranges; none means every port.
	Ports []PortRange `yaml:"ports,omitempty" json:"ports,omitempty"`
	// Proto is tcp, udp or any (the default).
	Proto string `yaml:"proto,omitempty" json:"proto,omitempty"`
}

// PortRange is an inclusive range; To 0 means From only.
type PortRange struct {
	From uint16 `yaml:"from" json:"from"`
	To   uint16 `yaml:"to,omitempty" json:"to,omitempty"`
}

// Parse reads one policy document (YAML or JSON) with unknown fields rejected.
func Parse(r io.Reader) (Document, error) {
	var doc Document
	data, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return doc, err
	}
	if len(data) > MaxBytes {
		return doc, fmt.Errorf("policy exceeds %d bytes", MaxBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return doc, fmt.Errorf("parsing policy: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return doc, fmt.Errorf("parsing policy: one document per file")
	}
	return doc, doc.Validate()
}

func validMode(m string, allowEmpty bool) bool {
	return m == "audit" || m == "enforce" || (allowEmpty && m == "")
}

func validAction(a string) bool { return a == "allow" || a == "deny" }

func (d Document) Validate() error {
	if d.Version != 1 {
		return fmt.Errorf("unsupported policy version %d", d.Version)
	}
	p := d.Policy
	if p.Mode != "off" && !validMode(p.Mode, false) {
		return fmt.Errorf("policy mode must be audit, enforce or off")
	}
	s := p.Egress
	if !validAction(s.Default) {
		return fmt.Errorf("egress default must be allow or deny")
	}
	if !validMode(s.DefaultMode, true) {
		return fmt.Errorf("egress defaultMode must be audit or enforce")
	}
	if p.Mode == "off" && len(s.Rules) > 0 {
		return fmt.Errorf("an off policy cannot carry rules")
	}
	if len(s.Rules) > MaxRules {
		return fmt.Errorf("too many egress rules (max %d)", MaxRules)
	}
	names := map[string]bool{}
	for _, r := range s.Rules {
		if strings.TrimSpace(r.Name) == "" || names[r.Name] {
			return fmt.Errorf("rule names must be unique and non-empty")
		}
		names[r.Name] = true
		if err := r.validate(); err != nil {
			return fmt.Errorf("rule %q: %w", r.Name, err)
		}
	}
	return nil
}

func (r Rule) validate() error {
	if !validAction(r.Action) {
		return fmt.Errorf("action must be allow or deny")
	}
	if !validMode(r.Mode, true) {
		return fmt.Errorf("mode must be audit or enforce")
	}
	if _, ok := protos[r.Proto]; !ok {
		return fmt.Errorf("proto must be tcp, udp or any")
	}
	if len(r.CIDRs) == 0 {
		return fmt.Errorf("at least one CIDR is required")
	}
	cidrs, err := parsePrefixes(r.CIDRs)
	if err != nil {
		return err
	}
	if len(r.Except) > 0 && r.Action != "deny" {
		return fmt.Errorf("except applies to deny rules only")
	}
	excepts, err := parsePrefixes(r.Except)
	if err != nil {
		return err
	}
	for i, e := range excepts {
		inside := false
		for _, c := range cidrs {
			inside = inside || c.contains(e)
		}
		if !inside {
			return fmt.Errorf("except %s is not inside the rule's CIDRs", r.Except[i])
		}
	}
	for _, p := range r.Ports {
		if p.From == 0 || (p.To != 0 && p.To < p.From) {
			return fmt.Errorf("port range %d-%d must be within 1-65535 with from <= to", p.From, p.To)
		}
	}
	return nil
}

// prefix is a CIDR in the map's 16-byte form: IPv4 is IPv4-mapped, and bits
// counts from the start of the 16 bytes.
type prefix struct {
	addr [16]byte
	bits int
	v4   bool
}

// mappedRoot is 0.0.0.0/0, the IPv4-mapped IPv6 range ::ffff:0:0/96.
var mappedRoot = prefix{addr: [16]byte{10: 0xff, 11: 0xff}, bits: 96, v4: true}

func parsePrefix(s string) (prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return prefix{}, fmt.Errorf("invalid CIDR %q (write a prefix, for example 192.0.2.0/24)", s)
	}
	p = p.Masked()
	// Every IPv6 prefix inside ::ffff:0:0/96 has an IPv4-mapped address.
	if p.Addr().Is4In6() {
		return prefix{}, fmt.Errorf("CIDR %q is IPv4-mapped; write it as IPv4", s)
	}
	out := prefix{addr: p.Addr().As16(), bits: p.Bits(), v4: p.Addr().Is4()}
	if out.v4 {
		out.bits += 96
	}
	return out, nil
}

func parsePrefixes(list []string) ([]prefix, error) {
	out := make([]prefix, 0, len(list))
	for _, s := range list {
		p, err := parsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// containsBits compares addresses only: q lies inside p.
func (p prefix) containsBits(q prefix) bool {
	if q.bits < p.bits {
		return false
	}
	for i := 0; i < p.bits; i++ {
		if (p.addr[i/8]>>(7-i%8))&1 != (q.addr[i/8]>>(7-i%8))&1 {
			return false
		}
	}
	return true
}

// contains reports whether q lies inside p in the same family. The IPv4-mapped
// range belongs to IPv4 only, so an IPv6 rule such as ::/0 never matches an
// IPv4 destination.
func (p prefix) contains(q prefix) bool {
	return p.v4 == q.v4 && p.containsBits(q)
}
