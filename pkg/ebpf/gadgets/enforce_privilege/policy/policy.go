// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

// Package privpolicy defines the enforce_privilege policy document (YAML or
// JSON, see ../examples/policy.yaml), parses it, and compiles one or more
// documents into the gadget's map entries.
package privpolicy

import (
	"bytes"
	"fmt"
	"io"
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
	Mode      string  `yaml:"mode" json:"mode"`
	Privilege Section `yaml:"privilege" json:"privilege"`
}

type Section struct {
	Default string `yaml:"default" json:"default"`
	Rules   []Rule `yaml:"rules,omitempty" json:"rules,omitempty"`
}

type Rule struct {
	Name   string `yaml:"name" json:"name"`
	Target Target `yaml:"target" json:"target"`
	Action string `yaml:"action" json:"action"`
	Mode   string `yaml:"mode,omitempty" json:"mode,omitempty"`
	Origin string `yaml:"origin,omitempty" json:"origin,omitempty"`
}

// Target selects exactly one primitive kind. Flags qualify Syscall only.
type Target struct {
	Syscall     []string `yaml:"syscall,omitempty" json:"syscall,omitempty"`
	Flags       []string `yaml:"flags,omitempty" json:"flags,omitempty"`
	Capability  []string `yaml:"capability,omitempty" json:"capability,omitempty"`
	MountFSType []string `yaml:"mountFsType,omitempty" json:"mountFsType,omitempty"`
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
	s := p.Privilege
	if !validAction(s.Default) {
		return fmt.Errorf("privilege default must be allow or deny")
	}
	if p.Mode == "off" && len(s.Rules) > 0 {
		return fmt.Errorf("an off policy cannot carry rules")
	}
	if len(s.Rules) > MaxRules {
		return fmt.Errorf("too many privilege rules (max %d)", MaxRules)
	}
	names := map[string]bool{}
	for _, r := range s.Rules {
		if strings.TrimSpace(r.Name) == "" || names[r.Name] {
			return fmt.Errorf("rule names must be unique and non-empty")
		}
		names[r.Name] = true
		if !validAction(r.Action) {
			return fmt.Errorf("rule %q: action must be allow or deny", r.Name)
		}
		if !validMode(r.Mode, true) {
			return fmt.Errorf("rule %q: mode must be audit or enforce", r.Name)
		}
		if err := r.Target.validate(); err != nil {
			return fmt.Errorf("rule %q: %w", r.Name, err)
		}
	}
	return nil
}

func (t Target) validate() error {
	kinds := 0
	for _, n := range []int{len(t.Syscall), len(t.Capability), len(t.MountFSType)} {
		if n > 0 {
			kinds++
		}
	}
	if kinds != 1 {
		return fmt.Errorf("target must select exactly one of syscall, capability or mountFsType")
	}
	for _, s := range t.Syscall {
		if _, ok := Syscalls[s]; !ok {
			return fmt.Errorf("unsupported syscall %q", s)
		}
	}
	if len(t.Flags) == 0 {
		for _, s := range t.Syscall {
			if s == "clone" || s == "clone3" {
				// The gadget judges a clone by its namespace flags. A rule
				// without flags would read as "deny every fork", which it
				// does not do.
				return fmt.Errorf("a %s rule must list namespace flags: a plain fork is never judged", s)
			}
		}
	}
	if len(t.Flags) > 0 {
		if len(t.Syscall) == 0 {
			return fmt.Errorf("flags qualify a syscall target only")
		}
		for _, s := range t.Syscall {
			if !NamespaceSyscalls[s] {
				return fmt.Errorf("flags qualify unshare, setns, clone and clone3 only")
			}
		}
		for _, f := range t.Flags {
			if _, ok := NamespaceFlags[f]; !ok {
				return fmt.Errorf("unsupported flag %q", f)
			}
		}
	}
	for _, c := range t.Capability {
		if _, ok := Capabilities[c]; !ok {
			return fmt.Errorf("unsupported capability %q (use the short name, for example SYS_ADMIN)", c)
		}
	}
	for _, fs := range t.MountFSType {
		if fs == "" || len(fs) >= KernelNameLen || strings.ContainsRune(fs, 0) {
			return fmt.Errorf("filesystem type %q must be 1-%d bytes without NUL", fs, KernelNameLen-1)
		}
	}
	return nil
}
