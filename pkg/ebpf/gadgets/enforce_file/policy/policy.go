// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

// Package filepolicy defines the enforce_file policy document (YAML or JSON,
// see ../examples/policy.yaml), parses it, and compiles one or more documents
// into the gadget's map entries.
package filepolicy

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

// Access kinds, in the order of the kernel's per-access arrays.
const (
	AccessRead   = "read"
	AccessWrite  = "write"
	AccessCreate = "create"
	AccessDelete = "delete"
	AccessRename = "rename"
	AccessChmod  = "chmod"
)

// AccessKinds lists every access kind; the index is the kernel's access id.
var AccessKinds = []string{AccessRead, AccessWrite, AccessCreate, AccessDelete, AccessRename, AccessChmod}

type Document struct {
	// Name qualifies rule names in events when several policies merge.
	Name    string `yaml:"name,omitempty" json:"name,omitempty"`
	Version int    `yaml:"version" json:"version"`
	Policy  Policy `yaml:"policy" json:"policy"`
}

type Policy struct {
	// Mode is audit, enforce or off. Rules and defaults without their own
	// mode take it.
	Mode string  `yaml:"mode" json:"mode"`
	File Section `yaml:"file" json:"file"`
}

type Section struct {
	// Defaults holds one entry per access kind; every kind is required.
	Defaults map[string]Default `yaml:"defaults" json:"defaults"`
	Rules    []Rule             `yaml:"rules,omitempty" json:"rules,omitempty"`
}

type Default struct {
	Action string `yaml:"action" json:"action"`
	Mode   string `yaml:"mode,omitempty" json:"mode,omitempty"`
	Origin string `yaml:"origin,omitempty" json:"origin,omitempty"`
}

type Rule struct {
	Name   string `yaml:"name" json:"name"`
	Action string `yaml:"action" json:"action"`
	Mode   string `yaml:"mode,omitempty" json:"mode,omitempty"`
	Origin string `yaml:"origin,omitempty" json:"origin,omitempty"`
	// Access lists the access kinds the rule judges; none means all.
	Access []string `yaml:"access,omitempty" json:"access,omitempty"`
	// Paths are absolute globs (see README "Patterns"). None means every
	// path; then FromImage must be set.
	Paths []string `yaml:"paths,omitempty" json:"paths,omitempty"`
	// FromImage limits the rule to files of the image's lower layer.
	FromImage bool `yaml:"fromImage,omitempty" json:"fromImage,omitempty"`
	// Except lifts this deny rule for the paths it lists. The other rules
	// and the defaults still apply there.
	Except []string `yaml:"except,omitempty" json:"except,omitempty"`
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

func accessIndex(kind string) int {
	for i, k := range AccessKinds {
		if k == kind {
			return i
		}
	}
	return -1
}

func (d Document) Validate() error {
	if d.Version != 1 {
		return fmt.Errorf("unsupported policy version %d", d.Version)
	}
	p := d.Policy
	if p.Mode != "off" && !validMode(p.Mode, false) {
		return fmt.Errorf("policy mode must be audit, enforce or off")
	}
	s := p.File
	for k := range s.Defaults {
		if accessIndex(k) < 0 {
			return fmt.Errorf("unknown access kind %q in defaults", k)
		}
	}
	for _, k := range AccessKinds {
		def, ok := s.Defaults[k]
		if !ok {
			return fmt.Errorf("default for %s is missing", k)
		}
		if !validAction(def.Action) {
			return fmt.Errorf("default for %s must be allow or deny", k)
		}
		if !validMode(def.Mode, true) {
			return fmt.Errorf("default mode for %s must be audit or enforce", k)
		}
	}
	if p.Mode == "off" && len(s.Rules) > 0 {
		return fmt.Errorf("an off policy cannot carry rules")
	}
	if len(s.Rules) > MaxRules {
		return fmt.Errorf("too many file rules (max %d)", MaxRules)
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
	seen := map[string]bool{}
	for _, a := range r.Access {
		if accessIndex(a) < 0 {
			return fmt.Errorf("unknown access kind %q", a)
		}
		if seen[a] {
			return fmt.Errorf("access kind %q listed twice", a)
		}
		seen[a] = true
	}
	if len(r.Paths) == 0 && !r.FromImage {
		return fmt.Errorf("a rule needs paths or fromImage")
	}
	for _, p := range r.Paths {
		if _, err := ParsePattern(p); err != nil {
			return fmt.Errorf("path %q: %w", p, err)
		}
	}
	if len(r.Except) > 0 && r.Action != "deny" {
		return fmt.Errorf("except is allowed on deny rules only")
	}
	for _, p := range r.Except {
		if _, err := ParsePattern(p); err != nil {
			return fmt.Errorf("except %q: %w", p, err)
		}
	}
	return nil
}
