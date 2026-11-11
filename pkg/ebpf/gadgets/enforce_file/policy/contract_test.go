// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package filepolicy

import (
	"bytes"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// The shared merge contract vectors (../../common/merge/CONTRACT.md), mapped to
// file targets: a key is a path pattern (checked at one path under it), a
// qualifier is an access kind. A rule without qual judges every access kind;
// a check without quals uses another access kind. A policy default applies to
// every access kind.
var (
	contractKeys  = map[string][2]string{"k1": {"/data/k1/**", "/data/k1/f"}, "k2": {"/data/k2/**", "/data/k2/f"}}
	contractQuals = map[string]string{"q1": AccessWrite, "q2": AccessCreate}
	contractRanks = map[string]uint8{"allow": RankAllow, "deny-audit": RankDenyAudit, "deny-enforce": RankDenyEnforce}
)

type contractVectors struct {
	Vectors []struct {
		Name     string `yaml:"name"`
		Policies []struct {
			Mode    string `yaml:"mode"`
			Default string `yaml:"default"`
			Rules   []struct {
				Key    string `yaml:"key"`
				Qual   string `yaml:"qual"`
				Action string `yaml:"action"`
				Mode   string `yaml:"mode"`
			} `yaml:"rules"`
		} `yaml:"policies"`
		Checks []struct {
			Key     string   `yaml:"key"`
			Quals   []string `yaml:"quals"`
			Verdict string   `yaml:"verdict"`
		} `yaml:"checks"`
	} `yaml:"vectors"`
}

func TestMergeContractVectors(t *testing.T) {
	data, err := os.ReadFile("../../common/merge/vectors.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var file contractVectors
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil {
		t.Fatal(err)
	}
	key := func(k string) [2]string {
		if contractKeys[k][0] == "" {
			t.Fatalf("unknown key %q", k)
		}
		return contractKeys[k]
	}
	qual := func(q string) string {
		if contractQuals[q] == "" {
			t.Fatalf("unknown qual %q", q)
		}
		return contractQuals[q]
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			var docs []Document
			for i, p := range v.Policies {
				d := Document{Version: 1, Name: string(rune('a' + i)), Policy: Policy{Mode: p.Mode, File: Section{Defaults: allDefaults(p.Default)}}}
				for j, r := range p.Rules {
					rule := Rule{Name: "r" + string(rune('0'+j)), Action: r.Action, Mode: r.Mode, Paths: []string{key(r.Key)[0]}}
					if r.Qual != "" {
						rule.Access = []string{qual(r.Qual)}
					}
					d.Policy.File.Rules = append(d.Policy.File.Rules, rule)
				}
				docs = append(docs, d)
			}
			c, err := CompileSlots([][]Document{docs}, 1)
			if err != nil {
				t.Fatal(err)
			}
			s := newSim(c)
			for _, check := range v.Checks {
				want, ok := contractRanks[check.Verdict]
				if !ok {
					t.Fatalf("unknown verdict %q", check.Verdict)
				}
				kinds := []string{AccessDelete}
				if len(check.Quals) > 0 {
					kinds = nil
					for _, q := range check.Quals {
						kinds = append(kinds, qual(q))
					}
				}
				// Several qualifiers: the most limiting result wins.
				var got uint8
				for _, kind := range kinds {
					got = max(got, s.judge(0, kind, key(check.Key)[1], false).rank)
				}
				if got != want {
					t.Errorf("%s %v: rank %d, want %s", check.Key, check.Quals, got, check.Verdict)
				}
			}
		})
	}
}
