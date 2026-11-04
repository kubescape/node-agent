// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package privpolicy

import (
	"bytes"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// The shared merge contract vectors (../../common/merge/CONTRACT.md), mapped to
// privilege targets.
var (
	contractKeys  = map[string]string{"k1": "mount", "k2": "unshare"}
	contractQuals = map[string]string{"q1": "CLONE_NEWNS", "q2": "CLONE_NEWNET"}
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

// contractRank resolves a call like the program: per qualifier, the rules on
// the bare key and on the qualified key, else the default; the most limiting
// qualifier wins.
func contractRank(c Compiled, syscall string, flags []string) uint8 {
	def, _ := lookup(c, KernelKey{Kind: KindDefault, ID: KindSyscall})
	bare, _ := lookup(c, KernelKey{Kind: KindSyscall, ID: Syscalls[syscall]})
	if len(flags) == 0 {
		if bare.Rank != RankNone {
			return bare.Rank
		}
		return def.Rank
	}
	var result uint8
	for _, f := range flags {
		q, _ := lookup(c, KernelKey{Kind: KindSyscall, ID: Syscalls[syscall], Qual: NamespaceFlags[f]})
		r := max(bare.Rank, q.Rank)
		if r == RankNone {
			r = def.Rank
		}
		result = max(result, r)
	}
	return result
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
	key := func(k string) string {
		if contractKeys[k] == "" {
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
				d := Document{Version: 1, Name: string(rune('a' + i)), Policy: Policy{Mode: p.Mode, Privilege: Section{Default: p.Default}}}
				for j, r := range p.Rules {
					rule := Rule{Name: "r" + string(rune('0'+j)), Action: r.Action, Mode: r.Mode, Target: Target{Syscall: []string{key(r.Key)}}}
					if r.Qual != "" {
						rule.Target.Flags = []string{qual(r.Qual)}
					}
					d.Policy.Privilege.Rules = append(d.Policy.Privilege.Rules, rule)
				}
				docs = append(docs, d)
			}
			c, err := CompileSlots([][]Document{docs}, 1)
			if err != nil {
				t.Fatal(err)
			}
			for _, check := range v.Checks {
				var flags []string
				for _, q := range check.Quals {
					flags = append(flags, qual(q))
				}
				want, ok := contractRanks[check.Verdict]
				if !ok {
					t.Fatalf("unknown verdict %q", check.Verdict)
				}
				if got := contractRank(c, key(check.Key), flags); got != want {
					t.Errorf("%s %v: rank %d, want %s", check.Key, check.Quals, got, check.Verdict)
				}
			}
		})
	}
}
