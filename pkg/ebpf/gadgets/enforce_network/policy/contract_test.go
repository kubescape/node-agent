// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package netpolicy

import (
	"bytes"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// The shared merge contract vectors (../../common/merge/CONTRACT.md), mapped to
// network targets: a key is a CIDR (checked at one address in it), a qualifier
// is a destination port. A rule without qual matches every port; a check
// without quals uses another port.
var (
	contractKeys  = map[string][2]string{"k1": {"192.0.2.0/24", "192.0.2.1"}, "k2": {"2001:db8::/32", "2001:db8::1"}}
	contractQuals = map[string]uint16{"q1": 53, "q2": 54}
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
	qual := func(q string) uint16 {
		if contractQuals[q] == 0 {
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
				d := Document{Version: 1, Name: string(rune('a' + i)), Policy: Policy{Mode: p.Mode, Egress: Section{Default: p.Default}}}
				for j, r := range p.Rules {
					rule := Rule{Name: "r" + string(rune('0'+j)), Action: r.Action, Mode: r.Mode, CIDRs: []string{key(r.Key)[0]}}
					if r.Qual != "" {
						rule.Ports = []PortRange{{From: qual(r.Qual)}}
					}
					d.Policy.Egress.Rules = append(d.Policy.Egress.Rules, rule)
				}
				docs = append(docs, d)
			}
			c, err := CompileSlots([][]Document{docs}, 1)
			if err != nil {
				t.Fatal(err)
			}
			for _, check := range v.Checks {
				want, ok := contractRanks[check.Verdict]
				if !ok {
					t.Fatalf("unknown verdict %q", check.Verdict)
				}
				ports := []uint16{80}
				if len(check.Quals) > 0 {
					ports = nil
					for _, q := range check.Quals {
						ports = append(ports, qual(q))
					}
				}
				// Several qualifiers: the most limiting result wins.
				var got uint8
				for _, port := range ports {
					rank, _ := decide(t, c, 0, key(check.Key)[1], port, ProtoTCP)
					got = max(got, rank)
				}
				if got != want {
					t.Errorf("%s %v: rank %d, want %s", check.Key, check.Quals, got, check.Verdict)
				}
			}
		})
	}
}
