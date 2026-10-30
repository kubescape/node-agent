package igbackend

import (
	"encoding/binary"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	dsapi "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

func verdictPlan() sandboxpolicy.Plan {
	p := fullPlan()
	p.Policies[0].Exec.Rules = nil
	for _, r := range []api.Rule{{Name: "allow", Action: "allow", Mode: "enforce"}, {Name: "audit-deny", Action: "deny", Mode: "audit"}, {Name: "enforce-deny", Action: "deny", Mode: "enforce"}} {
		p.Policies[0].Exec.Rules = append(p.Policies[0].Exec.Rules, api.ExecRule{Rule: r, Target: api.ExecTarget{PathTarget: api.PathTarget{Path: []string{"/bin/tool"}}}})
	}
	return p
}
func verdictDecoder(t *testing.T, p sandboxpolicy.Plan) *FullVerdictDecoder {
	t.Helper()
	b := sandboxpolicy.Binding{CgroupID: 19, ContainerName: "app"}
	k, e := CompileFull(b, p, 7, nil)
	if e != nil {
		t.Fatal(e)
	}
	d, e := NewFullVerdictDecoder(b, p, k)
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func TestFullVerdictUnion(t *testing.T) {
	d := verdictDecoder(t, verdictPlan())
	for _, tc := range []struct {
		name         string
		bits         uint64
		deny, mode   uint32
		rule, reason string
	}{
		{"allow overrides unmatched defaults", 1, 0, 2, "allow", "matching_rule"},
		{"audit denial dominates enforced allow", 3, 1, 1, "audit-deny", "matching_rule"},
		{"enforced denial dominates audit", 7, 1, 2, "enforce-deny", "matching_rule"},
		{"global defaults", 0, 1, 1, "", "section_default"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, e := d.Decode(RawFullVerdict{RawVerdict: RawVerdict{Generation: 7, Cgroup: 19, Deny: tc.deny, Mode: tc.mode, PathResult: -1, Path: "partial"}, MatchedRules: [4]uint64{tc.bits}})
			if e != nil {
				t.Fatal(e)
			}
			if v.Rule != tc.rule || v.Reason != tc.reason || len(v.PolicySet) != 2 || !v.MatchesComplete || v.TargetPath != "" || v.UID != nil || v.FromImage != nil || v.ActorPath != "" || v.Argv != nil || v.WouldDeny != (tc.deny == 1 && tc.mode == 1) {
				t.Fatalf("unexpected %+v", v)
			}
		})
	}
}
func TestFullVerdictAmbiguousAndCopies(t *testing.T) {
	p := verdictPlan()
	p.Policies[1].Exec.Rules = []api.ExecRule{p.Policies[0].Exec.Rules[2]}
	d := verdictDecoder(t, p)
	p.Policies[0].Identity.Name = "mutated"
	p.Policies[0].Exec.Rules[2].Name = "mutated"
	r := RawFullVerdict{RawVerdict: RawVerdict{Generation: 7, Cgroup: 19, Deny: 1, Mode: 2}, MatchedRules: [4]uint64{12}}
	v, e := d.Decode(r)
	if e != nil {
		t.Fatal(e)
	}
	if v.Rule != "" || v.Policy.UID != "" || len(v.Matches) != 2 {
		t.Fatalf("invented attribution %+v", v)
	}
	v.PolicySet[0].Revision = "mutated"
	v.Matches[0].Name = "mutated"
	v, e = d.Decode(r)
	if e != nil || v.PolicySet[0].Revision == "mutated" || v.Matches[0].Name == "mutated" {
		t.Fatal("decoder aliases caller", e)
	}
	// Two same-mode defaults are equally decisive; absence of defaults leaves
	// implicit audit allow without inventing a policy contributor.
	for _, fallback := range []api.Action{"deny", ""} {
		p := verdictPlan()
		for i := range p.Policies {
			p.Policies[i].Mode = "audit"
			p.Policies[i].Exec = api.ExecSection{Default: fallback}
		}
		d := verdictDecoder(t, p)
		r.MatchedRules = [4]uint64{}
		r.Mode = 1
		r.Deny = 0
		if fallback == "deny" {
			r.Deny = 1
		}
		v, e = d.Decode(r)
		if e != nil || v.Policy.UID != "" || v.Rule != "" {
			t.Fatalf("default attribution %+v %v", v, e)
		}
	}
}
func TestFullVerdictValidation(t *testing.T) {
	d := verdictDecoder(t, verdictPlan())
	valid := RawFullVerdict{RawVerdict: RawVerdict{Generation: 7, Cgroup: 19, Mode: 2, Path: "/bin/tool", PathResult: 10}, MatchedRules: [4]uint64{1}}
	if _, e := d.Decode(valid); e != nil {
		t.Fatal(e)
	}
	for name, change := range map[string]func(*RawFullVerdict){"generation": func(r *RawFullVerdict) { r.Generation++ }, "cgroup": func(r *RawFullVerdict) { r.Cgroup++ }, "mode": func(r *RawFullVerdict) { r.Mode = 3 }, "decision": func(r *RawFullVerdict) { r.Deny = 1 }, "bitmap": func(r *RawFullVerdict) { r.MatchedRules[3] = 1 << 63 }, "error": func(r *RawFullVerdict) { r.Error = 4 }, "path length": func(r *RawFullVerdict) { r.PathResult++ }, "relative": func(r *RawFullVerdict) { r.Path = "bin/tool"; r.PathResult = 9 }, "unclean": func(r *RawFullVerdict) { r.Path = "/bin/../x"; r.PathResult = 10 }, "nul": func(r *RawFullVerdict) { r.Path = "/a\x00"; r.PathResult = 4 }} {
		t.Run(name, func(t *testing.T) {
			r := valid
			change(&r)
			if _, e := d.Decode(r); e == nil {
				t.Fatal("accepted malformed verdict")
			}
		})
	}
	for code := uint32(1); code <= 3; code++ {
		r := valid
		r.Error = code
		if _, e := d.Decode(r); e == nil {
			t.Fatal("operational allow")
		}
		r.Deny = 1
		r.Mode = 1
		if _, e := d.Decode(r); e == nil {
			t.Fatal("operational audit")
		}
		r.Mode = 2
		v, e := d.Decode(r)
		if e != nil || v.MatchesComplete || v.Rule != "" || v.Policy.UID != "" || v.Reason != "operational_error" || len(v.Matches) != 1 {
			t.Fatalf("fault %+v %v", v, e)
		}
	}
}
func TestFullVerdictMetadataValidation(t *testing.T) {
	b := sandboxpolicy.Binding{CgroupID: 19, ContainerName: "app"}
	for _, kind := range []string{"revision", "name", "origin", "uid", "predicate", "generation", "container"} {
		t.Run(kind, func(t *testing.T) {
			p := verdictPlan()
			k, e := CompileFull(b, p, 7, nil)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "revision":
				p.Policies[0].Revision = "other"
			case "name":
				k.Rules[0].Name = "other"
			case "origin":
				k.Rules[0].Origin = "other"
			case "uid":
				p.Policies[0].Identity.UID = "other"
			case "predicate":
				p.Policies[0].Exec.Rules[0].Target.Path = []string{"/other"}
			case "generation":
				k.Entries[0][0] = 0
			case "container":
				b.ContainerName = "other"
			}
			if _, e := NewFullVerdictDecoder(b, p, k); e == nil {
				t.Fatal("accepted mismatched provenance")
			}
		})
	}
}

func TestReadFullVerdict(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		var flags uint32
		if order == binary.BigEndian {
			flags = dsapi.DataSourceFlagsBigEndian
		}
		ds, e := datasource.NewFromAPI(&dsapi.DataSource{Name: "verdict", Type: uint32(datasource.TypeSingle), Flags: flags})
		if e != nil {
			t.Fatal(e)
		}
		for n, k := range map[string]dsapi.Kind{"generation": dsapi.Kind_Uint64, "cgroup": dsapi.Kind_Uint64, "deny": dsapi.Kind_Uint32, "mode": dsapi.Kind_Uint32, "host_pid": dsapi.Kind_Uint32, "path_result": dsapi.Kind_Int32, "path": dsapi.Kind_String, "matched_rules": dsapi.ArrayOf(dsapi.Kind_Uint64), "error": dsapi.Kind_Uint32} {
			if _, e = ds.AddField(n, k); e != nil {
				t.Fatal(e)
			}
		}
		data, err := ds.NewPacketSingle()
		if err != nil {
			t.Fatal(err)
		}
		defer ds.Release(data)
		ds.GetField("generation").PutUint64(data, 7)
		ds.GetField("cgroup").PutUint64(data, 19)
		ds.GetField("mode").PutUint32(data, 2)
		ds.GetField("deny").PutUint32(data, 0)
		ds.GetField("error").PutUint32(data, 0)
		ds.GetField("host_pid").PutUint32(data, 42)
		ds.GetField("path_result").PutInt32(data, -1)
		ds.GetField("path").PutString(data, "")
		bytes := make([]byte, 32)
		want := [4]uint64{1, 1 << 31, 1 << 32, 1 << 63}
		for i, word := range want {
			order.PutUint64(bytes[i*8:], word)
		}
		if err := ds.GetField("matched_rules").Set(data, bytes); err != nil {
			t.Fatal(err)
		}
		got, e := ReadFullVerdict(ds, data)
		if e != nil || got.MatchedRules != want || got.PID != 42 {
			t.Fatalf("read %+v %v", got, e)
		}
		// Typed accessors alone do not reject a different field kind.
		for _, field := range ds.Fields() {
			if field.Name != "matched_rules" {
				continue
			}
			for _, kind := range []dsapi.Kind{dsapi.Kind_Bytes, dsapi.Kind_Uint64, dsapi.ArrayOf(dsapi.Kind_Uint32)} {
				field.Kind = kind
				if _, err := ReadFullVerdict(ds, data); err == nil {
					t.Fatalf("accepted bitmap kind %v", kind)
				}
			}
			field.Kind = dsapi.ArrayOf(dsapi.Kind_Uint64)
		}
		for _, length := range []int{0, 8, 24, 31, 33, 40} {
			if err := ds.GetField("matched_rules").Set(data, make([]byte, length)); err != nil {
				t.Fatal(err)
			}
			if _, e = ReadFullVerdict(ds, data); e == nil {
				t.Fatalf("accepted bitmap length %d", length)
			}
		}
	}
	names := []string{"generation", "cgroup", "deny", "mode", "host_pid", "path_result", "path", "matched_rules", "error"}
	for _, missing := range names {
		ds, _ := datasource.New(datasource.TypeSingle, "missing")
		for _, name := range names {
			if name != missing {
				if _, err := ds.AddField(name, dsapi.Kind_Uint32); err != nil {
					t.Fatal(err)
				}
			}
		}
		if _, err := ReadFullVerdict(ds, nil); err == nil {
			t.Fatalf("accepted missing %s", missing)
		}
	}
	if _, e := ReadFullVerdict(nil, nil); e == nil {
		t.Fatal("nil datasource")
	}
}

func TestFullVerdictRetainedEpochSortedSnapshot(t *testing.T) {
	p := verdictPlan()
	p.Policies[0], p.Policies[1] = p.Policies[1], p.Policies[0]
	b := sandboxpolicy.Binding{CgroupID: 19, ContainerName: "app"}
	k, err := CompileFull(b, p, 7, map[string]uint64{"uid-one": 2})
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewFullVerdictDecoder(b, p, k)
	if err != nil {
		t.Fatal(err)
	}
	k.Rules[0].Name = "mutated"
	k.Entries[0][0] = 0
	v, err := d.Decode(RawFullVerdict{RawVerdict: RawVerdict{Generation: 7, Cgroup: 19, Mode: 2}, MatchedRules: [4]uint64{1}})
	if err != nil || v.Rule != "allow" || v.Policy.UID != "uid-one" || v.Revision != p.Revision || v.PolicySet[0].Policy.UID != "uid-one" {
		t.Fatalf("wrong sorted snapshot %+v %v", v, err)
	}
	p = verdictPlan()
	p.Policies = p.Policies[:1]
	d = verdictDecoder(t, p)
	v, err = d.Decode(RawFullVerdict{RawVerdict: RawVerdict{Generation: 7, Cgroup: 19, Mode: 2, Deny: 1}, Error: 1})
	if err != nil || v.Policy.UID != "uid-one" || v.Rule != "" || v.MatchesComplete {
		t.Fatalf("single policy context %+v %v", v, err)
	}
}

func TestFullVerdictAlwaysRetainsAggregateRevision(t *testing.T) {
	for _, name := range []string{"unique rule", "ambiguous rules", "single policy", "unique default", "ambiguous defaults", "single fault"} {
		t.Run(name, func(t *testing.T) {
			p := verdictPlan()
			r := RawFullVerdict{RawVerdict: RawVerdict{Generation: 7, Cgroup: 19, Deny: 1, Mode: 2}, MatchedRules: [4]uint64{4}}
			switch name {
			case "ambiguous rules":
				p.Policies[1].Exec.Rules = []api.ExecRule{p.Policies[0].Exec.Rules[2]}
				r.MatchedRules[0] = 12
			case "single policy":
				p.Policies = p.Policies[:1]
			case "unique default":
				r.MatchedRules = [4]uint64{}
				r.Mode = 1
			case "ambiguous defaults":
				r.MatchedRules = [4]uint64{}
				r.Mode = 1
				p.Policies[0].Exec.Default = "deny"
				p.Policies[0].Mode = "audit"
			case "single fault":
				p.Policies = p.Policies[:1]
				r.Error = 2
			}
			v, err := verdictDecoder(t, p).Decode(r)
			if err != nil {
				t.Fatal(err)
			}
			if v.Revision != p.Revision {
				t.Fatalf("aggregate revision changed: %q", v.Revision)
			}
			for _, policy := range v.PolicySet {
				if policy.Revision == "" || policy.Revision == p.Revision {
					t.Fatal("lost policy revision")
				}
			}
			for _, match := range v.Matches {
				if match.Revision == "" || match.Revision == p.Revision {
					t.Fatal("lost rule policy revision")
				}
			}
		})
	}
}
