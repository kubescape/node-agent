package igbackend

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"reflect"
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
		// G020 D1: on shared-engine events only, and only when the shared
		// engine opted the decoder in, an Audit infrastructure fault is a
		// would-deny operational error.
		shared := r
		shared.Shared, shared.ExecClass, shared.Pass, shared.LoadEpoch = true, 1, sharedVerdictPassUnknown, 11
		if v, e := d.Decode(shared); e == nil {
			t.Fatalf("shared audit fault without the decoder flag %+v", v)
		}
		d.sharedAuditFaults = true
		v, e := d.Decode(shared)
		d.sharedAuditFaults = false
		if e != nil || !v.WouldDeny || v.Verdict != api.ActionDeny || v.Mode != api.RuleAudit || v.MatchesComplete || v.Rule != "" || v.Reason != "operational_error" {
			t.Fatalf("shared audit fault %+v %v", v, e)
		}
		r.Mode = 2
		v, e = d.Decode(r)
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
		if err := ds.GetField("generation").PutUint64(data, 7); err != nil {
			t.Fatal(err)
		}
		if err := ds.GetField("cgroup").PutUint64(data, 19); err != nil {
			t.Fatal(err)
		}
		if err := ds.GetField("mode").PutUint32(data, 2); err != nil {
			t.Fatal(err)
		}
		if err := ds.GetField("deny").PutUint32(data, 0); err != nil {
			t.Fatal(err)
		}
		if err := ds.GetField("error").PutUint32(data, 0); err != nil {
			t.Fatal(err)
		}
		if err := ds.GetField("host_pid").PutUint32(data, 42); err != nil {
			t.Fatal(err)
		}
		if err := ds.GetField("path_result").PutInt32(data, -1); err != nil {
			t.Fatal(err)
		}
		if err := ds.GetField("path").PutString(data, ""); err != nil {
			t.Fatal(err)
		}
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

func TestFullVerdictOriginPresenceAndDefaultWinners(t *testing.T) {
	for _, tc := range []struct {
		name   string
		origin *string
		want   []string
	}{
		{"omitted", nil, []string{}},
		{"explicit empty", testOrigin(""), []string{""}},
		{"nonempty", testOrigin("source/rule"), []string{"source/rule"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := verdictPlan()
			p.Policies = p.Policies[:1]
			p.Policies[0].Exec.Rules = p.Policies[0].Exec.Rules[:1]
			p.Policies[0].Exec.Rules[0].Origin = tc.origin
			d := verdictDecoder(t, p)
			v, err := d.Decode(RawFullVerdict{RawVerdict: RawVerdict{Generation: 7, Cgroup: 19, Mode: 2}, MatchedRules: [4]uint64{1}})
			if err != nil || !reflect.DeepEqual(v.Origins, tc.want) || !reflect.DeepEqual(v.Matches[0].Origins, tc.want) {
				t.Fatalf("origins %v, matches %v, err %v", v.Origins, v.Matches, err)
			}
			data, err := json.Marshal(v)
			if err != nil || !bytes.Contains(data, []byte(`"origins":`+jsonList(t, tc.want))) {
				t.Fatalf("JSON %s: %v", data, err)
			}
		})
	}
	p := verdictPlan()
	p.Policies[0].Exec = api.ExecSection{Default: api.ActionDeny, DefaultOrigin: testOrigin("z")}
	p.Policies[0].Mode = api.ModeEnforce
	p.Policies[1].Exec = api.ExecSection{Default: api.ActionDeny, DefaultOrigin: testOrigin("")}
	p.Policies[1].Mode = api.ModeAudit
	third := p.Policies[1]
	third.Identity.UID = "uid-three"
	third.Exec = api.ExecSection{Default: api.ActionAllow, DefaultOrigin: testOrigin("loser")}
	p.Policies = append(p.Policies, third)
	fourth := p.Policies[1]
	fourth.Identity.UID = "uid-four"
	fourth.Exec.DefaultOrigin = testOrigin("z")
	p.Policies = append(p.Policies, fourth)
	d := verdictDecoder(t, p)
	// Caller mutation after decoder creation cannot change the snapshot.
	*p.Policies[0].Exec.DefaultOrigin = "changed"
	v, err := d.Decode(RawFullVerdict{RawVerdict: RawVerdict{Generation: 7, Cgroup: 19, Deny: 1, Mode: 2}})
	if err != nil || !reflect.DeepEqual(v.Origins, []string{"", "z"}) || v.Reason != "section_default" || v.Policy.UID != "" {
		t.Fatalf("winning default origins: %+v %v", v, err)
	}
	defaultJSON, err := json.Marshal(v)
	if err != nil || !bytes.Contains(defaultJSON, []byte(`"origins":["","z"]`)) {
		t.Fatalf("default origin JSON %s: %v", defaultJSON, err)
	}
	v.Origins[0] = "mutated"
	v, err = d.Decode(RawFullVerdict{RawVerdict: RawVerdict{Generation: 7, Cgroup: 19, Deny: 1, Mode: 2}})
	if err != nil || !reflect.DeepEqual(v.Origins, []string{"", "z"}) {
		t.Fatalf("decoder alias: %+v %v", v, err)
	}
}

func jsonList(t *testing.T, values []string) string {
	t.Helper()
	data, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func sharedVerdictDataSource(t *testing.T, cookie bool, skip string, wrong string) datasource.DataSource {
	t.Helper()
	ds, err := datasource.NewFromAPI(&dsapi.DataSource{Name: "verdict", Type: uint32(datasource.TypeSingle)})
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]dsapi.Kind{"generation": dsapi.Kind_Uint64, "cgroup": dsapi.Kind_Uint64, "deny": dsapi.Kind_Uint32, "mode": dsapi.Kind_Uint32, "host_pid": dsapi.Kind_Uint32, "path_result": dsapi.Kind_Int32, "path": dsapi.Kind_String, "matched_rules": dsapi.ArrayOf(dsapi.Kind_Uint64), "error": dsapi.Kind_Uint32}
	for name, kind := range sharedVerdictFields {
		fields[name] = kind
	}
	if cookie {
		fields[sharedVerdictTaskCookie] = dsapi.Kind_Uint64
	}
	for name, kind := range fields {
		if name == skip {
			continue
		}
		if name == wrong {
			kind = dsapi.Kind_Uint16
		}
		if _, err := ds.AddField(name, kind); err != nil {
			t.Fatal(err)
		}
	}
	return ds
}

func TestReadFullVerdictSharedFields(t *testing.T) {
	for _, cookie := range []bool{false, true} {
		ds := sharedVerdictDataSource(t, cookie, "", "")
		data, err := ds.NewPacketSingle()
		if err != nil {
			t.Fatal(err)
		}
		defer ds.Release(data)
		for name, value := range map[string]uint32{"mode": 1, "deny": 1, "error": 2, "exec_class": 1, "pass": sharedVerdictPassUnknown, "uncertain": 1, "facts_unknown": 0x81} {
			if err := ds.GetField(name).PutUint32(data, value); err != nil {
				t.Fatal(err)
			}
		}
		for name, value := range map[string]uint64{"generation": 7, "cgroup": 19, "scope": 5, "exec_id": 9, "load_epoch": 0xe90c} {
			if err := ds.GetField(name).PutUint64(data, value); err != nil {
				t.Fatal(err)
			}
		}
		if cookie {
			if err := ds.GetField(sharedVerdictTaskCookie).PutUint64(data, 77); err != nil {
				t.Fatal(err)
			}
		}
		if err := ds.GetField("path_result").PutInt32(data, -1); err != nil {
			t.Fatal(err)
		}
		if err := ds.GetField("matched_rules").Set(data, make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		got, err := ReadFullVerdict(ds, data)
		if err != nil || !got.Shared || got.ExecClass != 1 || got.Scope != 5 || got.ExecID != 9 || got.Pass != sharedVerdictPassUnknown || got.Uncertain != 1 || got.FactsUnknown != 0x81 || got.LoadEpoch != 0xe90c || got.HasTaskCookie != cookie || (cookie && got.TaskCookie != 77) {
			t.Fatalf("read %+v %v", got, err)
		}
		// D1 Audit fault with additive fields: refused unless the shared
		// engine enabled it, then a would-deny operational error, no pass.
		d := verdictDecoder(t, verdictPlan())
		if v, err := d.Decode(got); err == nil {
			t.Fatalf("decoder without the shared audit-fault flag accepted %+v", v)
		}
		d.sharedAuditFaults = true
		v, err := d.Decode(got)
		if err != nil || !v.WouldDeny || v.Reason != "operational_error" || v.Pass != nil || v.ExecID == nil || *v.ExecID != 9 || v.LoadEpoch == nil || *v.LoadEpoch != 0xe90c || (v.TaskCookie != nil) != cookie || v.ExecClass == nil || *v.ExecClass != 1 || v.Scope == nil || *v.Scope != 5 || v.Uncertain == nil || !*v.Uncertain || v.FactsUnknown == nil || *v.FactsUnknown != 0x81 {
			t.Fatalf("decode %+v %v", v, err)
		}
		if err := subscribeFullVerdicts(ds, nil, nil); err != nil {
			t.Fatalf("subscription refused additive schema: %v", err)
		}
	}
	// Partial, mistyped or orphaned additive fields are refused, never guessed.
	for name, ds := range map[string]datasource.DataSource{
		"partial":             sharedVerdictDataSource(t, false, "scope", ""),
		"no load_epoch":       sharedVerdictDataSource(t, true, "load_epoch", ""),
		"mistyped":            sharedVerdictDataSource(t, false, "", "exec_id"),
		"mistyped load_epoch": sharedVerdictDataSource(t, true, "", "load_epoch"),
		"mistyped cookie":     sharedVerdictDataSource(t, true, "", sharedVerdictTaskCookie),
	} {
		if err := subscribeFullVerdicts(ds, nil, nil); err == nil {
			t.Fatalf("%s: subscription accepted", name)
		}
		data, err := ds.NewPacketSingle()
		if err != nil {
			t.Fatal(err)
		}
		if err := ds.GetField("matched_rules").Set(data, make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadFullVerdict(ds, data); err == nil {
			t.Fatalf("%s: read accepted", name)
		}
		ds.Release(data)
	}
	orphan, _ := datasource.New(datasource.TypeSingle, "verdict")
	if _, err := orphan.AddField(sharedVerdictTaskCookie, dsapi.Kind_Uint64); err != nil {
		t.Fatal(err)
	}
	if _, _, err := checkSharedVerdictSchema(orphan); err == nil {
		t.Fatal("accepted task_cookie without the shared fields")
	}
}

func TestFullVerdictSharedValidation(t *testing.T) {
	d := verdictDecoder(t, verdictPlan())
	valid := RawFullVerdict{RawVerdict: RawVerdict{Generation: 7, Cgroup: 19, Mode: 2, PathResult: -1}, MatchedRules: [4]uint64{1}, Shared: true, ExecClass: 2, Pass: 5, ExecID: 3, LoadEpoch: 11}
	v, err := d.Decode(valid)
	if err != nil || v.Pass == nil || *v.Pass != 5 || v.ExecID == nil || *v.ExecID != 3 || v.LoadEpoch == nil || *v.LoadEpoch != 11 || v.TaskCookie != nil {
		t.Fatalf("decode %+v %v", v, err)
	}
	legacy := valid
	legacy.Shared = false
	if v, err := d.Decode(legacy); err != nil || v.Pass != nil || v.ExecID != nil || v.LoadEpoch != nil || v.ExecClass != nil || v.Scope != nil || v.Uncertain != nil || v.FactsUnknown != nil {
		t.Fatalf("legacy %+v %v", v, err)
	}
	for name, change := range map[string]func(*RawFullVerdict){"class": func(r *RawFullVerdict) { r.ExecClass = 3 }, "no class": func(r *RawFullVerdict) { r.ExecClass = 0 }, "pass": func(r *RawFullVerdict) { r.Pass = 6 }, "uncertain": func(r *RawFullVerdict) { r.Uncertain = 2 }, "no load epoch": func(r *RawFullVerdict) { r.LoadEpoch = 0 }} {
		r := valid
		change(&r)
		if _, err := d.Decode(r); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// TestFullVerdictSharedAuditFaultFlag: the G020 D1 Audit fault decodes only
// on a decoder the shared engine opted in, and only on a shared event; a
// Strict fault decodes either way.
func TestFullVerdictSharedAuditFaultFlag(t *testing.T) {
	audit := RawFullVerdict{RawVerdict: RawVerdict{Generation: 7, Cgroup: 19, Deny: 1, Mode: 1, PathResult: -1}, Error: 1, Shared: true, ExecClass: 1, Pass: sharedVerdictPassUnknown, ExecID: 3, LoadEpoch: 11}
	strict := audit
	strict.Mode, strict.ExecClass = 2, 2
	legacy := audit
	legacy.Shared, legacy.ExecClass, legacy.Pass, legacy.ExecID, legacy.LoadEpoch = false, 0, 0, 0, 0
	for _, flag := range []bool{false, true} {
		d := verdictDecoder(t, verdictPlan())
		d.sharedAuditFaults = flag
		v, err := d.Decode(audit)
		if flag != (err == nil) {
			t.Fatalf("flag %v: audit fault %+v %v", flag, v, err)
		}
		if flag && (!v.WouldDeny || v.Verdict != api.ActionDeny || v.Mode != api.RuleAudit || v.Reason != "operational_error" || v.MatchesComplete) {
			t.Fatalf("flag %v: audit fault %+v", flag, v)
		}
		if v, err := d.Decode(strict); err != nil || v.WouldDeny || v.Reason != "operational_error" {
			t.Fatalf("flag %v: strict fault %+v %v", flag, v, err)
		}
		if _, err := d.Decode(legacy); err == nil {
			t.Fatalf("flag %v: legacy audit fault accepted", flag)
		}
	}
}

func TestFullVerdictCatalogSharedAuditFaults(t *testing.T) {
	b := sandboxpolicy.Binding{CgroupID: 19, ContainerName: "app"}
	for _, flag := range []bool{false, true} {
		c := NewFullVerdictCatalog(b)
		c.sharedAuditFaults = flag
		k, err := CompileFull(b, verdictPlan(), 7, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Stage(7, verdictPlan(), k); err != nil {
			t.Fatal(err)
		}
		if c.decoders[7].sharedAuditFaults != flag {
			t.Fatalf("catalog flag %v not carried to its decoder", flag)
		}
	}
}
