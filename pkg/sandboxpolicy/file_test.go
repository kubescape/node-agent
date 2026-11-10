package sandboxpolicy

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	filepolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/policy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func boolPtr(v bool) *bool { return &v }

func fileRule(name string, action api.Action, target api.FileTarget) api.FileRule {
	return api.FileRule{Rule: api.Rule{Name: name, Action: action}, Target: target}
}

// fileSpec has a scalar default.
func fileSpec(def api.Action, rules ...api.FileRule) api.PolicySpec {
	return api.PolicySpec{Containers: []string{"*"}, Mode: api.ModeEnforce,
		File: &api.FileSection{Default: def, Rules: rules}}
}

// writesConfined is the design's per-access default: reads open, the rest denied.
func writesConfined() *api.FileAccessDefaults {
	return &api.FileAccessDefaults{Read: api.ActionAllow, Write: api.ActionDeny, Create: api.ActionDeny,
		Delete: api.ActionDeny, Rename: api.ActionDeny, Chmod: api.ActionDeny, ExecMap: api.ActionAllow}
}

// confine replaces the scalar default with writesConfined.
func confine(f *api.FileSection) {
	f.Default, f.DefaultByAccess = "", writesConfined()
}

func translateFile(t *testing.T, spec api.PolicySpec, shared map[string][]string) *FilePlan {
	t.Helper()
	plan, err := TranslateFile(spec, shared, FileNode{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func fileRuleByName(plan *FilePlan, name string) *filepolicy.Rule {
	for i, r := range plan.Doc.Policy.File.Rules {
		if r.Name == name {
			return &plan.Doc.Policy.File.Rules[i]
		}
	}
	return nil
}

func fileDegraded(plan *FilePlan, rule string) *api.DegradedRule {
	for i, d := range plan.Report.Degraded {
		if d.Rule == rule {
			return &plan.Report.Degraded[i]
		}
	}
	return nil
}

func notEnforcedHas(t *testing.T, plan *FilePlan, want ...string) {
	t.Helper()
	got := strings.Join(plan.Report.NotEnforced, ";")
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("NotEnforced %q lacks %q", got, w)
		}
	}
}

func TestTranslateFileRules(t *testing.T) {
	spec := fileSpec("",
		fileRule("workspace", api.ActionAllow, api.FileTarget{Access: []string{"rename", "write", "create", "delete"}, PathTarget: api.PathTarget{Path: []string{"/workspace/**", "/tmp/**"}}}),
		fileRule("no-agent-config", api.ActionDeny, api.FileTarget{Access: []string{"write", "create"}, PathTarget: api.PathTarget{PathClass: []string{"agentConfig"}}}),
		fileRule("no-image-tamper", api.ActionDeny, api.FileTarget{Access: []string{"write", "delete", "rename", "chmod"}, PathTarget: api.PathTarget{FromImage: boolPtr(true)}}),
		fileRule("nothing-anywhere", api.ActionDeny, api.FileTarget{Access: []string{"chmod"}}),
		fileRule("no-wx", api.ActionDeny, api.FileTarget{Access: []string{"execMap"}}),
		fileRule("hooks", api.ActionDeny, api.FileTarget{Access: []string{"write", "execMap"}, PathTarget: api.PathTarget{Path: []string{"**/.git/hooks/**"}}}),
	)
	confine(spec.File)
	spec.File.Rules[1].Mode, spec.File.Rules[1].Origin = api.RuleEnforce, testOriginString("catalog/C1")
	spec.File.DefaultModeByAccess = &api.FileAccessModes{Write: api.RuleEnforce, Create: api.RuleAudit}
	spec.File.DefaultOriginByAccess = &api.FileAccessOrigins{Write: testOriginString("catalog/D1"), Chmod: testOriginString("catalog/D1")}
	plan := translateFile(t, spec, nil)
	p := plan.Doc.Policy
	if p.Mode != "enforce" || plan.Doc.Version != 1 {
		t.Fatalf("document header %+v", plan.Doc)
	}
	want := map[string]filepolicy.Default{
		"read": {Action: "allow"}, "write": {Action: "deny", Mode: "enforce", Origin: testOriginString("catalog/D1")}, "create": {Action: "deny", Mode: "audit"},
		"delete": {Action: "deny"}, "rename": {Action: "deny"}, "chmod": {Action: "deny", Origin: testOriginString("catalog/D1")},
	}
	if !reflect.DeepEqual(p.File.Defaults, want) {
		t.Fatalf("defaults %+v", p.File.Defaults)
	}
	ws := fileRuleByName(plan, "workspace")
	if ws == nil || !reflect.DeepEqual(ws.Access, []string{"write", "create", "delete", "rename"}) || !reflect.DeepEqual(ws.Paths, []string{"/tmp/**", "/workspace/**"}) {
		t.Fatalf("workspace %+v", ws)
	}
	ac := fileRuleByName(plan, "no-agent-config")
	if ac == nil || ac.Mode != "enforce" || ac.Origin == nil || *ac.Origin != "catalog/C1" || !reflect.DeepEqual(ac.Paths, sortedUnique(slices.Clone(defaultPathClasses["agentConfig"]))) {
		t.Fatalf("agent config %+v", ac)
	}
	if img := fileRuleByName(plan, "no-image-tamper"); img == nil || !img.FromImage || len(img.Paths) != 0 {
		t.Fatalf("fromImage rule %+v", img)
	}
	if all := fileRuleByName(plan, "nothing-anywhere"); all == nil || !reflect.DeepEqual(all.Paths, []string{"/**"}) {
		t.Fatalf("an empty target must match every path: %+v", all)
	}
	if fileRuleByName(plan, "no-wx") != nil {
		t.Fatal("an execMap-only rule must not reach the gadget")
	}
	if h := fileRuleByName(plan, "hooks"); h == nil || !reflect.DeepEqual(h.Access, []string{"write"}) {
		t.Fatalf("hooks %+v", h)
	}
	notEnforcedHas(t, plan, "rule no-wx: access execMap", "rule hooks: access execMap")
	dev := fileRuleByName(plan, "runtime-devices")
	if dev == nil || dev.Action != "allow" || !slices.Contains(dev.Paths, "/dev/null") || !slices.Contains(dev.Paths, "/dev/pts/**") ||
		!reflect.DeepEqual(dev.Access, []string{"read", "write"}) {
		t.Fatalf("runtime devices %+v", dev)
	}
	shm := fileRuleByName(plan, "runtime-shm")
	if shm == nil || shm.Action != "allow" || !reflect.DeepEqual(shm.Paths, []string{"/dev/shm/**"}) ||
		!reflect.DeepEqual(shm.Access, []string{"read", "write", "create", "delete"}) {
		t.Fatalf("runtime shm %+v", shm)
	}
	if plan.Report.NotReady != "" || len(plan.Report.Degraded) != 0 || plan.Report.Rules != 6 || plan.Report.ClassesResolved != 1 {
		t.Fatalf("report %+v", plan.Report)
	}
}

func TestTranslateFileScalarDefault(t *testing.T) {
	spec := fileSpec(api.ActionDeny)
	spec.Mode = api.ModeAudit
	spec.File.DefaultMode, spec.File.DefaultOrigin = api.RuleEnforce, testOriginString("catalog/X")
	plan := translateFile(t, spec, nil)
	for _, k := range filepolicy.AccessKinds {
		if d := plan.Doc.Policy.File.Defaults[k]; !reflect.DeepEqual(d, filepolicy.Default{Action: "deny", Mode: "enforce", Origin: testOriginString("catalog/X")}) {
			t.Fatalf("default %s %+v", k, d)
		}
	}
	notEnforcedHas(t, plan, "default execMap deny")
	if plan.Doc.Policy.Mode != "audit" {
		t.Fatalf("mode %q", plan.Doc.Policy.Mode)
	}
	if plan := translateFile(t, fileSpec(api.ActionAllow), nil); len(plan.Report.NotEnforced) != 0 {
		t.Fatalf("an execMap allow default loses nothing: %v", plan.Report.NotEnforced)
	}
}

// Origin presence and the default modes reach the gadget document: a missing
// origin stays nil, an explicit "" stays "", for rules, the scalar default and
// the per-access defaults.
func TestFileDocumentOriginPresenceAndDefaults(t *testing.T) {
	empty := ""
	spec := fileSpec(api.ActionDeny,
		fileRule("none", api.ActionDeny, api.FileTarget{PathTarget: api.PathTarget{Path: []string{"/none"}}}),
		fileRule("blank", api.ActionDeny, api.FileTarget{PathTarget: api.PathTarget{Path: []string{"/blank"}}}))
	spec.File.Rules[1].Origin = &empty
	spec.File.DefaultMode, spec.File.DefaultOrigin = api.RuleAudit, &empty
	f := translateFile(t, spec, nil).Doc.Policy.File
	if r := f.Rules[0]; r.Name != "none" || r.Origin != nil {
		t.Fatalf("absent rule origin: %+v", r)
	}
	if r := f.Rules[1]; r.Name != "blank" || r.Origin == nil || *r.Origin != "" {
		t.Fatalf("explicit empty rule origin: %+v", r)
	}
	for _, k := range filepolicy.AccessKinds {
		if d := f.Defaults[k]; d.Mode != "audit" || d.Origin == nil || *d.Origin != "" {
			t.Fatalf("scalar default %s: mode %q origin %v", k, d.Mode, d.Origin)
		}
	}
	spec.File.DefaultOrigin = nil
	if d := translateFile(t, spec, nil).Doc.Policy.File.Defaults[filepolicy.AccessRead]; d.Origin != nil {
		t.Fatal("a missing default origin must stay missing")
	}

	spec.File.DefaultMode = ""
	confine(spec.File)
	spec.File.DefaultModeByAccess = &api.FileAccessModes{Write: api.RuleAudit, Chmod: api.RuleEnforce}
	spec.File.DefaultOriginByAccess = &api.FileAccessOrigins{Write: &empty, Chmod: testOriginString("catalog/D1")}
	f = translateFile(t, spec, nil).Doc.Policy.File
	if d := f.Defaults[filepolicy.AccessWrite]; d.Mode != "audit" || d.Origin == nil || *d.Origin != "" {
		t.Fatalf("write default: mode %q origin %v", d.Mode, d.Origin)
	}
	if d := f.Defaults[filepolicy.AccessChmod]; d.Mode != "enforce" || d.Origin == nil || *d.Origin != "catalog/D1" {
		t.Fatalf("chmod default: mode %q origin %v", d.Mode, d.Origin)
	}
	if d := f.Defaults[filepolicy.AccessDelete]; d.Mode != "" || d.Origin != nil {
		t.Fatalf("delete default: mode %q origin %v", d.Mode, d.Origin)
	}
}

func TestTranslateFileValidates(t *testing.T) {
	exceptA := []api.FileException{{Target: &api.FileTarget{PathTarget: api.PathTarget{Path: []string{"/a"}}}}}
	for name, mutate := range map[string]func(*api.PolicySpec){
		"default":     func(s *api.PolicySpec) { s.File.Default = "maybe" },
		"no default":  func(s *api.PolicySpec) { s.File.Default = "" },
		"access":      func(s *api.PolicySpec) { s.File.Rules[0].Target.Access = []string{"exec"} },
		"fsType":      func(s *api.PolicySpec) { s.File.Rules[0].Target.FSType = []string{"ext4"} },
		"empty path":  func(s *api.PolicySpec) { s.File.Rules[0].Target.Path = []string{" "} },
		"empty class": func(s *api.PolicySpec) { s.File.Rules[0].Target.PathClass = []string{""} },
		"action":      func(s *api.PolicySpec) { s.File.Rules[0].Action = "block" },
		"mode":        func(s *api.PolicySpec) { s.File.Rules[0].Mode = "tripwire" },
		"actor":       func(s *api.PolicySpec) { s.File.Rules[0].Actor = &api.Actor{Path: []string{"/bin/sh"}} },
		"defaultMode": func(s *api.PolicySpec) { s.File.DefaultMode = "tripwire" },
		"both defaults": func(s *api.PolicySpec) {
			s.File.DefaultByAccess = writesConfined()
		},
		"incomplete by access": func(s *api.PolicySpec) {
			confine(s.File)
			s.File.DefaultByAccess.Chmod = ""
		},
		"mode by access": func(s *api.PolicySpec) {
			confine(s.File)
			s.File.DefaultModeByAccess = &api.FileAccessModes{Chmod: "loud"}
		},
		"scalar default with by-access mode": func(s *api.PolicySpec) {
			s.File.DefaultModeByAccess = &api.FileAccessModes{Write: api.RuleAudit}
		},
		"per-access default with scalar origin": func(s *api.PolicySpec) {
			confine(s.File)
			s.File.DefaultOrigin = testOriginString("catalog/D1")
		},
		"except on allow": func(s *api.PolicySpec) {
			s.File.Rules[0].Action = api.ActionAllow
			s.File.Rules[0].Except = exceptA
		},
		"empty except": func(s *api.PolicySpec) {
			s.File.Rules[0].Except = []api.FileException{{Target: &api.FileTarget{}}}
		},
		"except access": func(s *api.PolicySpec) {
			s.File.Rules[0].Except = []api.FileException{{Target: &api.FileTarget{Access: []string{"open"}}}}
		},
	} {
		spec := fileSpec(api.ActionAllow, fileRule("r", api.ActionDeny, api.FileTarget{PathTarget: api.PathTarget{Path: []string{"/etc/**"}}}))
		mutate(&spec)
		if _, err := TranslateFile(spec, nil, FileNode{}, nil); err == nil {
			t.Errorf("%s: invalid input accepted", name)
		}
	}
}

func TestFilePathClasses(t *testing.T) {
	spec := fileSpec(api.ActionAllow,
		fileRule("no-keys", api.ActionDeny, api.FileTarget{PathTarget: api.PathTarget{PathClass: []string{"sshKeys"}, Path: []string{"/srv/key"}}}),
		fileRule("no-backend", api.ActionDeny, api.FileTarget{PathTarget: api.PathTarget{PathClass: []string{"backendOnly"}}}),
	)
	spec.Classes = &api.PolicyClasses{PathClasses: map[string][]string{"sshKeys": {"/opt/keys/**"}}}
	shared := map[string][]string{"sshKeys": {"/data/ssh/**"}, "backendOnly": {"/var/lib/backend/**"}}
	plan := translateFile(t, spec, shared)
	keys := fileRuleByName(plan, "no-keys")
	want := []string{"/data/ssh/**", "/home/*/.ssh/**", "/opt/keys/**", "/root/.ssh/**", "/srv/..*/key", "/srv/key"}
	if keys == nil || !reflect.DeepEqual(keys.Paths, want) {
		t.Fatalf("built-in, shared, policy and literal paths must combine: %+v", keys)
	}
	if b := fileRuleByName(plan, "no-backend"); b == nil || !reflect.DeepEqual(b.Paths, []string{"/var/lib/backend/**"}) {
		t.Fatalf("shared class %+v", b)
	}
	if plan.Report.ClassesResolved != 2 || plan.Report.ClassesUnresolved != 0 {
		t.Fatalf("report %+v", plan.Report)
	}
	// Another policy's addition does not reach this one.
	other := fileSpec(api.ActionAllow, fileRule("no-keys", api.ActionDeny, api.FileTarget{PathTarget: api.PathTarget{PathClass: []string{"sshKeys"}}}))
	if r := fileRuleByName(translateFile(t, other, nil), "no-keys"); slices.Contains(r.Paths, "/opt/keys/**") {
		t.Fatal("a policy-local class addition must stay local")
	}
}

func TestFileUnresolvedClassFailsClosed(t *testing.T) {
	spec := fileSpec("",
		fileRule("no-model-cache", api.ActionDeny, api.FileTarget{Access: []string{"read"}, PathTarget: api.PathTarget{PathClass: []string{"modelCache"}}}),
		fileRule("work", api.ActionAllow, api.FileTarget{Access: []string{"write", "create"}, PathTarget: api.PathTarget{PathClass: []string{"workspace"}, Path: []string{"/tmp/**"}}}),
	)
	confine(spec.File)
	spec.File.DefaultModeByAccess = &api.FileAccessModes{Create: api.RuleAudit}
	plan := translateFile(t, spec, nil)
	if fileRuleByName(plan, "no-model-cache") != nil {
		t.Fatal("a deny without any path must not reach the gadget")
	}
	notEnforcedHas(t, plan, "rule no-model-cache: no path is resolved")
	// The allow keeps its literal path; the defaults keep their modes.
	if w := fileRuleByName(plan, "work"); w == nil || !reflect.DeepEqual(w.Paths, []string{"/tmp/**"}) {
		t.Fatalf("allow %+v", w)
	}
	defs := plan.Doc.Policy.File.Defaults
	if defs["write"].Mode == "audit" || defs["create"].Mode != "audit" {
		t.Fatalf("an unresolved class must not degrade a default: %+v", defs)
	}
	if fileDegraded(plan, "default/write") != nil {
		t.Fatal("no default is degraded")
	}
	if plan.Report.NotReady != "ClassUnresolved" || plan.Report.ClassesUnresolved != 2 {
		t.Fatalf("report %+v", plan.Report)
	}

	// A deny with a resolved part keeps the resolved paths at enforce: an
	// ssh key read stays denied while another class is unresolved.
	partial := fileSpec(api.ActionAllow, fileRule("d", api.ActionDeny, api.FileTarget{PathTarget: api.PathTarget{PathClass: []string{"sshKeys", "modelCache"}}}))
	plan = translateFile(t, partial, nil)
	r := fileRuleByName(plan, "d")
	if r == nil || len(r.Paths) == 0 || r.Mode == "audit" {
		t.Fatalf("partly resolved deny must keep its resolved paths at enforce: %+v", r)
	}
	if d := fileDegraded(plan, "d"); d == nil || d.Effective == "audit" || d.Reason != "class-unresolved" {
		t.Fatalf("partly resolved deny %+v", d)
	}
	if plan.Report.NotReady != "ClassUnresolved" {
		t.Fatalf("a partly resolved deny makes the policy NotReady: %+v", plan.Report)
	}
	// An allow without access leaves every default as it is.
	every := fileSpec(api.ActionDeny, fileRule("a", api.ActionAllow, api.FileTarget{PathTarget: api.PathTarget{PathClass: []string{"workspace"}}}))
	plan = translateFile(t, every, nil)
	for _, k := range filepolicy.AccessKinds {
		if plan.Doc.Policy.File.Defaults[k].Mode == "audit" || fileDegraded(plan, "default/"+k) != nil {
			t.Fatalf("default %s must not run in audit: %+v", k, plan.Doc.Policy.File.Defaults[k])
		}
	}
}

func TestFileExcept(t *testing.T) {
	deny := func() api.PolicySpec {
		return fileSpec(api.ActionAllow, fileRule("no-agent-config", api.ActionDeny, api.FileTarget{Access: []string{"write", "create"}, PathTarget: api.PathTarget{Path: []string{"**/.claude/**"}}}))
	}
	path := func(p ...string) *api.FileTarget { return &api.FileTarget{PathTarget: api.PathTarget{Path: p}} }
	for name, tc := range map[string]struct {
		entries  []api.FileException
		lifted   []string
		notReady string
		disabled string
	}{
		"path":            {entries: []api.FileException{{Target: path("/workspace/.claude/settings.local.json")}}, lifted: []string{"/workspace/.claude/..*/settings.local.json", "/workspace/.claude/settings.local.json"}},
		"covering access": {entries: []api.FileException{{Target: &api.FileTarget{Access: []string{"create", "write", "read"}, PathTarget: api.PathTarget{Path: []string{"/a/.claude/x"}}}}}, lifted: []string{"/a/.claude/..*/x", "/a/.claude/x"}},
		"partial access":  {entries: []api.FileException{{Target: &api.FileTarget{Access: []string{"write"}, PathTarget: api.PathTarget{Path: []string{"/a/.claude/x"}}}}}, disabled: "must cover every access kind"},
		"unresolved class": {entries: []api.FileException{{Target: &api.FileTarget{PathTarget: api.PathTarget{PathClass: []string{"workspace"}}}}},
			notReady: "ClassUnresolved", disabled: "class-unresolved"},
		"fsType":  {entries: []api.FileException{{Target: &api.FileTarget{PathTarget: api.PathTarget{FSType: []string{"tmpfs"}}}}}, disabled: "fromImage and fsType"},
		"actor":   {entries: []api.FileException{{Actor: &api.Actor{Path: []string{"/bin/git"}}}}, disabled: "actor predicates"},
		"pattern": {entries: []api.FileException{{Target: path("/a/.claude/fil?")}}, disabled: "cannot be expressed"},
		"two":     {entries: []api.FileException{{Target: path("/b/.claude/y")}, {Actor: &api.Actor{UID: []int64{0}}}}, lifted: []string{"/b/.claude/..*/y", "/b/.claude/y"}, disabled: "except 1 is disabled"},
	} {
		t.Run(name, func(t *testing.T) {
			spec := deny()
			spec.File.Rules[0].Except = tc.entries
			plan := translateFile(t, spec, nil)
			r := fileRuleByName(plan, "no-agent-config")
			if r == nil || r.Mode != "" || !reflect.DeepEqual(r.Except, tc.lifted) {
				t.Fatalf("rule %+v", r)
			}
			if plan.Report.NotReady != tc.notReady {
				t.Fatalf("not ready %q", plan.Report.NotReady)
			}
			if tc.disabled != "" {
				notEnforcedHas(t, plan, tc.disabled, "the deny applies there")
			}
			if tc.notReady != "" {
				if d := fileDegraded(plan, "no-agent-config"); d == nil || d.Reason != "except-class-unresolved" || d.Effective != "enforce" {
					t.Fatalf("degraded %+v", d)
				}
			}
		})
	}
}

func TestFileNotEnforceableTargets(t *testing.T) {
	spec := fileSpec("",
		fileRule("no-tmpfs-write", api.ActionDeny, api.FileTarget{Access: []string{"write"}, PathTarget: api.PathTarget{FSType: []string{"tmpfs"}}}),
		fileRule("tmpfs-ok", api.ActionAllow, api.FileTarget{Access: []string{"create"}, PathTarget: api.PathTarget{FSType: []string{"tmpfs"}}}),
		fileRule("own-files", api.ActionAllow, api.FileTarget{Access: []string{"delete"}, PathTarget: api.PathTarget{FromImage: boolPtr(false)}}),
		fileRule("odd", api.ActionDeny, api.FileTarget{PathTarget: api.PathTarget{Path: []string{"/etc/shadow", "/etc/[ab]"}}}),
		fileRule("odd-allow", api.ActionAllow, api.FileTarget{Access: []string{"rename"}, PathTarget: api.PathTarget{Path: []string{"/w/fil?"}}}),
	)
	confine(spec.File)
	plan := translateFile(t, spec, nil)
	for _, name := range []string{"no-tmpfs-write", "tmpfs-ok", "own-files", "odd-allow"} {
		if fileRuleByName(plan, name) != nil {
			t.Errorf("rule %s must not reach the gadget", name)
		}
	}
	if odd := fileRuleByName(plan, "odd"); odd == nil || !reflect.DeepEqual(odd.Paths, []string{"/etc/..*/shadow", "/etc/shadow"}) {
		t.Fatalf("a deny keeps the globs the gadget can match: %+v", odd)
	}
	notEnforcedHas(t, plan, "rule no-tmpfs-write: fsType", "rule tmpfs-ok: fsType", "rule own-files: fromImage false", "rule odd: path /etc/[ab]", "rule odd-allow: path /w/fil?")
	// An allow the gadget cannot judge must not turn its accesses into an
	// enforced deny: their defaults run in audit.
	defs := plan.Doc.Policy.File.Defaults
	for k, want := range map[string]string{"write": "", "create": "audit", "delete": "audit", "rename": "audit", "chmod": ""} {
		if defs[k].Mode != want {
			t.Errorf("default %s mode %q, want %q", k, defs[k].Mode, want)
		}
	}
	if d := fileDegraded(plan, "default/create"); d == nil || d.Reason != "not-enforceable" {
		t.Fatalf("create default %+v", d)
	}
	// Review 2 finding 6: an allow rule that cannot be enforced makes the
	// policy not ready, as in the network section.
	if plan.Report.NotReady != "RuleNotEnforceable" {
		t.Fatalf("not ready %q", plan.Report.NotReady)
	}
	// A deny the gadget cannot judge is reported, not a reason to be not ready.
	denyOnly := fileSpec(api.ActionAllow, fileRule("no-tmpfs-write", api.ActionDeny, api.FileTarget{Access: []string{"write"}, PathTarget: api.PathTarget{FSType: []string{"tmpfs"}}}))
	if r := translateFile(t, denyOnly, nil).Report.NotReady; r != "" {
		t.Fatalf("deny only: not ready %q", r)
	}
	// ClassUnresolved is the stronger reason.
	both := fileSpec("",
		fileRule("tmpfs-ok", api.ActionAllow, api.FileTarget{Access: []string{"create"}, PathTarget: api.PathTarget{FSType: []string{"tmpfs"}}}),
		fileRule("work", api.ActionAllow, api.FileTarget{Access: []string{"write"}, PathTarget: api.PathTarget{PathClass: []string{"workspace"}}}),
	)
	confine(both.File)
	if r := translateFile(t, both, nil).Report.NotReady; r != "ClassUnresolved" {
		t.Fatalf("both: not ready %q", r)
	}
}

func TestFileRuntimeDevicesNameIsFree(t *testing.T) {
	plan := translateFile(t, fileSpec(api.ActionAllow, fileRule("runtime-devices", api.ActionDeny, api.FileTarget{PathTarget: api.PathTarget{Path: []string{"/dev/mem"}}})), nil)
	if r := fileRuleByName(plan, "runtime-devices"); r == nil || r.Action != "deny" {
		t.Fatalf("the policy's rule keeps its name: %+v", r)
	}
	if r := fileRuleByName(plan, "runtime-devices~1"); r == nil || r.Action != "allow" {
		t.Fatalf("built-in rule %+v", r)
	}
}

func TestFileDocumentCheckFails(t *testing.T) {
	saved := checkFileDocument
	defer func() { checkFileDocument = saved }()
	checkFileDocument = func(filepolicy.Document) error { return errors.New("over limits") }
	if _, err := TranslateFile(fileSpec(api.ActionAllow), nil, FileNode{}, nil); err == nil || !strings.Contains(err.Error(), "file: over limits") {
		t.Fatalf("err %v", err)
	}
}

// filePolicyObject builds a SandboxPolicy object. extras are set on the file
// section; a "defaultByAccess" extra replaces the scalar default.
func filePolicyObject(name string, spec api.PolicySpec, extras map[string]any) *unstructured.Unstructured {
	p := &api.SandboxPolicy{TypeMeta: metav1.TypeMeta{APIVersion: api.SchemeGroupVersion.String(), Kind: "SandboxPolicy"}, ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns", UID: types.UID("uid-" + name), Generation: 1},
		Spec: api.SandboxPolicySpec{PolicySpec: spec}}
	raw, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(p)
	file := raw["spec"].(map[string]any)["file"].(map[string]any)
	if _, ok := extras["defaultByAccess"]; ok {
		delete(file, "default")
	}
	for k, v := range extras {
		file[k] = v
	}
	return &unstructured.Unstructured{Object: raw}
}

func TestControllerFilePlanAndStatus(t *testing.T) {
	ctx := context.Background()
	spec := fileSpec(api.ActionAllow,
		fileRule("work", api.ActionAllow, api.FileTarget{Access: []string{"write"}, PathTarget: api.PathTarget{PathClass: []string{"workspace"}}}),
		fileRule("no-wx", api.ActionDeny, api.FileTarget{Access: []string{"execMap"}}))
	c, backend, w, _ := setup(t)
	obj := filePolicyObject("files", spec, map[string]any{
		"defaultByAccess":     map[string]any{"read": "allow", "write": "deny", "create": "deny", "delete": "deny", "rename": "deny", "chmod": "deny", "execMap": "allow"},
		"defaultModeByAccess": map[string]any{"write": "enforce"},
	})
	c.objects[objectKey(obj)] = obj
	if err := c.SetBindings(ctx, []Binding{binding()}); err != nil {
		t.Fatal(err)
	}
	plan := backend.plans[bindingKey(binding())]
	if len(plan.Policies) != 1 || plan.Policies[0].File == nil || fileRuleByName(plan.Policies[0].File, "runtime-devices") == nil {
		t.Fatalf("file plan not sent to the backend: %+v", plan)
	}
	if d := plan.Policies[0].File.Doc.Policy.File.Defaults["write"]; d.Action != "deny" || d.Mode == "audit" {
		t.Fatalf("an unresolved allow class must not degrade the write default: %+v", d)
	}
	report := w.reports["uid-files"]
	ready := report.Status.Conditions[0]
	if ready.Status != metav1.ConditionFalse || ready.Reason != "ClassUnresolved" || !strings.Contains(ready.Message, "file allow rule") {
		t.Fatalf("ready %+v", ready)
	}
	if report.Status.Counts.Degraded != 2 || report.Status.Compiled == nil || report.Status.Compiled.Rules != 2 || report.Status.Compiled.ClassesUnresolved != 1 {
		t.Fatalf("status %+v", report.Status)
	}
	found := false
	for _, cond := range report.Status.Conditions {
		found = found || (cond.Type == "FileNotEnforced" && cond.Reason == "UnsupportedByGadget" && strings.Contains(cond.Message, "rule no-wx"))
	}
	if !found {
		t.Fatalf("execMap rule not reported: %+v", report.Status.Conditions)
	}

	// The class resolves: the plan changes (new revision) and the policy is ready.
	classes := &api.SandboxPolicyClasses{TypeMeta: metav1.TypeMeta{APIVersion: api.SchemeGroupVersion.String(), Kind: "SandboxPolicyClasses"}, ObjectMeta: metav1.ObjectMeta{Name: "backend", UID: "classes"},
		Spec: api.PolicyClasses{PathClasses: map[string][]string{"workspace": {"/workspace/**"}}}}
	raw, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(classes)
	c.objects[objectKey(&unstructured.Unstructured{Object: raw})] = &unstructured.Unstructured{Object: raw}
	if err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	next := backend.plans[bindingKey(binding())]
	if next.Revision == plan.Revision || fileRuleByName(next.Policies[0].File, "work") == nil {
		t.Fatal("a class change must give a new plan")
	}
	if ready := w.reports["uid-files"].Status.Conditions[0]; ready.Status != metav1.ConditionTrue {
		t.Fatalf("resolved class must be ready: %+v", ready)
	}
}

func TestControllerRejectsInvalidFileSection(t *testing.T) {
	ctx := context.Background()
	c, backend, w, _ := setup(t)
	obj := filePolicyObject("files", fileSpec(api.ActionAllow), map[string]any{"defaultModeByAccess": map[string]any{"write": "enforce"}})
	c.objects[objectKey(obj)] = obj
	if err := c.SetBindings(ctx, []Binding{binding()}); err == nil {
		t.Fatal("a by-access mode with a scalar default must be rejected")
	}
	if len(backend.plans) != 0 || w.reports["uid-files"].Status.Conditions[0].Status != metav1.ConditionFalse {
		t.Fatal("an invalid file section must not be installed")
	}
}

func TestStatusCombinesNetworkAndFile(t *testing.T) {
	ctx := context.Background()
	spec := fileSpec(api.ActionAllow, fileRule("no-wx", api.ActionDeny, api.FileTarget{Access: []string{"execMap"}}))
	spec.Network = &api.NetworkSection{Default: api.NetworkDefault{Egress: api.ActionAllow, Listen: api.ActionAllow},
		Rules: []api.NetworkRule{netRule("models", api.ActionAllow, api.NetworkTarget{DestClass: []string{"modelProvider"}})}}
	c, _, w, _ := setup(t)
	obj := filePolicyObject("both", spec, nil)
	c.objects[objectKey(obj)] = obj
	if err := c.SetBindings(ctx, []Binding{binding()}); err != nil {
		t.Fatal(err)
	}
	status := w.reports["uid-both"].Status
	if ready := status.Conditions[0]; ready.Reason != "ClassUnresolved" || !strings.Contains(ready.Message, "network allow rule") || strings.Contains(ready.Message, "file allow rule") {
		t.Fatalf("ready %+v", ready)
	}
	if status.Compiled.Rules != 2 || status.Compiled.ClassesUnresolved != 1 {
		t.Fatalf("compiled %+v", status.Compiled)
	}
	types := map[string]bool{}
	for _, cond := range status.Conditions {
		types[cond.Type] = true
	}
	if !types["FileNotEnforced"] || types["NetworkNotEnforced"] {
		t.Fatalf("conditions %+v", status.Conditions)
	}
}

func TestFileSectionUnavailableIsReported(t *testing.T) {
	ctx := context.Background()
	c, _, w, _ := setup(t)
	obj := filePolicyObject("files", fileSpec(api.ActionAllow), nil)
	c.objects[objectKey(obj)] = obj
	sections, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, nil, nil)
	c.backend = sections
	_ = c.SetBindings(ctx, []Binding{binding()})
	if ready := w.reports["uid-files"].Status.Conditions[0]; ready.Status != metav1.ConditionFalse || ready.Reason != "FileNotConfigured" {
		t.Fatalf("ready %+v", ready)
	}
	if !c.HasSlotPolicies() {
		t.Fatal("a file policy has a node-wide slot")
	}
}

func filePlan(def string) *FilePlan {
	defaults := map[string]filepolicy.Default{}
	for _, k := range filepolicy.AccessKinds {
		defaults[k] = filepolicy.Default{Action: def}
	}
	return &FilePlan{Doc: filepolicy.Document{Version: 1, Policy: filepolicy.Policy{Mode: "enforce", File: filepolicy.Section{Defaults: defaults}}}}
}

func TestSectionBackendRoutesFileSection(t *testing.T) {
	exec, network, file := &fakeBackend{plans: map[string]Plan{}}, &fakeBackend{plans: map[string]Plan{}}, &fakeBackend{plans: map[string]Plan{}}
	s, _ := NewSectionBackend(exec, nil, nil)
	_, err := s.Replace(context.Background(), Binding{}, sectionPlan("r", CompiledPolicy{File: filePlan("allow")}))
	var u *EnforcementUnavailableError
	if !errors.As(err, &u) || u.Reason != "FileNotConfigured" || s.SectionUnavailable(SectionFile) == nil {
		t.Fatalf("file must be rejected without a file backend: %v", err)
	}
	s.WithNetwork(network, nil).WithFile(file, nil)
	b := Binding{ContainerID: "c"}
	p := CompiledPolicy{Identity: PolicyIdentity{UID: "1"}, Exec: api.ExecSection{Default: api.ActionDeny}, Network: networkPlan(), File: filePlan("allow")}
	if _, err := s.Replace(context.Background(), b, sectionPlan("r1", p)); err != nil {
		t.Fatal(err)
	}
	if got := file.plans[bindingKey(b)]; len(got.Policies) != 1 || got.Policies[0].File == nil {
		t.Fatalf("file plan %+v", got)
	}
	if got := exec.plans[bindingKey(b)]; got.Policies[0].File != nil || got.Policies[0].Network != nil {
		t.Fatalf("exec plan must not carry the file section: %+v", got)
	}
	// A file change keeps the exec and network revisions.
	p.File = filePlan("deny")
	if _, err := s.Replace(context.Background(), b, sectionPlan("r2", p)); err != nil || exec.replacements != 1 || network.replacements != 1 || file.replacements != 2 {
		t.Fatalf("exec %d network %d file %d replacements, %v", exec.replacements, network.replacements, file.replacements, err)
	}
	// A file failure returns network and exec to their previous plans.
	file.fail = true
	p.File, p.Network = filePlan("allow"), networkPlan()
	p.Network.Egress.Policy.Egress.Default = "deny"
	if r, err := s.Replace(context.Background(), b, sectionPlan("r3", p)); err == nil || r.Committed {
		t.Fatalf("expected failure: %+v", r)
	}
	if got := network.plans[bindingKey(b)]; got.Policies[0].Network.Egress.Policy.Egress.Default != "allow" {
		t.Fatal("network must return to its previous plan")
	}
	file.fail = false
	if r, err := s.Withdraw(context.Background(), b); err != nil || !r.Committed || file.withdrawals != 1 || len(s.active) != 0 {
		t.Fatalf("withdraw %+v %v", r, err)
	}
}

// TestFilePathAliases: a pattern also matches the resolved path the gadget
// sees for a /var/run name and for a file of a kubelet atomic-writer volume.
func TestFilePathAliases(t *testing.T) {
	spec := fileSpec(api.ActionAllow,
		fileRule("creds", api.ActionDeny, api.FileTarget{Access: []string{"read"}, PathTarget: api.PathTarget{PathClass: []string{"credentialStore", "containerRuntimeSocket"}}}),
		fileRule("cfg", api.ActionAllow, api.FileTarget{Access: []string{"write"}, PathTarget: api.PathTarget{Path: []string{"/etc/app/config.yaml", "/data/**"}}}),
	)
	spec.File.Rules[0].Except = []api.FileException{{Target: &api.FileTarget{PathTarget: api.PathTarget{Path: []string{"/var/run/docker.sock"}}}}}
	plan := translateFile(t, spec, nil)
	creds, cfg := fileRuleByName(plan, "creds"), fileRuleByName(plan, "cfg")
	if creds == nil || cfg == nil {
		t.Fatalf("rules %+v", plan.Doc.Policy.File.Rules)
	}
	const ts = "..2026_11_04_10_00_00.123456789"
	for _, path := range []string{
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
		"/run/secrets/kubernetes.io/serviceaccount/token",
		"/var/run/secrets/kubernetes.io/serviceaccount/" + ts + "/token",
		"/run/secrets/kubernetes.io/serviceaccount/" + ts + "/token",
		"/run/docker.sock", "/var/run/docker.sock", "/run/containerd/containerd.sock",
		// Review 2 finding 1: the floating class members of a Secret volume.
		"/root/.docker/" + ts + "/config.json", "/home/app/.docker/" + ts + "/config.json",
		"/app/.npmrc", "/app/" + ts + "/.npmrc",
	} {
		if !globsMatch(t, creds.Paths, path) {
			t.Errorf("deny paths %v do not match %s", creds.Paths, path)
		}
	}
	for _, path := range []string{"/var/run/secrets/kubernetes.io/serviceaccount/x/token", "/root/.docker/x/config.json"} {
		if globsMatch(t, creds.Paths, path) {
			t.Errorf("%s: only ..* directories are aliases", path)
		}
	}
	for _, path := range []string{"/run/docker.sock", "/var/run/..data/docker.sock"} {
		if !globsMatch(t, creds.Except, path) {
			t.Errorf("except %v does not match %s", creds.Except, path)
		}
	}
	if !globsMatch(t, cfg.Paths, "/etc/app/..data/config.yaml") || !slices.Contains(cfg.Paths, "/data/**") || len(cfg.Paths) != 3 {
		t.Errorf("allow paths %v", cfg.Paths)
	}
	for in, want := range map[string][]string{
		"/x":                     {"/x"},
		"/a/**":                  {"/a/**"},
		"**/.env":                {"**/.env"},
		"/a/**/b":                {"/a/**/b"},
		"/a/*.sock":              {"/a/*.sock", "/a/..*/*.sock"},
		"**/.docker/config.json": {"**/.docker/config.json", "/**/.docker/..*/config.json"},
		"/a/b/c":                 {"/a/b/c", "/a/b/..*/c"},
	} {
		if got := pathAliases([]string{in}, false); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: aliases %v, want %v", in, got, want)
		}
	}
	// Merged /usr: deny rules and their excepts, not allow rules.
	if got := pathAliases([]string{"/bin/**", "/lib64/ld.so"}, true); !reflect.DeepEqual(got,
		[]string{"/bin/**", "/usr/bin/**", "/lib64/ld.so", "/lib64/..*/ld.so", "/usr/lib64/ld.so", "/usr/lib64/..*/ld.so"}) {
		t.Errorf("merged /usr aliases %v", got)
	}
	usr := fileSpec(api.ActionAllow,
		fileRule("no-bin", api.ActionDeny, api.FileTarget{Access: []string{"write"}, PathTarget: api.PathTarget{Path: []string{"/bin/**", "/sbin/**", "/lib/**"}}}),
		fileRule("bin-ok", api.ActionAllow, api.FileTarget{Access: []string{"read"}, PathTarget: api.PathTarget{Path: []string{"/bin/**"}}}),
	)
	usr.File.Rules[0].Except = []api.FileException{{Target: &api.FileTarget{PathTarget: api.PathTarget{Path: []string{"/bin/sh"}}}}}
	plan = translateFile(t, usr, nil)
	noBin, binOK := fileRuleByName(plan, "no-bin"), fileRuleByName(plan, "bin-ok")
	for _, path := range []string{"/usr/bin/python3", "/usr/sbin/x", "/usr/lib/x/y.so", "/bin/sh"} {
		if !globsMatch(t, noBin.Paths, path) {
			t.Errorf("deny %v does not match %s", noBin.Paths, path)
		}
	}
	if globsMatch(t, binOK.Paths, "/usr/bin/x") {
		t.Errorf("merged /usr aliases on an allow rule %v", binOK.Paths)
	}
	// A write to /bin/sh is judged on /usr/bin/sh (the resolved path): the
	// except /bin/sh lifts that deny too, and nothing else.
	for _, path := range []string{"/bin/sh", "/usr/bin/sh"} {
		if !globsMatch(t, noBin.Except, path) {
			t.Errorf("except %v does not lift %s", noBin.Except, path)
		}
	}
	for _, path := range []string{"/usr/bin/bash", "/bin/bash"} {
		if globsMatch(t, noBin.Except, path) {
			t.Errorf("except %v lifts %s", noBin.Except, path)
		}
	}
}

func globsMatch(t *testing.T, globs []string, path string) bool {
	t.Helper()
	for _, g := range globs {
		p, err := filepolicy.ParsePattern(g)
		if err != nil {
			t.Fatalf("%s: %v", g, err)
		}
		if p.MatchPath(path) {
			return true
		}
	}
	return false
}

// TestFileDefaultClassesFit: the built-in path classes with their aliases fit
// the segment bits of one slot, as one policy and as two policies together
// (a read deny of every class, and a write and create deny of every class
// under a confined write default).
func TestFileDefaultClassesFit(t *testing.T) {
	var classes []string
	for name, members := range defaultPathClasses {
		if len(members) > 0 {
			classes = append(classes, name)
		}
	}
	slices.Sort(classes)
	policy := func(name string, access []string, byAccess *api.FileAccessDefaults) filepolicy.Document {
		var rules []api.FileRule
		for _, c := range classes {
			rules = append(rules, fileRule("no-"+c, api.ActionDeny, api.FileTarget{Access: access, PathTarget: api.PathTarget{PathClass: []string{c}}}))
		}
		spec := fileSpec(api.ActionAllow, rules...)
		if byAccess != nil {
			spec.File.Default, spec.File.DefaultByAccess = "", byAccess
		}
		doc := translateFile(t, spec, nil).Doc
		doc.Name = name
		return doc
	}
	reads := policy("reads", []string{"read"}, nil)
	writes := policy("writes", []string{"write", "create"}, writesConfined())
	used := func(c filepolicy.Compiled) int {
		a := c.Slots[0].Accept
		for i := filepolicy.KernelSegBits - 1; i >= 0; i-- {
			if a[i/64]&(1<<(i%64)) != 0 {
				return i + 1
			}
		}
		return 0
	}
	for name, docs := range map[string][]filepolicy.Document{"one": {reads}, "two": {reads, writes}} {
		c, err := filepolicy.CompileSlots([][]filepolicy.Document{docs}, 1)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		t.Logf("%s: %d of %d segment bits, %d rules, %d globs", name, used(c), filepolicy.KernelSegBits,
			c.Slots[0].NRules, c.Slots[0].NGlobs)
	}
}

// TestFileDegradedDenyKeepsDefault: a deny with an unresolved class keeps its
// resolved paths at enforce, and never loosens its own policy's enforce
// default deny.
func TestFileDegradedDenyKeepsDefault(t *testing.T) {
	spec := fileSpec("", fileRule("corp", api.ActionDeny, api.FileTarget{Access: []string{"write"},
		PathTarget: api.PathTarget{Path: []string{"/etc/**"}, PathClass: []string{"corpSecrets"}}}))
	confine(spec.File)
	plan := translateFile(t, spec, nil)
	if r := fileRuleByName(plan, "corp"); r == nil || r.Mode == "audit" || !slices.Contains(r.Paths, "/etc/**") {
		t.Fatalf("the deny keeps its resolved path at enforce: %+v", r)
	}
	if d := fileDegraded(plan, "corp"); d == nil || d.Effective == "audit" || d.Reason != "class-unresolved" {
		t.Fatalf("degraded %+v", d)
	}
	if plan.Report.NotReady != "ClassUnresolved" {
		t.Fatalf("report %+v", plan.Report)
	}
	c, err := filepolicy.CompileKernel(plan.Doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	v := c.Slots[0]
	if v.Defaults[1].Rank != filepolicy.RankDenyEnforce || v.Unresolved[1] != filepolicy.RankDenyEnforce {
		t.Fatalf("write default %+v unresolved %d", v.Defaults[1], v.Unresolved[1])
	}
	for _, r := range v.Rules[:v.NRules] {
		if r.Access&(1<<1) != 0 && r.Rank == filepolicy.RankDenyAudit {
			t.Fatalf("a write deny audit rule hides the write default: %+v", c.RuleNames[r.RuleID])
		}
	}
}

// TestFileFromImageUnavailable: on a kernel whose overlay layout the gadget
// cannot read, fromImage rules are reported, never enforced on a guess.
func TestFileFromImageUnavailable(t *testing.T) {
	spec := fileSpec("",
		fileRule("img", api.ActionDeny, api.FileTarget{Access: []string{"write"}, PathTarget: api.PathTarget{FromImage: boolPtr(true)}}),
		fileRule("img-ok", api.ActionAllow, api.FileTarget{Access: []string{"read"}, PathTarget: api.PathTarget{FromImage: boolPtr(true)}}),
	)
	confine(spec.File)
	plan, err := TranslateFile(spec, nil, FileNode{FromImageUnavailable: "no overlay BTF"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fileRuleByName(plan, "img") != nil || fileRuleByName(plan, "img-ok") != nil {
		t.Fatal("fromImage rules must not reach the gadget")
	}
	notEnforcedHas(t, plan, "rule img: fromImage is not enforced on this node: no overlay BTF", "rule img-ok: fromImage is not enforced")
	if d := fileDegraded(plan, "img-ok"); d == nil || d.Reason != "not-enforceable" {
		t.Fatalf("allow degraded %+v", d)
	}
	if plan.Report.NotReady != "RuleNotEnforceable" {
		t.Fatalf("not ready %q", plan.Report.NotReady)
	}
	plan = translateFile(t, spec, nil)
	if r := fileRuleByName(plan, "img"); r == nil || !r.FromImage {
		t.Fatalf("fromImage rule %+v", r)
	}
}

// TestFileTwoPoliciesAtRuleLimit: the built-in rules of several policies
// merge in the gadget compiler, so two policies of 32 rules each (30 own and
// the 2 built-in) fit the 64 rules of a slot; one more own rule in each does
// not.
func TestFileTwoPoliciesAtRuleLimit(t *testing.T) {
	builtin := len(runtimeDevices)
	policy := func(name string, n int) filepolicy.Document {
		var rules []api.FileRule
		for i := 0; i < n; i++ {
			rules = append(rules, fileRule(fmt.Sprint(i), api.ActionDeny, api.FileTarget{Access: []string{"read"},
				PathTarget: api.PathTarget{Path: []string{fmt.Sprintf("/%s/%d/**", name, i)}}}))
		}
		doc := translateFile(t, fileSpec(api.ActionAllow, rules...), nil).Doc
		doc.Name = name
		return doc
	}
	own := (filepolicy.KernelMaxRules - builtin) / 2
	if _, err := filepolicy.CompileSlots([][]filepolicy.Document{{policy("a", own), policy("b", own)}}, 1); err != nil {
		t.Fatalf("two policies of %d rules: %v", own+builtin, err)
	}
	if _, err := filepolicy.CompileSlots([][]filepolicy.Document{{policy("a", own+1), policy("b", own+1)}}, 1); err == nil {
		t.Fatalf("two policies of %d rules fit one slot", own+1+builtin)
	}
}

// A path class defined in two class objects is unresolved for the file
// section: the deny rule degrades, and the policy still binds.
func TestFileDuplicateSharedClassDegrades(t *testing.T) {
	ctx := context.Background()
	deny := fileRule("no-broken", api.ActionDeny, api.FileTarget{PathTarget: api.PathTarget{PathClass: []string{"broken"}}})
	obj := filePolicyObject("files", fileSpec(api.ActionAllow, deny), nil)
	classes := &api.SandboxPolicyClasses{TypeMeta: metav1.TypeMeta{APIVersion: api.SchemeGroupVersion.String(), Kind: "SandboxPolicyClasses"}, ObjectMeta: metav1.ObjectMeta{Name: "classes", UID: "classes"},
		Spec: api.PolicyClasses{PathClasses: map[string][]string{"broken": {"/etc/one"}}}}
	duplicate := classes.DeepCopy()
	duplicate.Name, duplicate.UID = "duplicate", "duplicate"
	c, backend, w, _ := setup(t, classes, duplicate)
	c.objects[objectKey(obj)] = obj
	err := c.SetBindings(ctx, []Binding{binding()})
	plan := backend.plans[bindingKey(binding())]
	if len(plan.Policies) != 1 || plan.Policies[0].File == nil {
		t.Fatalf("the file policy must still bind: %+v err=%v status=%+v", plan, err, w.reports["uid-files"])
	}
	degraded := plan.Policies[0].File.Report.Degraded
	if len(degraded) != 1 || degraded[0].Rule != "no-broken" || !strings.Contains(degraded[0].Reason, "class-unresolved") {
		t.Fatalf("degraded %+v", degraded)
	}
}
