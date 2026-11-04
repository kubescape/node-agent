package sandboxpolicy

import (
	"context"
	"errors"
	"os"
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

func TestMain(m *testing.M) {
	if _, err := filepolicy.ParsePattern("/a"); err != nil {
		// The file gadget compiler is not in this tree yet: accept the globs
		// it will accept (it rejects '?' and '[') and every document.
		filePatternError = func(p string) error {
			if strings.ContainsAny(p, "?[") {
				return errors.New("unsupported glob")
			}
			return nil
		}
		checkFileDocument = func(filepolicy.Document) error { return nil }
	}
	os.Exit(m.Run())
}

func boolPtr(v bool) *bool { return &v }

func fileRule(name string, action api.Action, target api.FileTarget) api.FileRule {
	return api.FileRule{Rule: api.Rule{Name: name, Action: action}, Target: target}
}

// fileSpec has a scalar default.
func fileSpec(def api.Action, rules ...api.FileRule) api.PolicySpec {
	return api.PolicySpec{Containers: []string{"*"}, Mode: api.ModeEnforce,
		File: &api.FileSection{Default: api.FileDefault{Action: def}, Rules: rules}}
}

// writesConfined is the design's per-access default: reads open, the rest denied.
func writesConfined() api.FileDefault {
	return api.FileDefault{PerAccess: &api.FileAccessDefaults{Read: api.ActionAllow, Write: api.ActionDeny, Create: api.ActionDeny,
		Delete: api.ActionDeny, Rename: api.ActionDeny, Chmod: api.ActionDeny, ExecMap: api.ActionAllow}}
}

func translateFile(t *testing.T, spec api.PolicySpec, x FileExtras, shared map[string][]string) *FilePlan {
	t.Helper()
	plan, err := TranslateFile(spec, x, shared)
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
	spec.File.Default = writesConfined()
	spec.File.Rules[1].Mode, spec.File.Rules[1].Origin = api.RuleEnforce, "catalog/C1"
	x := FileExtras{
		DefaultModeByAccess:   &FileAccessValues{Write: "enforce", Create: "audit"},
		DefaultOriginByAccess: &FileAccessValues{Write: "catalog/D1", Chmod: "catalog/D1"},
	}
	plan := translateFile(t, spec, x, nil)
	p := plan.Doc.Policy
	if p.Mode != "enforce" || plan.Doc.Version != 1 {
		t.Fatalf("document header %+v", plan.Doc)
	}
	want := map[string]filepolicy.Default{
		"read": {Action: "allow"}, "write": {Action: "deny", Mode: "enforce", Origin: "catalog/D1"}, "create": {Action: "deny", Mode: "audit"},
		"delete": {Action: "deny"}, "rename": {Action: "deny"}, "chmod": {Action: "deny", Origin: "catalog/D1"},
	}
	if !reflect.DeepEqual(p.File.Defaults, want) {
		t.Fatalf("defaults %+v", p.File.Defaults)
	}
	ws := fileRuleByName(plan, "workspace")
	if ws == nil || !reflect.DeepEqual(ws.Access, []string{"write", "create", "delete", "rename"}) || !reflect.DeepEqual(ws.Paths, []string{"/tmp/**", "/workspace/**"}) {
		t.Fatalf("workspace %+v", ws)
	}
	ac := fileRuleByName(plan, "no-agent-config")
	if ac == nil || ac.Mode != "enforce" || ac.Origin != "catalog/C1" || !reflect.DeepEqual(ac.Paths, sortedUnique(slices.Clone(defaultPathClasses["agentConfig"]))) {
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
	if plan.Report.NotReady != "" || len(plan.Report.Degraded) != 0 || plan.Report.Rules != 6 || plan.Report.ClassesResolved != 1 {
		t.Fatalf("report %+v", plan.Report)
	}
}

func TestTranslateFileScalarDefault(t *testing.T) {
	spec := fileSpec(api.ActionDeny)
	spec.Mode = api.ModeAudit
	plan := translateFile(t, spec, FileExtras{DefaultMode: "enforce", DefaultOrigin: "catalog/X"}, nil)
	for _, k := range filepolicy.AccessKinds {
		if d := plan.Doc.Policy.File.Defaults[k]; d != (filepolicy.Default{Action: "deny", Mode: "enforce", Origin: "catalog/X"}) {
			t.Fatalf("default %s %+v", k, d)
		}
	}
	notEnforcedHas(t, plan, "default execMap deny")
	if plan.Doc.Policy.Mode != "audit" {
		t.Fatalf("mode %q", plan.Doc.Policy.Mode)
	}
	if plan := translateFile(t, fileSpec(api.ActionAllow), FileExtras{}, nil); len(plan.Report.NotEnforced) != 0 {
		t.Fatalf("an execMap allow default loses nothing: %v", plan.Report.NotEnforced)
	}
}

func TestTranslateFileValidates(t *testing.T) {
	for name, mutate := range map[string]func(*api.PolicySpec, *FileExtras){
		"default":     func(s *api.PolicySpec, _ *FileExtras) { s.File.Default = api.FileDefault{Action: "maybe"} },
		"access":      func(s *api.PolicySpec, _ *FileExtras) { s.File.Rules[0].Target.Access = []string{"exec"} },
		"fsType":      func(s *api.PolicySpec, _ *FileExtras) { s.File.Rules[0].Target.FSType = []string{"ext4"} },
		"empty path":  func(s *api.PolicySpec, _ *FileExtras) { s.File.Rules[0].Target.Path = []string{" "} },
		"empty class": func(s *api.PolicySpec, _ *FileExtras) { s.File.Rules[0].Target.PathClass = []string{""} },
		"action":      func(s *api.PolicySpec, _ *FileExtras) { s.File.Rules[0].Action = "block" },
		"mode":        func(s *api.PolicySpec, _ *FileExtras) { s.File.Rules[0].Mode = "tripwire" },
		"actor":       func(s *api.PolicySpec, _ *FileExtras) { s.File.Rules[0].Actor = &api.Actor{Path: []string{"/bin/sh"}} },
		"defaultMode": func(_ *api.PolicySpec, x *FileExtras) { x.DefaultMode = "tripwire" },
		"mode by access": func(s *api.PolicySpec, x *FileExtras) {
			s.File.Default = writesConfined()
			x.DefaultModeByAccess = &FileAccessValues{Chmod: "loud"}
		},
		"scalar default with by-access mode": func(_ *api.PolicySpec, x *FileExtras) {
			x.DefaultModeByAccess = &FileAccessValues{Write: "audit"}
		},
		"per-access default with scalar origin": func(s *api.PolicySpec, x *FileExtras) {
			s.File.Default = writesConfined()
			x.DefaultOrigin = "catalog/D1"
		},
		"except on allow": func(s *api.PolicySpec, x *FileExtras) {
			s.File.Rules[0].Action = api.ActionAllow
			x.Except = map[string][]FileExcept{"r": {{Target: &api.FileTarget{PathTarget: api.PathTarget{Path: []string{"/a"}}}}}}
		},
		"empty except": func(_ *api.PolicySpec, x *FileExtras) {
			x.Except = map[string][]FileExcept{"r": {{Target: &api.FileTarget{}}}}
		},
		"except access": func(_ *api.PolicySpec, x *FileExtras) {
			x.Except = map[string][]FileExcept{"r": {{Target: &api.FileTarget{Access: []string{"open"}}}}}
		},
		"except for unknown rule": func(_ *api.PolicySpec, x *FileExtras) {
			x.Except = map[string][]FileExcept{"other": {{Target: &api.FileTarget{PathTarget: api.PathTarget{Path: []string{"/a"}}}}}}
		},
	} {
		spec := fileSpec(api.ActionAllow, fileRule("r", api.ActionDeny, api.FileTarget{PathTarget: api.PathTarget{Path: []string{"/etc/**"}}}))
		var x FileExtras
		mutate(&spec, &x)
		if _, err := TranslateFile(spec, x, nil); err == nil {
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
	plan := translateFile(t, spec, FileExtras{}, shared)
	keys := fileRuleByName(plan, "no-keys")
	want := []string{"/data/ssh/**", "/home/*/.ssh/**", "/opt/keys/**", "/root/.ssh/**", "/srv/key"}
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
	if r := fileRuleByName(translateFile(t, other, FileExtras{}, nil), "no-keys"); slices.Contains(r.Paths, "/opt/keys/**") {
		t.Fatal("a policy-local class addition must stay local")
	}
}

func TestFileUnresolvedClassDegradation(t *testing.T) {
	spec := fileSpec("",
		fileRule("no-model-cache", api.ActionDeny, api.FileTarget{Access: []string{"read"}, PathTarget: api.PathTarget{PathClass: []string{"modelCache"}}}),
		fileRule("work", api.ActionAllow, api.FileTarget{Access: []string{"write", "create"}, PathTarget: api.PathTarget{PathClass: []string{"workspace"}, Path: []string{"/tmp/**"}}}),
	)
	spec.File.Default = writesConfined()
	plan := translateFile(t, spec, FileExtras{DefaultModeByAccess: &FileAccessValues{Create: "audit"}}, nil)
	if fileRuleByName(plan, "no-model-cache") != nil {
		t.Fatal("a deny without any path must not reach the gadget")
	}
	if d := fileDegraded(plan, "no-model-cache"); d == nil || d.Effective != "audit" || d.Requested != api.RuleEnforce || d.Reason != "class-unresolved" {
		t.Fatalf("deny degraded %+v", d)
	}
	notEnforcedHas(t, plan, "rule no-model-cache: no path is resolved")
	// The allow keeps its literal path; the defaults of its access kinds run in audit.
	if w := fileRuleByName(plan, "work"); w == nil || !reflect.DeepEqual(w.Paths, []string{"/tmp/**"}) {
		t.Fatalf("allow %+v", w)
	}
	defs := plan.Doc.Policy.File.Defaults
	if defs["write"].Mode != "audit" || defs["create"].Mode != "audit" || defs["delete"].Mode != "" || defs["read"].Mode != "" {
		t.Fatalf("defaults %+v", defs)
	}
	if d := fileDegraded(plan, "default/write"); d == nil || d.Reason != "class-unresolved" {
		t.Fatalf("write default degraded %+v", d)
	}
	if fileDegraded(plan, "default/create") != nil {
		t.Fatal("a default already in audit is not degraded")
	}
	if plan.Report.NotReady != "ClassUnresolved" || plan.Report.ClassesUnresolved != 2 {
		t.Fatalf("report %+v", plan.Report)
	}

	// A deny with a resolved part keeps it, in audit.
	partial := fileSpec(api.ActionAllow, fileRule("d", api.ActionDeny, api.FileTarget{PathTarget: api.PathTarget{PathClass: []string{"sshKeys", "modelCache"}}}))
	if r := fileRuleByName(translateFile(t, partial, FileExtras{}, nil), "d"); r == nil || r.Mode != "audit" || len(r.Paths) != 2 {
		t.Fatalf("partly resolved deny %+v", r)
	}
	// An allow without access degrades every default.
	every := fileSpec(api.ActionDeny, fileRule("a", api.ActionAllow, api.FileTarget{PathTarget: api.PathTarget{PathClass: []string{"workspace"}}}))
	plan = translateFile(t, every, FileExtras{}, nil)
	for _, k := range filepolicy.AccessKinds {
		if plan.Doc.Policy.File.Defaults[k].Mode != "audit" || fileDegraded(plan, "default/"+k) == nil {
			t.Fatalf("default %s must run in audit: %+v", k, plan.Doc.Policy.File.Defaults[k])
		}
	}
}

func TestFileExcept(t *testing.T) {
	deny := func() api.PolicySpec {
		return fileSpec(api.ActionAllow, fileRule("no-agent-config", api.ActionDeny, api.FileTarget{Access: []string{"write", "create"}, PathTarget: api.PathTarget{Path: []string{"**/.claude/**"}}}))
	}
	path := func(p ...string) *api.FileTarget { return &api.FileTarget{PathTarget: api.PathTarget{Path: p}} }
	for name, tc := range map[string]struct {
		entries  []FileExcept
		lifted   []string
		notReady string
		disabled string
	}{
		"path":            {entries: []FileExcept{{Target: path("/workspace/.claude/settings.local.json")}}, lifted: []string{"/workspace/.claude/settings.local.json"}},
		"covering access": {entries: []FileExcept{{Target: &api.FileTarget{Access: []string{"create", "write", "read"}, PathTarget: api.PathTarget{Path: []string{"/a/.claude/x"}}}}}, lifted: []string{"/a/.claude/x"}},
		"partial access":  {entries: []FileExcept{{Target: &api.FileTarget{Access: []string{"write"}, PathTarget: api.PathTarget{Path: []string{"/a/.claude/x"}}}}}, disabled: "must cover every access kind"},
		"unresolved class": {entries: []FileExcept{{Target: &api.FileTarget{PathTarget: api.PathTarget{PathClass: []string{"workspace"}}}}},
			notReady: "ClassUnresolved", disabled: "class-unresolved"},
		"fsType":  {entries: []FileExcept{{Target: &api.FileTarget{PathTarget: api.PathTarget{FSType: []string{"tmpfs"}}}}}, disabled: "fromImage and fsType"},
		"actor":   {entries: []FileExcept{{Actor: &api.Actor{Path: []string{"/bin/git"}}}}, disabled: "actor predicates"},
		"pattern": {entries: []FileExcept{{Target: path("/a/.claude/fil?")}}, disabled: "cannot be expressed"},
		"two":     {entries: []FileExcept{{Target: path("/b/.claude/y")}, {Actor: &api.Actor{UID: []int64{0}}}}, lifted: []string{"/b/.claude/y"}, disabled: "except 1 is disabled"},
	} {
		t.Run(name, func(t *testing.T) {
			plan := translateFile(t, deny(), FileExtras{Except: map[string][]FileExcept{"no-agent-config": tc.entries}}, nil)
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
	spec.File.Default = writesConfined()
	plan := translateFile(t, spec, FileExtras{}, nil)
	for _, name := range []string{"no-tmpfs-write", "tmpfs-ok", "own-files", "odd-allow"} {
		if fileRuleByName(plan, name) != nil {
			t.Errorf("rule %s must not reach the gadget", name)
		}
	}
	if odd := fileRuleByName(plan, "odd"); odd == nil || !reflect.DeepEqual(odd.Paths, []string{"/etc/shadow"}) {
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
	if plan.Report.NotReady != "" {
		t.Fatalf("not ready %q", plan.Report.NotReady)
	}
}

func TestFileRuntimeDevicesNameIsFree(t *testing.T) {
	plan := translateFile(t, fileSpec(api.ActionAllow, fileRule("runtime-devices", api.ActionDeny, api.FileTarget{PathTarget: api.PathTarget{Path: []string{"/dev/mem"}}})), FileExtras{}, nil)
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
	if _, err := TranslateFile(fileSpec(api.ActionAllow), FileExtras{}, nil); err == nil || !strings.Contains(err.Error(), "file: over limits") {
		t.Fatalf("err %v", err)
	}
}

func TestSplitFileExtras(t *testing.T) {
	spec := map[string]any{"file": map[string]any{
		"defaultByAccess":       map[string]any{"read": "allow", "write": "deny", "create": "deny", "delete": "deny", "rename": "deny", "chmod": "deny", "execMap": "allow"},
		"defaultModeByAccess":   map[string]any{"write": "enforce"},
		"defaultOriginByAccess": map[string]any{"write": "catalog/D1"},
		"rules": []any{map[string]any{"name": "r", "action": "deny", "target": map[string]any{}, "except": []any{
			map[string]any{"target": map[string]any{"path": []any{"/a"}}}}}},
	}}
	x, err := splitFileExtras(spec)
	if err != nil || x.DefaultModeByAccess.Write != "enforce" || x.DefaultOriginByAccess.Write != "catalog/D1" || len(x.Except["r"]) != 1 {
		t.Fatalf("extras %+v %v", x, err)
	}
	f := spec["file"].(map[string]any)
	for _, key := range []string{"defaultByAccess", "defaultModeByAccess", "defaultOriginByAccess"} {
		if _, ok := f[key]; ok {
			t.Fatalf("%s must be removed for strict decoding", key)
		}
	}
	if _, ok := f["rules"].([]any)[0].(map[string]any)["except"]; ok {
		t.Fatal("except must be removed for strict decoding")
	}
	// The storage type reads defaultByAccess as the object form of default.
	var section api.FileSection
	if err := decodeValue(f, &section); err != nil || section.Default.PerAccess == nil || section.Default.PerAccess.Write != api.ActionDeny {
		t.Fatalf("section %+v %v", section, err)
	}
	for name, bad := range map[string]map[string]any{
		"both defaults":    {"default": "allow", "defaultByAccess": map[string]any{"read": "allow"}},
		"scalar by access": {"defaultByAccess": "deny"},
		"unknown key":      {"defaultModeByAccess": map[string]any{"open": "audit"}},
		"mode type":        {"defaultMode": map[string]any{"write": "audit"}},
		"except shape":     {"rules": []any{map[string]any{"name": "r", "except": []any{map[string]any{"target": map[string]any{"port": 1}}}}}},
	} {
		if _, err := splitFileExtras(map[string]any{"file": bad}); err == nil {
			t.Errorf("%s accepted", name)
		}
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
	if d := plan.Policies[0].File.Doc.Policy.File.Defaults["write"]; d.Action != "deny" || d.Mode != "audit" {
		t.Fatalf("the write default must run in audit: %+v", d)
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
