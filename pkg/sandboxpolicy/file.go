package sandboxpolicy

import (
	"fmt"
	"slices"
	"strings"

	filepolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/policy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// FilePlan is the file section of one policy, translated to the file gadget's
// policy document: path classes resolved to globs. Its content is part of the
// policy revision, so a class change replaces the node instance like a policy
// change.
type FilePlan struct {
	Doc    filepolicy.Document `json:"doc"`
	Report FileReport          `json:"report"`
}

// FileReport is what the node status says about the file translation. It has
// the fields of NetworkReport.
type FileReport NetworkReport

// FileExtras mirrors file fields of the SandboxPolicy design
// (sandbox-policy-crd.md sections 5.2 and 6.1) that the storage API types do
// not have yet: the per-default modes and origins and the except list of deny
// rules. The pinned storage type reads per-access defaults from the object form
// of default, so splitFileExtras moves defaultByAccess there.
// TODO: replace with the storage types when storage adds these fields.
type FileExtras struct {
	// DefaultMode and DefaultOrigin go with a scalar default.
	DefaultMode   string `json:"defaultMode,omitempty"`
	DefaultOrigin string `json:"defaultOrigin,omitempty"`
	// DefaultModeByAccess and DefaultOriginByAccess go with per-access
	// defaults. Every key is optional.
	DefaultModeByAccess   *FileAccessValues `json:"defaultModeByAccess,omitempty"`
	DefaultOriginByAccess *FileAccessValues `json:"defaultOriginByAccess,omitempty"`
	// Except holds the except list of each rule, by rule name.
	Except map[string][]FileExcept `json:"except,omitempty"`
}

// FileAccessValues holds one optional value per access kind.
type FileAccessValues struct {
	Read    string `json:"read,omitempty"`
	Write   string `json:"write,omitempty"`
	Create  string `json:"create,omitempty"`
	Delete  string `json:"delete,omitempty"`
	Rename  string `json:"rename,omitempty"`
	Chmod   string `json:"chmod,omitempty"`
	ExecMap string `json:"execMap,omitempty"`
}

// FileExcept mirrors one except entry of a deny rule.
type FileExcept struct {
	Actor  *api.Actor      `json:"actor,omitempty"`
	Target *api.FileTarget `json:"target,omitempty"`
}

// accessExecMap is the CRD access kind the gadget does not enforce.
const accessExecMap = "execMap"

// fileAccessKinds are the CRD access kinds: the gadget's kinds and execMap.
var fileAccessKinds = append(slices.Clone(filepolicy.AccessKinds), accessExecMap)

var fileFSTypes = []string{"tmpfs", "overlay", "memfd", "deleted", "procfs", "sysfs"}

func (v *FileAccessValues) get(kind string) string {
	if v == nil {
		return ""
	}
	return map[string]string{"read": v.Read, "write": v.Write, "create": v.Create, "delete": v.Delete,
		"rename": v.Rename, "chmod": v.Chmod, accessExecMap: v.ExecMap}[kind]
}

// splitFileExtras removes the mirrored fields from a decoded spec (a JSON value
// the caller owns), so the storage types decode the rest strictly. A
// defaultByAccess object becomes the object form of default.
func splitFileExtras(spec any) (FileExtras, error) {
	var x FileExtras
	m, _ := spec.(map[string]any)
	f, _ := m["file"].(map[string]any)
	if f == nil {
		return x, nil
	}
	if value, ok := f["defaultByAccess"]; ok {
		if _, both := f["default"]; both {
			return x, fmt.Errorf("file: set exactly one of default and defaultByAccess")
		}
		if _, isObject := value.(map[string]any); !isObject {
			return x, fmt.Errorf("file defaultByAccess must be an object")
		}
		f["default"] = value
		delete(f, "defaultByAccess")
	}
	for key, target := range map[string]any{"defaultMode": &x.DefaultMode, "defaultOrigin": &x.DefaultOrigin,
		"defaultModeByAccess": &x.DefaultModeByAccess, "defaultOriginByAccess": &x.DefaultOriginByAccess} {
		if value, ok := f[key]; ok {
			if err := decodeValue(value, target); err != nil {
				return x, fmt.Errorf("file %s: %w", key, err)
			}
			delete(f, key)
		}
	}
	var err error
	x.Except, err = splitExcept[FileExcept](f, "file")
	return x, err
}

// fileDefaults returns the default action of every CRD access kind.
func fileDefaults(d api.FileDefault) FileAccessValues {
	if p := d.PerAccess; p != nil {
		return FileAccessValues{string(p.Read), string(p.Write), string(p.Create), string(p.Delete), string(p.Rename), string(p.Chmod), string(p.ExecMap)}
	}
	a := string(d.Action)
	return FileAccessValues{a, a, a, a, a, a, a}
}

// validateFileTarget checks what ValidatePolicySpec does not: access and
// fsType values and empty entries (the CRD schema checks them only at
// admission).
func validateFileTarget(t api.FileTarget) error {
	for _, a := range t.Access {
		if !slices.Contains(fileAccessKinds, a) {
			return fmt.Errorf("access %q must be one of %s", a, strings.Join(fileAccessKinds, ", "))
		}
	}
	for _, fs := range t.FSType {
		if !slices.Contains(fileFSTypes, fs) {
			return fmt.Errorf("fsType %q must be one of %s", fs, strings.Join(fileFSTypes, ", "))
		}
	}
	for _, list := range [][]string{t.Path, t.PathClass} {
		for _, v := range list {
			if strings.TrimSpace(v) == "" {
				return fmt.Errorf("path and pathClass entries must not be empty")
			}
		}
	}
	return nil
}

// validateFile checks a file section and its mirrored fields.
func validateFile(f api.FileSection, x FileExtras) error {
	if err := f.Default.Validate(); err != nil {
		return err
	}
	if f.Default.PerAccess != nil && (x.DefaultMode != "" || x.DefaultOrigin != "") {
		return fmt.Errorf("file defaultMode and defaultOrigin go with a scalar default; use defaultModeByAccess and defaultOriginByAccess")
	}
	if f.Default.PerAccess == nil && (x.DefaultModeByAccess != nil || x.DefaultOriginByAccess != nil) {
		return fmt.Errorf("file defaultModeByAccess and defaultOriginByAccess go with defaultByAccess; use defaultMode and defaultOrigin")
	}
	if !validMode(x.DefaultMode) {
		return fmt.Errorf("file defaultMode must be audit or enforce")
	}
	for _, k := range fileAccessKinds {
		if !validMode(x.DefaultModeByAccess.get(k)) {
			return fmt.Errorf("file defaultModeByAccess %s must be audit or enforce", k)
		}
	}
	names := map[string]bool{}
	for _, r := range f.Rules {
		names[r.Name] = true
		if r.Action != api.ActionAllow && r.Action != api.ActionDeny {
			return fmt.Errorf("rule %q has invalid action", r.Name)
		}
		if !validMode(string(r.Mode)) {
			return fmt.Errorf("rule %q has invalid mode", r.Name)
		}
		if r.Actor != nil {
			return fmt.Errorf("rule %q: actor predicates are unsupported in the file section", r.Name)
		}
		if err := validateFileTarget(r.Target); err != nil {
			return fmt.Errorf("rule %q: %w", r.Name, err)
		}
		entries := x.Except[r.Name]
		if len(entries) > 0 && r.Action != api.ActionDeny {
			return fmt.Errorf("rule %q: except applies to deny rules only", r.Name)
		}
		for i, e := range entries {
			if e.Actor == nil && (e.Target == nil || digest(*e.Target) == digest(api.FileTarget{})) {
				return fmt.Errorf("rule %q except %d is empty", r.Name, i)
			}
			if e.Target != nil {
				if err := validateFileTarget(*e.Target); err != nil {
					return fmt.Errorf("rule %q except %d: %w", r.Name, i, err)
				}
			}
		}
	}
	for name := range x.Except {
		if !names[name] {
			return fmt.Errorf("except for unknown file rule %q", name)
		}
	}
	return nil
}

// defaultPathClasses are the path classes the agent ships
// (sandbox-policy-crd.md section 4.3). Shared SandboxPolicyClasses entries and
// the policy's own additions extend them.
var defaultPathClasses = map[string][]string{
	"credentialStore": {"/root/.aws/**", "/home/*/.aws/**", "/var/run/secrets/kubernetes.io/serviceaccount/token",
		"**/.netrc", "**/.docker/config.json", "**/.npmrc", "**/.pypirc", "**/.env"},
	"sshKeys":     {"/root/.ssh/**", "/home/*/.ssh/**"},
	"cloudConfig": {"/root/.config/gcloud/**", "/root/.azure/**", "/root/.aws/config"},
	"shellRc":     {"/root/.bashrc", "/root/.profile", "/root/.zshrc", "/etc/profile.d/**"},
	"agentConfig": {"**/.claude/**", "**/.cursor/**", "**/CLAUDE.md", "**/.mcp.json", "**/AGENTS.md"},
	"persistence": {"/etc/cron*/**", "/var/spool/cron/**", "/etc/systemd/**", "/etc/rc*.d/**", "/etc/ld.so.preload"},
	"packageStore": {"/usr/lib/python3*/site-packages/**", "/usr/local/lib/python3*/**", "**/node_modules/**",
		"/usr/lib/node_modules/**"},
	"workspace":              {},
	"containerRuntimeSocket": {"/run/containerd/**.sock", "/var/run/docker.sock", "/run/crio/**.sock"},
	"hostDevices":            {"/dev/mem", "/dev/kmem", "/dev/kmsg", "/dev/sd*", "/dev/nvme*", "/dev/xvd*"},
}

// runtimeDevices are the built-in allow rules for the devices a container
// runtime and ordinary programs use (healthchecks write /dev/null; sem_open
// and shm_open create files in /dev/shm). They keep a write or create default
// deny from blocking them. Every policy carries the same rules; the gadget
// compiler merges identical allow rules, so they take one slot rule each
// whatever the number of policies.
var runtimeDevices = []filepolicy.Rule{
	{Name: "runtime-devices", Action: "allow", Access: []string{filepolicy.AccessRead, filepolicy.AccessWrite},
		Paths: []string{"/dev/full", "/dev/null", "/dev/ptmx", "/dev/pts/**", "/dev/random", "/dev/tty", "/dev/urandom", "/dev/zero"}},
	{Name: "runtime-shm", Action: "allow", Access: []string{filepolicy.AccessRead, filepolicy.AccessWrite, filepolicy.AccessCreate, filepolicy.AccessDelete},
		Paths: []string{"/dev/shm/**"}},
}

// FileNode is what the file translation needs to know about this node.
type FileNode struct {
	// FromImageUnavailable says why the file gadget cannot judge fromImage
	// on this node's kernel; empty when it can.
	FromImageUnavailable string
}

// pathAliases adds, to each glob, the other names the kernel can show for
// the same file. The gadget judges the resolved path (d_path), not the name a
// program opens:
//   - /var/run/... is also /run/...: Debian and Ubuntu images link /var/run to
//     /run, and the runtime mounts at the resolved target;
//   - with mergedUsr (deny rules and their excepts), /bin/..., /sbin/...,
//     /lib/... and /lib64/... are also /usr/...: merged-usr images (Debian 12,
//     Ubuntu 22.04 and later) link those directories into /usr. On an image
//     where they are separate directories (Alpine), a deny of /lib/** also
//     covers /usr/lib/**: the translator does not know the image layout;
//   - a file is also the same name with a ..* directory before it: kubelet's
//     atomic writer (Secret, ConfigMap and projected volumes, such as the
//     service account token) links file to ..data/file and ..data to a
//     ..<timestamp> directory, so /dir/file is /dir/..<timestamp>/file
//     (atomicWriterAlias).
func pathAliases(paths []string, mergedUsr bool) []string {
	var out []string
	for _, p := range paths {
		forms := []string{p}
		if rest, ok := strings.CutPrefix(p, "/var/run/"); ok {
			forms = append(forms, "/run/"+rest)
		}
		if mergedUsr {
			for _, dir := range []string{"/bin/", "/sbin/", "/lib/", "/lib64/"} {
				if strings.HasPrefix(p, dir) {
					forms = append(forms, "/usr"+p)
				}
			}
		}
		for _, f := range forms {
			out = append(out, f)
			if alias, ok := atomicWriterAlias(f); ok {
				out = append(out, alias)
			}
		}
	}
	return out
}

// atomicWriterAlias returns the glob with a ..* segment inserted before its
// last segment, unless the last or the one before it is ** (a glob for a
// whole directory, or one whose ** already matches the ..<timestamp>
// directory). A key with a directory (items path a/b) puts the ..<timestamp>
// directory higher up; an alias for every level does not fit the gadget's
// segment budget with the built-in classes, so it is not added.
func atomicWriterAlias(glob string) (string, bool) {
	p, err := filepolicy.ParsePattern(glob)
	n := len(p.Segments)
	if err != nil || n < 2 || p.Segments[n-1].Kind == filepolicy.SegDoubleStar || p.Segments[n-2].Kind == filepolicy.SegDoubleStar {
		return "", false
	}
	alias := filepolicy.Pattern{Segments: slices.Insert(slices.Clone(p.Segments), n-1, filepolicy.Segment{Kind: filepolicy.SegGlob, Pre: ".."})}
	return alias.String(), true
}

// filePatternError and checkFileDocument are the gadget's checks of one path
// glob and of a whole document. They are variables so that the translation
// can be tested on its own.
var (
	filePatternError = func(p string) error {
		_, err := filepolicy.ParsePattern(p)
		return err
	}
	checkFileDocument = func(doc filepolicy.Document) error {
		if err := doc.Validate(); err != nil {
			return err
		}
		// The node instance merges this document with others, so a document
		// over the gadget limits alone fails there in every combination.
		// Report it here, as a reason of this policy.
		if _, err := filepolicy.CompileKernel(doc, 1); err != nil {
			return fmt.Errorf("the policy alone exceeds the file gadget limits: %w", err)
		}
		return nil
	}
)

// TranslateFile translates the file section of one policy to the file
// gadget's document. Path classes resolve to the built-in classes, the shared
// SandboxPolicyClasses entries and the policy's own additions; every glob gets
// its aliases (pathAliases). What the gadget cannot enforce (execMap, fsType,
// fromImage false, fromImage on a kernel whose overlay layout the gadget
// cannot read, globs it cannot express) is reported. An unresolved class
// follows the design (sandbox-policy-crd.md section 4.3): a deny rule degrades
// to audit and, like the network translator's, keeps no path, so that it cannot
// hide the policy's own enforce default deny; an allow rule degrades the
// defaults of its access kinds to audit and makes the policy not ready
// (ClassUnresolved); an except entry is disabled (its deny applies there) and
// makes the policy not ready. An allow rule the gadget cannot enforce degrades
// the same defaults and makes the policy not ready (RuleNotEnforceable), so
// the policy never denies more than it was written to.
func TranslateFile(spec api.PolicySpec, x FileExtras, shared map[string][]string, node FileNode) (*FilePlan, error) {
	f := spec.File
	if f == nil {
		return nil, nil
	}
	if err := validateFile(*f, x); err != nil {
		return nil, err
	}
	var local map[string][]string
	if spec.Classes != nil {
		local = spec.Classes.PathClasses
	}
	t := &pathTranslator{shared: shared, local: local, seen: map[string]bool{}}
	plan := &FilePlan{Doc: filepolicy.Document{Version: 1, Policy: filepolicy.Policy{Mode: string(spec.Mode),
		File: filepolicy.Section{Defaults: map[string]filepolicy.Default{}}}}}
	report := &plan.Report
	report.Rules = int64(len(f.Rules))
	defaults := fileDefaults(f.Default)
	modes, origins := x.DefaultModeByAccess, x.DefaultOriginByAccess
	if f.Default.PerAccess == nil {
		modes = &FileAccessValues{x.DefaultMode, x.DefaultMode, x.DefaultMode, x.DefaultMode, x.DefaultMode, x.DefaultMode, x.DefaultMode}
		origins = &FileAccessValues{x.DefaultOrigin, x.DefaultOrigin, x.DefaultOrigin, x.DefaultOrigin, x.DefaultOrigin, x.DefaultOrigin, x.DefaultOrigin}
	}
	for _, k := range filepolicy.AccessKinds {
		plan.Doc.Policy.File.Defaults[k] = filepolicy.Default{Action: defaults.get(k), Mode: modes.get(k), Origin: origins.get(k)}
	}
	if defaults.ExecMap == string(api.ActionDeny) {
		report.NotEnforced = append(report.NotEnforced, "default execMap deny: execMap is not enforced")
	}
	// degrade: access kind -> why its default runs in audit.
	degrade := map[string]string{}
	degradeKinds := func(kinds []string, why string) {
		for _, k := range kinds {
			if degrade[k] == "" || why == "class-unresolved" {
				degrade[k] = why
			}
		}
	}
	names := map[string]bool{}
	for _, r := range f.Rules {
		names[r.Name] = true
	}
	for _, r := range f.Rules {
		requested := r.Mode
		if requested == "" {
			requested = api.RuleMode(spec.Mode)
		}
		effective, mode := string(requested), string(r.Mode)
		var reasons []string
		notEnforced := func(why string) {
			report.NotEnforced = append(report.NotEnforced, fmt.Sprintf("rule %s: %s", r.Name, why))
		}
		access := gadgetAccess(r.Target.Access)
		kinds := access
		if len(kinds) == 0 {
			kinds = filepolicy.AccessKinds
		}
		if slices.Contains(r.Target.Access, accessExecMap) {
			notEnforced("access execMap is not enforced")
			if len(access) == 0 {
				continue // execMap only
			}
		}
		// An allow rule the gadget cannot enforce degrades the defaults of
		// its access kinds and makes the policy not ready, as the network
		// translator does; ClassUnresolved is the stronger reason.
		notEnforceableAllow := func() {
			degradeKinds(kinds, "not-enforceable")
			if report.NotReady == "" {
				report.NotReady = "RuleNotEnforceable"
			}
		}
		if why := unenforceableTarget(r.Target, node); why != "" {
			notEnforced(why)
			if r.Action == api.ActionAllow {
				notEnforceableAllow()
				report.Degraded = append(report.Degraded, api.DegradedRule{Rule: r.Name, Requested: requested, Effective: string(requested), Reason: "not-enforceable"})
			}
			continue
		}
		paths, unresolved := t.paths(r.Target.Path, r.Target.PathClass)
		paths, bad := supportedPatterns(paths)
		paths = pathAliases(paths, r.Action == api.ActionDeny)
		if len(bad) > 0 {
			notEnforced(fmt.Sprintf("path %s cannot be expressed by the file gadget", strings.Join(bad, ",")))
			if r.Action == api.ActionAllow {
				notEnforceableAllow()
				reasons = append(reasons, "not-enforceable")
			}
		}
		if unresolved {
			reasons = append(reasons, "class-unresolved")
			if r.Action == api.ActionDeny {
				mode, effective = "audit", "audit"
				// The resolved paths alone would give a deny audit rule
				// that hides the policy's own enforce default deny there
				// (common/merge/CONTRACT.md, as in the network
				// translator). So no path.
				paths = nil
			} else {
				degradeKinds(kinds, "class-unresolved")
				report.NotReady = "ClassUnresolved"
			}
		}
		var excepts []string
		for i, e := range x.Except[r.Name] {
			lifted, why, classMissing := t.except(e, kinds)
			if why != "" {
				notEnforced(fmt.Sprintf("except %d is disabled (%s); the deny applies there", i, why))
				if classMissing {
					reasons = append(reasons, "except-class-unresolved")
					report.NotReady = "ClassUnresolved"
				}
				continue
			}
			excepts = append(excepts, lifted...)
		}
		if len(reasons) > 0 {
			report.Degraded = append(report.Degraded, api.DegradedRule{Rule: r.Name, Requested: requested, Effective: effective, Reason: strings.Join(sortedUnique(reasons), ",")})
		}
		fromImage := r.Target.FromImage != nil && *r.Target.FromImage
		hasPaths := len(r.Target.Path) > 0 || len(r.Target.PathClass) > 0
		switch {
		case hasPaths && len(paths) == 0:
			if r.Action == api.ActionDeny {
				notEnforced("no path is resolved")
			}
			continue
		case !hasPaths && !fromImage:
			paths = []string{"/**"} // an empty target matches every file
		}
		plan.Doc.Policy.File.Rules = append(plan.Doc.Policy.File.Rules, filepolicy.Rule{
			Name: r.Name, Action: string(r.Action), Mode: mode, Origin: r.Origin, Access: access,
			Paths: sortedUnique(paths), FromImage: fromImage, Except: sortedUnique(excepts)})
	}
	for _, devices := range runtimeDevices {
		devices.Name = freeName(devices.Name, names)
		plan.Doc.Policy.File.Rules = append(plan.Doc.Policy.File.Rules, devices)
	}
	for _, k := range filepolicy.AccessKinds {
		why := degrade[k]
		if why == "" {
			continue
		}
		def := plan.Doc.Policy.File.Defaults[k]
		requested := def.Mode
		if requested == "" {
			requested = string(spec.Mode)
		}
		def.Mode = "audit"
		plan.Doc.Policy.File.Defaults[k] = def
		if requested == "enforce" && def.Action == string(api.ActionDeny) {
			report.Degraded = append(report.Degraded, api.DegradedRule{Rule: "default/" + k, Requested: api.RuleEnforce, Effective: "audit", Reason: why})
		}
	}
	for _, resolved := range t.seen {
		if resolved {
			report.ClassesResolved++
		} else {
			report.ClassesUnresolved++
		}
	}
	if err := checkFileDocument(plan.Doc); err != nil {
		return nil, fmt.Errorf("file: %w", err)
	}
	return plan, nil
}

// gadgetAccess returns the gadget access kinds of a CRD access list, sorted in
// the gadget's order, without execMap. Nil means every kind.
func gadgetAccess(access []string) []string {
	var out []string
	for _, k := range filepolicy.AccessKinds {
		if slices.Contains(access, k) {
			out = append(out, k)
		}
	}
	return out
}

// unenforceableTarget says why the gadget cannot judge a target, or "".
func unenforceableTarget(t api.FileTarget, node FileNode) string {
	switch {
	case len(t.FSType) > 0:
		return "fsType is not enforced"
	case t.FromImage != nil && !*t.FromImage:
		return "fromImage false is not enforced"
	case t.FromImage != nil && node.FromImageUnavailable != "":
		return "fromImage is not enforced on this node: " + node.FromImageUnavailable
	}
	return ""
}

// supportedPatterns splits globs into those the gadget can match and the rest.
func supportedPatterns(paths []string) (ok, bad []string) {
	for _, p := range paths {
		if filePatternError(p) != nil {
			bad = append(bad, p)
		} else {
			ok = append(ok, p)
		}
	}
	return ok, bad
}

// freeName returns name, or name with the first free "~N" suffix when a CRD
// rule already has it.
func freeName(name string, used map[string]bool) string {
	out := name
	for i := 1; used[out]; i++ {
		out = fmt.Sprintf("%s~%d", name, i)
	}
	return out
}

type pathTranslator struct {
	shared, local map[string][]string
	// seen: class name -> resolved, for the status counts.
	seen map[string]bool
}

// paths returns the globs of the path and pathClass fields (they are ORed) and
// whether a class has no member.
func (t *pathTranslator) paths(paths, classes []string) ([]string, bool) {
	out := slices.Clone(paths)
	unresolved := false
	for _, name := range classes {
		members := append(append(slices.Clone(defaultPathClasses[name]), t.shared[name]...), t.local[name]...)
		t.seen[name] = len(members) > 0
		unresolved = unresolved || len(members) == 0
		out = append(out, members...)
	}
	return out, unresolved
}

// except returns the globs an except entry lifts, or why it is disabled.
// kinds are the gadget access kinds of its deny rule.
func (t *pathTranslator) except(e FileExcept, kinds []string) (lifted []string, why string, classMissing bool) {
	if e.Actor != nil {
		return nil, "actor predicates are unsupported", false
	}
	target := *e.Target
	if len(target.FSType) > 0 || target.FromImage != nil {
		return nil, "fromImage and fsType in an except are not enforceable", false
	}
	if len(target.Access) > 0 {
		for _, k := range kinds {
			if !slices.Contains(target.Access, k) {
				return nil, "an except must cover every access kind of its rule", false
			}
		}
	}
	if len(target.Path) == 0 && len(target.PathClass) == 0 {
		return []string{"/**"}, "", false
	}
	paths, unresolved := t.paths(target.Path, target.PathClass)
	if unresolved {
		return nil, "class-unresolved", true
	}
	if _, bad := supportedPatterns(paths); len(bad) > 0 {
		return nil, fmt.Sprintf("path %s cannot be expressed by the file gadget", strings.Join(bad, ",")), false
	}
	// Excepts belong to deny rules: they get the deny's merged /usr forms,
	// so an except /bin/sh still lifts the deny of /usr/bin/sh.
	return pathAliases(paths, true), "", false
}
