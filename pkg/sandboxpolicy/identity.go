package sandboxpolicy

import (
	"fmt"
	"slices"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// expandIdentity moves the identity section of a policy into its file and
// network sections (sandbox-policy-crd.md section 5.5): a path or pathClass
// rule becomes a file rule with read access, an imds rule a network rule on
// the imds destination class, an envRead rule a file rule with read access on
// every environ file that judges only another process's procfs files (OtherProcess,
// whose rule names it returns). The generated rules keep the identity rule's
// name, action, mode and origin, so events and status name the identity rule.
// A section that identity needs and the policy lacks is added with an allow
// default, which does not change the merged result.
//
// The paths of the identity allow rules are subtracted from the classes of
// the identity deny rules, as except entries of those denies: a provisioned
// path in a class is then readable, under every alias the file translator
// gives the class member. The explicit paths of a deny are not subtracted
// (deny wins), so a deny with both paths and classes becomes two file rules.
// The split also keeps the explicit paths enforced when a class of the deny is
// unresolved (the file translator then drops every path of that rule).
//
// It reports what cannot be expressed: a deny default (identity has no
// universe of its own), a false imds or envRead, and an except entry whose
// target cannot match its rule's events.
func expandIdentity(spec api.PolicySpec) (api.PolicySpec, identityReport, error) {
	var report identityReport
	id := spec.Identity
	if id == nil {
		return spec, report, nil
	}
	spec.Identity = nil
	if id.Default != api.ActionAllow && id.Default != api.ActionDeny {
		return spec, report, fmt.Errorf("identity requires an allow/deny default")
	}
	// notEnforcedDeny reports a deny that nothing enforces; an enforce one
	// is also degraded, as the file and network translators do.
	notEnforcedDeny := func(rule string, mode api.RuleMode) {
		if mode == "" {
			mode = api.RuleMode(spec.Mode)
		}
		if mode == api.RuleEnforce {
			report.Degraded = append(report.Degraded, api.DegradedRule{Rule: rule, Requested: api.RuleEnforce, Effective: "audit", Reason: "not-enforceable"})
		}
	}
	if id.Default == api.ActionDeny {
		report.Notes = append(report.Notes, "default deny: identity has no default of its own; use deny rules")
		notEnforcedDeny("default/identity", id.DefaultMode)
	}
	names := ruleNames(spec, id)
	var provisioned []api.FileException
	for _, r := range id.Rules {
		if r.Action != api.ActionAllow && r.Action != api.ActionDeny {
			return spec, report, fmt.Errorf("rule %q has invalid action", r.Name)
		}
		if !validMode(string(r.Mode)) {
			return spec, report, fmt.Errorf("rule %q has invalid mode", r.Name)
		}
		if r.Actor != nil {
			return spec, report, fmt.Errorf("rule %q: actor predicates are unsupported in the identity section", r.Name)
		}
		if err := r.Target.Validate(); err != nil {
			return spec, report, fmt.Errorf("rule %q: %w", r.Name, err)
		}
		if r.Action == api.ActionAllow && isPathTarget(r.Target) {
			provisioned = append(provisioned, api.FileException{Target: fileTarget(r.Target.Path, r.Target.PathClass)})
		}
	}
	var files []api.FileRule
	var networks []api.NetworkRule
	for _, r := range id.Rules {
		note := func(why string) { report.Notes = append(report.Notes, fmt.Sprintf("rule %s: %s", r.Name, why)) }
		t := r.Target
		switch {
		case isPathTarget(t):
			excepts := identityExcepts(r, isPathTarget, note, func(e api.IdentityException) api.FileException {
				out := api.FileException{Actor: e.Actor}
				if e.Target != nil {
					out.Target = fileTarget(e.Target.Path, e.Target.PathClass)
				}
				return out
			})
			if r.Action == api.ActionDeny && len(t.PathClass) > 0 {
				files = append(files, identityFileRule(r.Rule, nil, t.PathClass, append(slices.Clone(excepts), provisioned...)))
				if len(t.Path) > 0 {
					rule := r.Rule
					rule.Name = splitName(r.Name, names)
					names[rule.Name] = true
					files = append(files, identityFileRule(rule, t.Path, nil, excepts))
				}
				continue
			}
			files = append(files, identityFileRule(r.Rule, t.Path, t.PathClass, excepts))
		case t.IMDS != nil:
			if !*t.IMDS {
				note("imds false selects nothing")
				continue
			}
			excepts := identityExcepts(r, func(t api.IdentityTarget) bool { return t.IMDS != nil && *t.IMDS }, note, func(e api.IdentityException) api.NetworkException {
				out := api.NetworkException{Actor: e.Actor}
				if e.Target != nil {
					out.Target = &api.NetworkTarget{DestClass: []string{"imds"}}
				}
				return out
			})
			networks = append(networks, api.NetworkRule{Rule: r.Rule, Target: api.NetworkTarget{DestClass: []string{"imds"}}, Except: excepts})
		case t.EnvRead != nil:
			if !*t.EnvRead {
				note("envRead false selects nothing")
				continue
			}
			excepts := identityExcepts(r, func(t api.IdentityTarget) bool { return t.EnvRead != nil && *t.EnvRead }, note, func(e api.IdentityException) api.FileException {
				out := api.FileException{Actor: e.Actor}
				if e.Target != nil {
					out.Target = fileTarget(environPaths, nil)
				}
				return out
			})
			files = append(files, identityFileRule(r.Rule, environPaths, nil, excepts))
			if report.OtherProcess == nil {
				report.OtherProcess = map[string]bool{}
			}
			report.OtherProcess[r.Name] = true
		}
	}
	if len(files) > 0 {
		f := api.FileSection{Default: api.ActionAllow}
		if spec.File != nil {
			f = *spec.File
		}
		f.Rules = append(slices.Clone(f.Rules), files...)
		spec.File = &f
	}
	if len(networks) > 0 {
		n := api.NetworkSection{Default: api.NetworkDefault{Egress: api.ActionAllow, Listen: api.ActionAllow}}
		if spec.Network != nil {
			n = *spec.Network
		}
		n.Rules = append(slices.Clone(n.Rules), networks...)
		spec.Network = &n
	}
	return spec, report, nil
}

// identityReport is what the status says about the identity section.
type identityReport struct {
	// Notes lists what cannot be expressed (IdentityNotEnforced).
	Notes []string
	// Degraded lists the enforce denies among them.
	Degraded []api.DegradedRule
	// OtherProcess names the generated file rules of envRead.
	OtherProcess map[string]bool
}

// environPaths are the environ files of a process and of its threads, under
// any mount point of procfs (a second proc mount, a host /proc volume). The
// gadget's otherProcess check reads the inode, so only procfs environ files of
// another process match.
var environPaths = []string{"/**/environ"}

// splitName names the explicit-path part of a split deny: the rule name with
// "/path" (and a free "~N"), cut so that it stays within the API's limit.
func splitName(name string, used map[string]bool) string {
	base := []rune(name)
	for {
		out := freeName(string(base)+"/path", used)
		n := len([]rune(out))
		if n <= api.MaxRuleNameLength {
			return out
		}
		base = base[:len(base)-(n-api.MaxRuleNameLength)]
	}
}

func isPathTarget(t api.IdentityTarget) bool { return len(t.Path) > 0 || len(t.PathClass) > 0 }

func fileTarget(paths, classes []string) *api.FileTarget {
	return &api.FileTarget{PathTarget: api.PathTarget{Path: slices.Clone(paths), PathClass: slices.Clone(classes)}}
}

func identityFileRule(rule api.Rule, paths, classes []string, excepts []api.FileException) api.FileRule {
	return api.FileRule{Rule: rule, Target: api.FileTarget{PathTarget: fileTarget(paths, classes).PathTarget,
		Access: []string{"read"}}, Except: excepts}
}

// identityExcepts maps the except entries of an identity rule. An entry whose
// target cannot match the rule's events (another kind, or imds false) is
// dropped and reported: the deny applies there.
func identityExcepts[E any](r api.IdentityRule, sameKind func(api.IdentityTarget) bool, note func(string), convert func(api.IdentityException) E) []E {
	var out []E
	for i, e := range r.Except {
		if e.Target != nil && !sameKind(*e.Target) {
			note(fmt.Sprintf("except %d is disabled (its target cannot match the rule's events); the deny applies there", i))
			continue
		}
		out = append(out, convert(e))
	}
	return out
}

// ruleNames returns the rule names of every section of a policy.
func ruleNames(spec api.PolicySpec, id *api.IdentitySection) map[string]bool {
	names := map[string]bool{}
	if spec.Exec != nil {
		for _, r := range spec.Exec.Rules {
			names[r.Name] = true
		}
	}
	if spec.File != nil {
		for _, r := range spec.File.Rules {
			names[r.Name] = true
		}
	}
	if spec.Network != nil {
		for _, r := range spec.Network.Rules {
			names[r.Name] = true
		}
	}
	if spec.Privilege != nil {
		for _, r := range spec.Privilege.Rules {
			names[r.Name] = true
		}
	}
	for _, r := range id.Rules {
		names[r.Name] = true
	}
	return names
}
