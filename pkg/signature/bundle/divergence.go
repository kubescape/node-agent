//go:build experimental_signing

package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"

	rulemanagertypesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// specPathFields names every top-level ContainerProfileSpec path for the
// divergence diff. setSpecPaths (class confinement, security-relevant) keeps
// its own checks; TestSpecPathTableMatchesSetSpecPaths pins the two lists to
// each other so a new spec field cannot silently join only one of them.
var specPathFields = []struct {
	name string
	get  func(*v1beta1.ContainerProfileSpec) any
}{
	{"architectures", func(s *v1beta1.ContainerProfileSpec) any { return s.Architectures }},
	{"capabilities", func(s *v1beta1.ContainerProfileSpec) any { return s.Capabilities }},
	{"execs", func(s *v1beta1.ContainerProfileSpec) any { return s.Execs }},
	{"opens", func(s *v1beta1.ContainerProfileSpec) any { return s.Opens }},
	{"syscalls", func(s *v1beta1.ContainerProfileSpec) any { return s.Syscalls }},
	{"seccompProfile", func(s *v1beta1.ContainerProfileSpec) any { return s.SeccompProfile }},
	{"endpoints", func(s *v1beta1.ContainerProfileSpec) any { return s.Endpoints }},
	{"imageID", func(s *v1beta1.ContainerProfileSpec) any { return s.ImageID }},
	{"imageTag", func(s *v1beta1.ContainerProfileSpec) any { return s.ImageTag }},
	{"rulePolicies", func(s *v1beta1.ContainerProfileSpec) any { return s.PolicyByRuleId }},
	{"identifiedCallStacks", func(s *v1beta1.ContainerProfileSpec) any { return s.IdentifiedCallStacks }},
	{"labelSelector", func(s *v1beta1.ContainerProfileSpec) any {
		return struct {
			ML map[string]string
			ME any
		}{s.MatchLabels, s.MatchExpressions}
	}},
	{"ingress", func(s *v1beta1.ContainerProfileSpec) any { return s.Ingress }},
	{"egress", func(s *v1beta1.ContainerProfileSpec) any { return s.Egress }},
}

// DiffSpecPaths reports the sorted top-level spec paths on which a and b
// differ. Path names only — values never leave this function, so nothing an
// attacker writes into a stored spec can reach a log pipeline through it.
// nil and empty collections compare equal at every level: the embed
// canonicalization materializes empty maps where the stored object has nil,
// and that must not read as divergence.
func DiffSpecPaths(a, b *v1beta1.ContainerProfileSpec) []string {
	var out []string
	for _, f := range specPathFields {
		if !fieldsEqual(f.get(a), f.get(b)) {
			out = append(out, f.name)
		}
	}
	sort.Strings(out)
	return out
}

func fieldsEqual(a, b any) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}
	aj, aerr := json.Marshal(a)
	bj, berr := json.Marshal(b)
	if aerr != nil || berr != nil {
		return true
	}
	var av, bv any
	if json.Unmarshal(aj, &av) != nil || json.Unmarshal(bj, &bv) != nil {
		return true
	}
	return normEqual(av, bv)
}

func emptyish(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case map[string]any:
		return len(t) == 0
	case []any:
		return len(t) == 0
	}
	return false
}

func normEqual(a, b any) bool {
	if emptyish(a) && emptyish(b) {
		return true
	}
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			return false
		}
		for k := range av {
			if !normEqual(av[k], bv[k]) {
				return false
			}
		}
		for k := range bv {
			if _, seen := av[k]; !seen && !normEqual(nil, bv[k]) {
				return false
			}
		}
		return true
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !normEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(a, b)
	}
}

// FragmentStoredDivergence compares a fragment's STORED spec against its
// embedded signed spec. paths is non-empty when the readable object shows
// content that is not what is enforced (or hides content that is). ok is false
// when there is nothing to compare (no embedded content) or the comparison
// itself failed — observability only, so a broken comparison never influences
// admission and reports nothing rather than something wrong.
func FragmentStoredDivergence(cp *v1beta1.ContainerProfile) (paths []string, storedHash string, ok bool) {
	adapter := profiles.NewContainerProfileAdapter(cp)
	embedded, present, err := signature.EmbeddedContent(adapter)
	if !present || err != nil {
		return nil, "", false
	}
	var view embeddedView
	if err := json.Unmarshal(embedded, &view); err != nil {
		return nil, "", false
	}
	return DiffSpecPaths(&cp.Spec, &view.Spec), hashSpec(cp.Spec), true
}

// RulesStoredDivergence is the Rules analogue: the stored rules list vs the
// embedded signed one. Counts only, never rule content.
func RulesStoredDivergence(r *rulemanagertypesv1.Rules) (diverged bool, storedCount, signedCount int, storedHash string, ok bool) {
	adapter := profiles.NewRulesAdapter(r)
	embedded, present, err := signature.EmbeddedContent(adapter)
	if !present || err != nil {
		return false, 0, 0, "", false
	}
	var view rulesEmbeddedView
	if err := json.Unmarshal(embedded, &view); err != nil {
		return false, 0, 0, "", false
	}
	diverged = !fieldsEqual(r.Spec.Rules, view.Spec.Rules)
	return diverged, len(r.Spec.Rules), len(view.Spec.Rules), hashSpec(r.Spec.Rules), true
}

func hashSpec(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
