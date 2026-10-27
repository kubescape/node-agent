package sandboxpolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// Limits are deliberately bounded before handing work to the kernel backend,
// which may impose stricter supported-environment limits.
const MaxPoliciesPerBinding = 64
const MaxRulesPerPolicy = 256
const MaxPathsPerRule = 256

// Compile resolves a single policy without mutating its source objects. A missing
// class/profile is an error, never a wildcard or a silently omitted rule.
func Compile(ctx context.Context, identity PolicyIdentity, spec api.PolicySpec, classes api.PolicyClasses, binding Binding, resolver SourceResolver) (CompiledPolicy, error) {
	var result CompiledPolicy
	if err := validateShape(spec); err != nil {
		return result, err
	}
	if err := api.ValidatePolicySpec(spec); err != nil {
		return result, err
	}
	if spec.Mode != api.ModeAudit && spec.Mode != api.ModeEnforce {
		return result, fmt.Errorf("policy is not active: %q", spec.Mode)
	}
	if spec.File != nil || spec.Network != nil || spec.Privilege != nil || spec.Identity != nil {
		return result, fmt.Errorf("non-exec sections are unsupported")
	}
	// JSON cloning preserves all pointers and slice fields of the API vocabulary.
	data, err := json.Marshal(spec)
	if err != nil {
		return result, err
	}
	var copy api.PolicySpec
	if err = json.Unmarshal(data, &copy); err != nil {
		return result, err
	}
	result = CompiledPolicy{Identity: identity, Mode: copy.Mode, RootRole: copy.RootRole}
	if result.RootRole == "" {
		result.RootRole = "agent"
	}
	if copy.Exec != nil {
		result.Exec = *copy.Exec
	}
	names := make(map[string]bool)
	for _, r := range result.Exec.Rules {
		names[r.Name] = true
	}
	for i, source := range copy.Sources {
		if len(source.Include) == 0 {
			return result, fmt.Errorf("source %q has no include sections", source.ContainerProfile.Name)
		}
		for _, section := range source.Include {
			if section != "execs" {
				return result, fmt.Errorf("source section %q is unsupported", section)
			}
		}
		if resolver == nil {
			return result, fmt.Errorf("ContainerProfile resolver unavailable")
		}
		rules, err := resolver.ResolveExecs(ctx, binding.Namespace, source.ContainerProfile.Name, binding.ContainerName)
		if err != nil {
			return result, fmt.Errorf("ContainerProfile %s: %w", source.ContainerProfile.Name, err)
		}
		for j, rule := range rules {
			rule.Name = fmt.Sprintf("source-%d-exec-%d", i, j)
			if names[rule.Name] {
				return result, fmt.Errorf("source rule name collision: %s", rule.Name)
			}
			names[rule.Name] = true
			if rule.Origin == "" {
				rule.Origin = "ContainerProfile/" + binding.Namespace + "/" + source.ContainerProfile.Name
			}
			// Copy resolver-owned pointers before expanding path classes below.
			data, err := json.Marshal(rule)
			if err != nil {
				return result, err
			}
			var cloned api.ExecRule
			if err := json.Unmarshal(data, &cloned); err != nil {
				return result, err
			}
			result.Exec.Rules = append(result.Exec.Rules, cloned)
		}
	}
	if len(result.Exec.Rules) > MaxRulesPerPolicy {
		return result, fmt.Errorf("policy exceeds %d exec rules", MaxRulesPerPolicy)
	}
	for i := range result.Exec.Rules {
		r := &result.Exec.Rules[i]
		if r.Action != api.ActionAllow && r.Action != api.ActionDeny {
			return result, fmt.Errorf("rule %q has invalid action", r.Name)
		}
		if r.Mode != "" && r.Mode != api.RuleAudit && r.Mode != api.RuleEnforce {
			return result, fmt.Errorf("rule %q has invalid mode", r.Name)
		}
		for _, name := range r.Target.PathClass {
			paths, found := classes.PathClasses[name]
			if copy.Classes != nil {
				if local, ok := copy.Classes.PathClasses[name]; ok {
					paths, found = append(append([]string(nil), paths...), local...), true
				}
			}
			if !found || len(paths) == 0 {
				return result, fmt.Errorf("unresolved path class %q", name)
			}
			r.Target.Path = append(r.Target.Path, paths...)
		}
		r.Target.Path = sortedUnique(r.Target.Path)
		r.Target.PathClass = nil
		if len(r.Target.Path) > MaxPathsPerRule {
			return result, fmt.Errorf("rule %q exceeds %d paths", r.Name, MaxPathsPerRule)
		}
	}
	// Validate imported rules as well as authored rules after class expansion.
	validated := api.PolicySpec{Containers: copy.Containers, Mode: copy.Mode, RootRole: result.RootRole, Exec: &result.Exec}
	if err := api.ValidatePolicySpec(validated); err != nil {
		return result, err
	}
	result.Revision = digest(result)
	return result, nil
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func digest(value any) string {
	data, _ := json.Marshal(value) // callers use only concrete JSON-serializable API structs
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ValidatePolicySpec supplies semantic checks, not full CRD admission. These
// structural checks also protect direct/fake clients and prevent malformed
// container selectors from authorizing withdrawal of a previous good revision.
func validateShape(spec api.PolicySpec) error {
	if len(spec.Containers) == 0 {
		return fmt.Errorf("containers must not be empty")
	}
	for _, name := range spec.Containers {
		if name == "" {
			return fmt.Errorf("container name must not be empty")
		}
	}
	if spec.Mode != api.ModeOff && spec.Mode != api.ModeAudit && spec.Mode != api.ModeEnforce {
		return fmt.Errorf("invalid policy mode %q", spec.Mode)
	}
	if spec.Mode == api.ModeOff {
		return nil
	}
	if spec.File != nil || spec.Network != nil || spec.Privilege != nil || spec.Identity != nil {
		return fmt.Errorf("non-exec sections are unsupported")
	}
	if spec.Exec != nil {
		if spec.Exec.Default != api.ActionAllow && spec.Exec.Default != api.ActionDeny {
			return fmt.Errorf("exec requires an allow/deny default")
		}
		for _, rule := range spec.Exec.Rules {
			if rule.Action != api.ActionAllow && rule.Action != api.ActionDeny {
				return fmt.Errorf("rule %q has invalid action", rule.Name)
			}
			if rule.Mode != "" && rule.Mode != api.RuleAudit && rule.Mode != api.RuleEnforce {
				return fmt.Errorf("rule %q has invalid mode", rule.Name)
			}
		}
	}
	return nil
}
