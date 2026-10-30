package igbackend

import (
	"fmt"
	"path"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	dsapi "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

type RawFullVerdict struct {
	RawVerdict
	MatchedRules [4]uint64
	Error        uint32
}

// FullVerdictDecoder snapshots bounded immutable provenance. It does not attach
// programs or attest that the kernel supplied complete or trustworthy facts.
type FullVerdictDecoder struct {
	binding    sandboxpolicy.Binding
	generation uint64
	revision   string
	policies   []sandboxpolicy.PolicyRevision
	defaults   []fullpolicy.KernelPolicy
	rules      []sandboxpolicy.RuleMatch
}

func NewFullVerdictDecoder(binding sandboxpolicy.Binding, plan sandboxpolicy.Plan, program *fullpolicy.KernelProgram) (*FullVerdictDecoder, error) {
	if err := fullpolicy.ValidateKernelProgram(program); err != nil {
		return nil, err
	}
	if binding.CgroupID == 0 {
		return nil, fmt.Errorf("full verdict requires a bound cgroup")
	}
	h, _ := fullpolicy.Decode[fullpolicy.KernelHeader](program.Entries[0])
	epochs := make(map[string]uint64, h.PolicyCount)
	for i := uint32(0); i < h.PolicyCount; i++ {
		p, _ := fullpolicy.Decode[fullpolicy.KernelPolicy](program.Entries[fullpolicy.KernelPolicyBase+i])
		epochs[program.Identities[p.UID]] = p.RootEpoch
	}
	// Compare the complete immutable IR, not merely self-consistent metadata: a
	// valid program for a different plan must not borrow this plan's provenance.
	// Rule-free policy revisions and display identities are not encoded in the
	// IR; these remain trusted owner-supplied plan metadata, not kernel evidence.
	expected, err := CompileFull(binding, plan, h.Generation, epochs)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(expected, program) {
		return nil, fmt.Errorf("full verdict program does not match plan")
	}
	policies := append([]sandboxpolicy.CompiledPolicy(nil), plan.Policies...)
	sort.Slice(policies, func(i, j int) bool { return policies[i].Identity.UID < policies[j].Identity.UID })
	d := &FullVerdictDecoder{binding: sandboxpolicy.Binding{ContainerID: binding.ContainerID, PodUID: binding.PodUID, PID: binding.PID, MountNamespace: binding.MountNamespace, CgroupID: binding.CgroupID}, generation: h.Generation, revision: plan.Revision}
	for i, p := range policies {
		d.policies = append(d.policies, sandboxpolicy.PolicyRevision{Policy: p.Identity, Revision: p.Revision})
		kp, _ := fullpolicy.Decode[fullpolicy.KernelPolicy](program.Entries[fullpolicy.KernelPolicyBase+i])
		d.defaults = append(d.defaults, kp)
	}
	for i, m := range program.Rules {
		r, _ := fullpolicy.Decode[fullpolicy.KernelRule](program.Entries[int(h.RuleBase)+i])
		action := api.ActionAllow
		if r.Deny == 1 {
			action = api.ActionDeny
		}
		d.rules = append(d.rules, sandboxpolicy.RuleMatch{Policy: d.policies[m.PolicyIndex].Policy, Revision: m.Revision, Name: m.Name, Origin: m.Origin, Action: action, Mode: fullMode(r.Mode)})
	}
	return d, nil
}
func fullMode(mode uint32) api.RuleMode {
	if mode == 2 {
		return api.RuleEnforce
	}
	return api.RuleAudit
}

func (d *FullVerdictDecoder) Decode(r RawFullVerdict) (sandboxpolicy.Verdict, error) {
	bad := func() (sandboxpolicy.Verdict, error) {
		return sandboxpolicy.Verdict{}, fmt.Errorf("invalid full verdict identity or decision")
	}
	if d == nil || d.generation == 0 || len(d.policies) == 0 || r.Generation != d.generation || r.Cgroup != d.binding.CgroupID || r.Deny > 1 || r.Mode < 1 || r.Mode > 2 || r.Error > 3 {
		return bad()
	}
	for i := len(d.rules); i < 256; i++ {
		if r.MatchedRules[i/64]&(uint64(1)<<uint(i%64)) != 0 {
			return bad()
		}
	}
	out := sandboxpolicy.Verdict{Time: time.Now(), Revision: d.revision, PolicySet: append([]sandboxpolicy.PolicyRevision(nil), d.policies...), MatchesComplete: r.Error == 0, ContainerID: d.binding.ContainerID, PodUID: d.binding.PodUID, BindingPID: d.binding.PID, MountNamespace: d.binding.MountNamespace, CgroupID: r.Cgroup, PID: r.PID, Mode: fullMode(r.Mode), Verdict: api.ActionAllow}
	if len(d.policies) == 1 {
		out.Policy = d.policies[0].Policy
	}
	if r.Deny == 1 {
		out.Verdict = api.ActionDeny
		out.WouldDeny = r.Mode == 1
	}
	// A nonpositive path result is unavailable, even if the raw buffer contains
	// stale or partial bytes. It says nothing about UID-only matching success.
	if r.PathResult > 0 {
		if r.PathResult > 256 || int(r.PathResult) != len(r.Path)+1 || !path.IsAbs(r.Path) || path.Clean(r.Path) != r.Path || strings.ContainsRune(r.Path, 0) {
			return bad()
		}
		out.TargetPath = r.Path
	}
	for i, m := range d.rules {
		if r.MatchedRules[i/64]&(uint64(1)<<uint(i%64)) != 0 {
			out.Matches = append(out.Matches, m)
		}
	}
	if r.Error != 0 {
		if r.Deny != 1 || r.Mode != 2 {
			return bad()
		}
		out.Reason = "operational_error"
		return out, nil // partial matches never imply a semantic decisive rule
	}
	deny, allowMode, denyMode := false, api.RuleAudit, api.RuleAudit
	consider := func(action api.Action, mode api.RuleMode) {
		if action == api.ActionDeny {
			deny = true
			if mode == api.RuleEnforce {
				denyMode = mode
			}
		} else if action == api.ActionAllow && mode == api.RuleEnforce {
			allowMode = mode
		}
	}
	out.Reason = "matching_rule"
	for _, m := range out.Matches {
		consider(m.Action, m.Mode)
	}
	if len(out.Matches) == 0 {
		out.Reason = "section_default"
		for _, p := range d.defaults {
			if p.Default == 2 {
				consider(api.ActionDeny, fullMode(p.Mode))
			} else if p.Default == 1 {
				consider(api.ActionAllow, fullMode(p.Mode))
			}
		}
	}
	wantDeny := uint32(0)
	wantMode := allowMode
	if deny {
		wantDeny = 1
		wantMode = denyMode
	}
	if r.Deny != wantDeny || out.Mode != wantMode {
		return bad()
	}
	// Attribute only a unique contributor to the global outcome. Defaults apply
	// only when the entire rule union is empty, never per unmatched policy.
	decisive := []sandboxpolicy.RuleMatch{}
	for _, m := range out.Matches {
		if m.Action == out.Verdict && m.Mode == out.Mode {
			decisive = append(decisive, m)
		}
	}
	if len(decisive) == 1 {
		m := decisive[0]
		out.Policy = m.Policy
		out.Rule = m.Name
		out.Origin = m.Origin
	}
	if len(out.Matches) == 0 && len(d.policies) > 1 {
		index := -1
		for i, p := range d.defaults {
			if ((p.Default == 2 && deny) || (p.Default == 1 && !deny)) && fullMode(p.Mode) == out.Mode {
				if index >= 0 {
					index = -2
					break
				}
				index = i
			}
		}
		if index >= 0 {
			out.Policy = d.policies[index].Policy
		}
	}
	return out, nil
}

// ReadFullVerdict checks schema presence before invoking typed accessors. Bitmap
// words use the producer's byte order, not the host's or the IR encoding order.
func ReadFullVerdict(ds datasource.DataSource, data datasource.Data) (RawFullVerdict, error) {
	var out RawFullVerdict
	if ds == nil || ds.ByteOrder() == nil {
		return out, fmt.Errorf("missing full verdict datasource")
	}
	for _, name := range []string{"generation", "cgroup", "deny", "mode", "host_pid", "path_result", "path", "matched_rules", "error"} {
		if ds.GetField(name) == nil {
			return out, fmt.Errorf("missing full verdict field %s", name)
		}
	}
	raw, err := readVerdict(ds, data)
	if err != nil {
		return out, err
	}
	out.RawVerdict = raw
	out.Error, err = ds.GetField("error").Uint32(data)
	if err != nil {
		return RawFullVerdict{}, err
	}
	field := ds.GetField("matched_rules")
	if field.Type() != dsapi.ArrayOf(dsapi.Kind_Uint64) || len(field.Get(data)) != 8*len(out.MatchedRules) {
		return RawFullVerdict{}, fmt.Errorf("invalid full verdict bitmap schema or length")
	}
	bitmap, err := field.Uint64Array(data)
	if err != nil {
		return RawFullVerdict{}, err
	}
	if len(bitmap) != len(out.MatchedRules) {
		return RawFullVerdict{}, fmt.Errorf("invalid full verdict bitmap length")
	}
	copy(out.MatchedRules[:], bitmap)
	return out, nil
}
