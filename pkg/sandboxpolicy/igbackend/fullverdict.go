package igbackend

import (
	"errors"
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
	// Shared reports that the event carried the additive shared-engine fields
	// (event ABI 1: exec_class, scope, exec_id, pass, uncertain,
	// facts_unknown, load_epoch); they are zero otherwise. task_cookie is
	// optional within that ABI: HasTaskCookie reports its presence.
	Shared                                   bool
	ExecClass, Pass, Uncertain, FactsUnknown uint32
	Scope, ExecID, LoadEpoch                 uint64
	HasTaskCookie                            bool
	TaskCookie                               uint64
}

// sharedVerdictPassUnknown is the pass value of a fault event
// (fullruntime.SharedVerdictPassUnknown); real passes are 0..5.
const sharedVerdictPassUnknown = ^uint32(0)

// sharedVerdictFields are the additive shared-engine event fields: all or
// none must be present. sharedVerdictTaskCookie is optional within them.
// load_epoch is the agent's nonzero per-load epoch: task_cookie restarts on
// every load, so an exec is keyed on (load_epoch, task_cookie, exec_id).
var sharedVerdictFields = map[string]dsapi.Kind{"exec_class": dsapi.Kind_Uint32, "scope": dsapi.Kind_Uint64, "exec_id": dsapi.Kind_Uint64, "pass": dsapi.Kind_Uint32, "uncertain": dsapi.Kind_Uint32, "facts_unknown": dsapi.Kind_Uint32, "load_epoch": dsapi.Kind_Uint64}

const sharedVerdictTaskCookie = "task_cookie"

// checkSharedVerdictSchema reports whether the additive shared fields are
// present, refusing a partial set or an incompatible type or size.
func checkSharedVerdictSchema(ds datasource.DataSource) (shared, cookie bool, err error) {
	present := 0
	for name, kind := range sharedVerdictFields {
		field := ds.GetField(name)
		if field == nil {
			continue
		}
		present++
		if err := checkVerdictField(field, name, kind); err != nil {
			return false, false, err
		}
	}
	if present != 0 && present != len(sharedVerdictFields) {
		return false, false, fmt.Errorf("partial shared verdict fields (%d of %d)", present, len(sharedVerdictFields))
	}
	if field := ds.GetField(sharedVerdictTaskCookie); field != nil {
		if present == 0 {
			return false, false, fmt.Errorf("shared verdict field %q without the shared event fields", sharedVerdictTaskCookie)
		}
		if err := checkVerdictField(field, sharedVerdictTaskCookie, dsapi.Kind_Uint64); err != nil {
			return false, false, err
		}
		cookie = true
	}
	return present != 0, cookie, nil
}

func checkVerdictField(field datasource.FieldAccessor, name string, kind dsapi.Kind) error {
	size := uint32(4)
	if kind == dsapi.Kind_Uint64 {
		size = 8
	}
	if field.Type() != kind || (field.Size() != 0 && field.Size() != size) {
		return fmt.Errorf("missing or incompatible full verdict field %q", name)
	}
	return nil
}

// FullVerdictDecoder snapshots bounded immutable provenance. It does not attach
// programs or attest that the kernel supplied complete or trustworthy facts.
type FullVerdictDecoder struct {
	binding        sandboxpolicy.Binding
	generation     uint64
	revision       string
	policies       []sandboxpolicy.PolicyRevision
	defaults       []fullpolicy.KernelPolicy
	defaultOrigins [][]string
	rules          []sandboxpolicy.RuleMatch
	// sharedAuditFaults admits the shared engine's Audit fault (G020 D1:
	// deny 1, mode 1, error 1) as a would-deny operational error. Only the
	// shared node engine enables it. The flag gates only shared events:
	// without it a shared fault must be a Strict denial. A non-shared
	// Audit fault (the base event ABI) is always admitted as a would-deny.
	sharedAuditFaults bool
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
		d.defaultOrigins = append(d.defaultOrigins, originList(p.Exec.DefaultOrigin))
	}
	for i, m := range program.Rules {
		r, _ := fullpolicy.Decode[fullpolicy.KernelRule](program.Entries[int(h.RuleBase)+i])
		action := api.ActionAllow
		if r.Deny == 1 {
			action = api.ActionDeny
		}
		var origins []string
		for _, authored := range policies[m.PolicyIndex].Exec.Rules {
			if authored.Name == m.Name {
				origins = originList(authored.Origin)
				break
			}
		}
		d.rules = append(d.rules, sandboxpolicy.RuleMatch{Policy: d.policies[m.PolicyIndex].Policy, Revision: m.Revision, Name: m.Name, Origin: m.Origin, Origins: origins, Action: action, Mode: fullMode(r.Mode)})
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
	// A shared event without its load epoch cannot be correlated: refuse it.
	if r.Shared && (r.LoadEpoch == 0 || r.ExecClass < 1 || r.ExecClass > 2 || r.Uncertain > 1 || (r.Pass > 5 && r.Pass != sharedVerdictPassUnknown)) {
		return bad()
	}
	for i := len(d.rules); i < 256; i++ {
		if r.MatchedRules[i/64]&(uint64(1)<<uint(i%64)) != 0 {
			return bad()
		}
	}
	out := sandboxpolicy.Verdict{Time: time.Now(), Revision: d.revision, PolicySet: append([]sandboxpolicy.PolicyRevision(nil), d.policies...), MatchesComplete: r.Error == 0, Origins: []string{}, ContainerID: d.binding.ContainerID, PodUID: d.binding.PodUID, BindingPID: d.binding.PID, MountNamespace: d.binding.MountNamespace, CgroupID: r.Cgroup, PID: r.PID, Mode: fullMode(r.Mode), Verdict: api.ActionAllow}
	if len(d.policies) == 1 {
		out.Policy = d.policies[0].Policy
	}
	if r.Shared {
		execID, epoch := r.ExecID, r.LoadEpoch
		out.ExecID, out.LoadEpoch = &execID, &epoch
		if r.Pass != sharedVerdictPassUnknown {
			pass := r.Pass
			out.Pass = &pass
		}
		if r.HasTaskCookie && r.TaskCookie != 0 {
			cookie := r.TaskCookie
			out.TaskCookie = &cookie
		}
		class, scope, uncertain, unknown := r.ExecClass, r.Scope, r.Uncertain == 1, r.FactsUnknown
		out.ExecClass, out.Scope, out.Uncertain, out.FactsUnknown = &class, &scope, &uncertain, &unknown
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
			m.Origins = append([]string{}, m.Origins...)
			out.Matches = append(out.Matches, m)
		}
	}
	if r.Error != 0 {
		// A Strict fault (deny 1, mode 2) denies. An Audit fault (deny 1,
		// mode 1) is a would-deny the kernel did not enforce; a shared event
		// carries it only when the shared engine enabled it.
		if r.Deny != 1 {
			return bad()
		}
		switch r.Mode {
		case 2: // Strict fault: an enforced denial.
		case 1:
			if r.Shared && !d.sharedAuditFaults {
				return bad()
			}
		default:
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
			switch p.Default {
			case 2:
				consider(api.ActionDeny, fullMode(p.Mode))
			case 1:
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
		out.Origins = append([]string{}, m.Origins...)
	}
	if len(out.Matches) == 0 {
		for i, p := range d.defaults {
			if (p.Default == 2 && deny) || (p.Default == 1 && !deny) {
				out.Origins = append(out.Origins, d.defaultOrigins[i]...)
			}
		}
		sort.Strings(out.Origins)
		out.Origins = distinctOrigins(out.Origins)
	}
	if len(out.Matches) == 0 && len(d.policies) > 1 {
		index := -1
		for i, p := range d.defaults {
			if (p.Default == 2 && deny) || (p.Default == 1 && !deny) {
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

// ErrVerdictDecode wraps every verdict event dropped because it could not be
// read from the datasource or decoded against its generation's catalogue.
// It reaches the onError callback only; enforcement is unaffected.
var ErrVerdictDecode = errors.New("sandbox verdict decode failed")

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
	shared, cookie, err := checkSharedVerdictSchema(ds)
	if err != nil {
		return RawFullVerdict{}, err
	}
	if shared {
		var errs [8]error
		out.Shared = true
		out.ExecClass, errs[0] = ds.GetField("exec_class").Uint32(data)
		out.Scope, errs[1] = ds.GetField("scope").Uint64(data)
		out.ExecID, errs[2] = ds.GetField("exec_id").Uint64(data)
		out.Pass, errs[3] = ds.GetField("pass").Uint32(data)
		out.Uncertain, errs[4] = ds.GetField("uncertain").Uint32(data)
		out.FactsUnknown, errs[5] = ds.GetField("facts_unknown").Uint32(data)
		out.LoadEpoch, errs[7] = ds.GetField("load_epoch").Uint64(data)
		if cookie {
			out.HasTaskCookie = true
			out.TaskCookie, errs[6] = ds.GetField(sharedVerdictTaskCookie).Uint64(data)
		}
		if err := errors.Join(errs[:]...); err != nil {
			return RawFullVerdict{}, err
		}
	}
	return out, nil
}

func originList(origin *string) []string {
	if origin == nil {
		return []string{}
	}
	return []string{*origin}
}

func distinctOrigins(origins []string) []string {
	if len(origins) == 0 {
		return []string{}
	}
	out := origins[:1]
	for _, origin := range origins[1:] {
		if origin != out[len(out)-1] {
			out = append(out, origin)
		}
	}
	return out
}

// subscribeFullVerdicts checks the verdict datasource schema before the
// engine activates anything, then decodes each event to emit.
func subscribeFullVerdicts(ds datasource.DataSource, emit func(RawFullVerdict), onError func(error)) error {
	if ds == nil || ds.ByteOrder() == nil {
		return fmt.Errorf("missing full enforcement verdict datasource")
	}
	for name, kind := range map[string]dsapi.Kind{"generation": dsapi.Kind_Uint64, "cgroup": dsapi.Kind_Uint64, "deny": dsapi.Kind_Uint32, "mode": dsapi.Kind_Uint32, "path_result": dsapi.Kind_Int32, "host_pid": dsapi.Kind_Uint32, "matched_rules": dsapi.ArrayOf(dsapi.Kind_Uint64), "error": dsapi.Kind_Uint32} {
		field := ds.GetField(name)
		if field == nil || field.Type() != kind {
			return fmt.Errorf("missing or incompatible full verdict field %q", name)
		}
		size := uint32(4)
		if kind == dsapi.Kind_Uint64 {
			size = 8
		}
		if name == "matched_rules" {
			size = 32
		}
		if field.Size() != 0 && field.Size() != size {
			return fmt.Errorf("invalid full verdict field size for %q", name)
		}
	}
	// Native BTF char arrays are CString; formatted datasource strings use
	// String. Both are read by the same String accessor, not byte-array guesses.
	path := ds.GetField("path")
	if path == nil || (path.Type() != dsapi.Kind_CString && path.Type() != dsapi.Kind_String) {
		return fmt.Errorf("missing or incompatible full verdict path")
	}
	// Additive shared-engine fields are optional, but never partial or mistyped.
	if _, _, err := checkSharedVerdictSchema(ds); err != nil {
		return err
	}
	return ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
		raw, err := ReadFullVerdict(ds, data)
		if err != nil {
			if onError != nil {
				onError(fmt.Errorf("%w: %w", ErrVerdictDecode, err))
			}
			return nil
		}
		if emit != nil {
			emit(raw)
		}
		return nil // Telemetry decode/export never changes enforcement lifecycle.
	}, 100)
}
