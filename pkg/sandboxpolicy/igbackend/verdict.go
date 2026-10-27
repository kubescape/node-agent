package igbackend

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

type RawVerdict struct {
	Generation, Cgroup uint64
	Deny, Mode, PID    uint32
	PathResult         int32
	Path               string
}

func readVerdict(ds datasource.DataSource, data datasource.Data) (RawVerdict, error) {
	var r RawVerdict
	var errs [7]error
	r.Generation, errs[0] = ds.GetField("generation").Uint64(data)
	r.Cgroup, errs[1] = ds.GetField("cgroup").Uint64(data)
	r.Deny, errs[2] = ds.GetField("deny").Uint32(data)
	r.Mode, errs[3] = ds.GetField("mode").Uint32(data)
	r.PID, errs[4] = ds.GetField("host_pid").Uint32(data)
	r.PathResult, errs[5] = ds.GetField("path_result").Int32(data)
	r.Path, errs[6] = ds.GetField("path").String(data)
	return r, errors.Join(errs[:]...)
}

// DecodeVerdict leaves argv, UID, image origin and actor paths absent when the
// legacy event cannot supply them. Time is receipt time, not kernel time.
func DecodeVerdict(binding sandboxpolicy.Binding, plan sandboxpolicy.Plan, generation uint64, r RawVerdict) (sandboxpolicy.Verdict, error) {
	var out sandboxpolicy.Verdict
	if len(plan.Policies) != 1 || r.Generation != generation || r.Cgroup != binding.CgroupID || r.Deny > 1 || r.Mode < 1 || r.Mode > 2 {
		return out, fmt.Errorf("verdict identity or values do not match active instance")
	}
	p := plan.Policies[0]
	out = sandboxpolicy.Verdict{Time: time.Now(), Policy: p.Identity, Revision: plan.Revision, ContainerID: binding.ContainerID, PodUID: binding.PodUID, BindingPID: binding.PID, MountNamespace: binding.MountNamespace, CgroupID: r.Cgroup, PID: r.PID, TargetPath: r.Path, Mode: api.RuleAudit, Verdict: api.ActionAllow}
	if r.Mode == 2 {
		out.Mode = api.RuleEnforce
	}
	if r.Deny == 1 {
		out.Verdict = api.ActionDeny
		out.WouldDeny = r.Mode == 1
	}
	if r.PathResult <= 0 {
		out.TargetPath = ""
		out.Reason = "path_resolution_error"
		return out, nil
	}
	if r.PathResult > 256 || int(r.PathResult) != len(r.Path)+1 || !path.IsAbs(r.Path) || path.Clean(r.Path) != r.Path || strings.ContainsRune(r.Path, 0) {
		return sandboxpolicy.Verdict{}, fmt.Errorf("malformed resolved verdict path")
	}
	out.Reason = "section_default"
	var decisive []api.ExecRule
	for _, rule := range p.Exec.Rules {
		match := false
		for _, pattern := range rule.Target.Path {
			if pattern == r.Path || (strings.HasSuffix(pattern, "/**") && strings.HasPrefix(r.Path, strings.TrimSuffix(pattern, "**"))) {
				match = true
				break
			}
		}
		if !match || rule.Action != out.Verdict {
			continue
		}
		if out.Verdict == api.ActionDeny {
			mode := rule.Mode
			if mode == "" {
				mode = api.RuleMode(p.Mode)
			}
			if mode != out.Mode {
				continue
			}
		}
		decisive = append(decisive, rule)
	}
	if len(decisive) > 0 {
		out.Reason = "matching_rule"
	}
	if len(decisive) == 1 {
		out.Rule = decisive[0].Name
		out.Origin = decisive[0].Origin
	}
	return out, nil
}
