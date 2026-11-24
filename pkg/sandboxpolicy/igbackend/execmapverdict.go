package igbackend

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	dsapi "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// The executable-mapping gate's verdicts (IG full/shared_exec_map.h, the
// "execmap" datasource): one event per executable mapping that a Strict
// binding denied or an Audit binding would deny. They are exec verdicts of
// the binding's policy with a MappingHook and a mapping_* reason.

// execMapReason names IG's enum em_cell for a refused mapping.
func execMapReason(cell uint32) string {
	switch cell {
	case 3:
		return "mapping_not_from_image"
	case 4:
		return "mapping_unknown"
	case 5, 11, 12: // anonymous memory, shmem/memfd, /dev/zero
		return "mapping_anonymous"
	case 6:
		return "mapping_written"
	}
	return "mapping_other"
}

var execMapHooks = map[uint32]string{1: "mmap_file", 2: "file_mprotect"}

// decodeMapping is Decode for a mapping event: the binding's policy set and
// revision of its generation, no rule attribution.
func (d *FullVerdictDecoder) decodeMapping(r RawFullVerdict) (sandboxpolicy.Verdict, error) {
	hook, ok := execMapHooks[r.Hook]
	if !ok || !r.Shared || r.LoadEpoch == 0 || r.ExecClass < 1 || r.ExecClass > 2 || r.Mode != r.ExecClass || r.Deny != boolU32(r.ExecClass == 2) {
		return sandboxpolicy.Verdict{}, fmt.Errorf("invalid executable-mapping verdict")
	}
	class, scope, epoch := r.ExecClass, r.Scope, r.LoadEpoch
	out := sandboxpolicy.Verdict{Time: time.Now(), Revision: d.revision, PolicySet: append([]sandboxpolicy.PolicyRevision(nil), d.policies...), MatchesComplete: true, Origins: []string{}, ContainerID: d.binding.ContainerID, PodUID: d.binding.PodUID, BindingPID: d.binding.PID, MountNamespace: d.binding.MountNamespace, CgroupID: r.Cgroup, PID: r.PID, Mode: fullMode(r.Mode), Verdict: api.ActionDeny, WouldDeny: r.ExecClass == 1, Reason: execMapReason(r.MapReason), MappingHook: hook, ExecClass: &class, Scope: &scope, LoadEpoch: &epoch}
	if len(d.policies) == 1 {
		out.Policy = d.policies[0].Policy
	}
	if r.Path != "" && path.IsAbs(r.Path) && path.Clean(r.Path) == r.Path && !strings.ContainsRune(r.Path, 0) && len(r.Path) < 256 {
		out.TargetPath = r.Path
	}
	return out, nil
}

func boolU32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// execMapFields are the fields node-agent reads from the "execmap"
// datasource, with their kinds.
var execMapFields = map[string]dsapi.Kind{"generation": dsapi.Kind_Uint64, "scope": dsapi.Kind_Uint64, "cgroup": dsapi.Kind_Uint64, "ino": dsapi.Kind_Uint64, "load_epoch": dsapi.Kind_Uint64, "dev": dsapi.Kind_Uint32, "hook": dsapi.Kind_Uint32, "reason": dsapi.Kind_Uint32, "exec_class": dsapi.Kind_Uint32, "deny": dsapi.Kind_Uint32, "host_pid": dsapi.Kind_Uint32}

// ReadExecMapVerdict reads one "execmap" event as a mapping RawFullVerdict.
func ReadExecMapVerdict(ds datasource.DataSource, data datasource.Data) (RawFullVerdict, error) {
	out := RawFullVerdict{Shared: true, Mapping: true}
	var errs []error
	u64 := func(name string, dst *uint64) {
		v, err := ds.GetField(name).Uint64(data)
		*dst = v
		errs = append(errs, err)
	}
	u32 := func(name string, dst *uint32) {
		v, err := ds.GetField(name).Uint32(data)
		*dst = v
		errs = append(errs, err)
	}
	u64("generation", &out.Generation)
	u64("scope", &out.Scope)
	u64("cgroup", &out.Cgroup)
	u64("ino", &out.Ino)
	u64("load_epoch", &out.LoadEpoch)
	u32("dev", &out.Dev)
	u32("hook", &out.Hook)
	u32("reason", &out.MapReason)
	u32("exec_class", &out.ExecClass)
	u32("deny", &out.Deny)
	u32("host_pid", &out.PID)
	p, err := ds.GetField("path").String(data)
	errs = append(errs, err)
	if err := errors.Join(errs...); err != nil {
		return RawFullVerdict{}, err
	}
	out.Mode = out.ExecClass
	if p != "" {
		out.Path, out.PathResult = p, int32(len(p)+1)
	}
	return out, nil
}

// subscribeExecMapVerdicts checks the "execmap" schema, then emits each
// event. Like the exec verdicts, decode errors never change enforcement.
func subscribeExecMapVerdicts(ds datasource.DataSource, emit func(RawFullVerdict), onError func(error)) error {
	if ds == nil {
		return fmt.Errorf("missing executable-mapping verdict datasource")
	}
	for name, kind := range execMapFields {
		if field := ds.GetField(name); field == nil || field.Type() != kind {
			return fmt.Errorf("missing or incompatible executable-mapping field %q", name)
		}
	}
	if p := ds.GetField("path"); p == nil || (p.Type() != dsapi.Kind_CString && p.Type() != dsapi.Kind_String) {
		return fmt.Errorf("missing or incompatible executable-mapping path")
	}
	return ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
		raw, err := ReadExecMapVerdict(ds, data)
		if err != nil {
			if onError != nil {
				onError(fmt.Errorf("%w: %w", ErrVerdictDecode, err))
			}
			return nil
		}
		if emit != nil {
			emit(raw)
		}
		return nil
	}, 100)
}
