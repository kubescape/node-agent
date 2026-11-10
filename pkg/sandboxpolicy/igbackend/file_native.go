package igbackend

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/rootbarrier"
	filepolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/policy"
	fileruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"oras.land/oras-go/v2"
)

// NewNativeFileEngine uses an already initialized runtime, like
// NewNativeNetworkEngine. Each Start is one node-wide instance. File verdicts
// are logged and reported, like network verdicts.
func NewNativeFileEngine(rt runtime.Runtime, kube operators.DataOperator, store oras.ReadOnlyTarget, image string, report SectionReporter) (FileEngine, error) {
	if rt == nil || kube == nil || store == nil || image == "" {
		return nil, fmt.Errorf("runtime, Kubernetes operator, OCI store and file image are required")
	}
	manager, err := instancemanager.New(rt)
	if err != nil {
		return nil, err
	}
	return &nativeFileEngine{nativeNodeEngine{manager: manager, kube: kube, store: store, image: image, report: report}}, nil
}

type nativeFileEngine struct{ nativeNodeEngine }

func (e *nativeFileEngine) Start(ctx context.Context, id string, config FileConfig) (NodeInstance, error) {
	// faults: the gadget arms tasks like privilege and counts tracking faults
	// per slot. Set it to false if the runtime configures no FaultMap.
	// strict: a node tracking fault (a lost mark of a CLONE_INTO_CGROUP fork
	// anywhere) also fails the health of a Strict file slot.
	instance := &nativeNodeInstance{manager: e.manager, id: id, section: "file", revision: config.Policy.Generation, faults: true,
		strict: func(slot uint32) bool { return fileruntime.Enforcing(config.Policy, slot) }}
	names, origins := config.Policy.RuleNames, config.Policy.Origins
	events := simple.New("sandbox-file-verdict", simple.WithPriority(100), simple.OnInit(func(gc operators.GadgetContext) error {
		ds := gc.GetDataSources()["verdict"]
		if ds == nil {
			return fmt.Errorf("missing file verdict datasource")
		}
		var err error
		instance.bindings, err = fileruntime.GetBindings(gc)
		if err != nil {
			return err
		}
		// An enforcing slot depends on the root barrier: without a
		// successful attestation its bindings are refused and reported.
		// Audit-only slots never depend on it.
		barrier, err := fileruntime.GetBarrier(gc)
		if err != nil {
			return err
		}
		instance.slotGate = func(slot uint32) error {
			if !fileruntime.Enforcing(config.Policy, slot) {
				return nil
			}
			return barrier.Err()
		}
		common, err := newVerdictFields(ds)
		if err != nil {
			return err
		}
		// Optional: the access kind, the path the verdict judged and whether
		// it is in the image.
		access, path, fromImage := ds.GetField("access"), ds.GetField("path"), ds.GetField("from_image")
		accessRaw := ds.GetField("access_raw")
		text := func(f datasource.FieldAccessor, data datasource.Data) string {
			if f == nil {
				return ""
			}
			s, _ := f.String(data)
			return s
		}
		return ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			v, hook := common.read(data, sandboxpolicy.SectionFile, names, origins)
			t := sandboxpolicy.FileTarget{Hook: enumName(hook, "FILE_HOOK_"), Access: enumName(text(access, data), "FILE_ACCESS_"), Path: text(path, data)}
			if t.Hook == hookFault {
				// An operational fault: access_raw is the fault kind.
				kind, ok := rawKind(accessRaw, data)
				t.Access = asFault(&v, kind, ok)
			}
			if t.Hook == fileHookRootBarrier {
				// A barrier denial: no rule decided; access_raw is the
				// barrier operation.
				v.Rule, v.Reason = sandboxpolicy.SectionRuleRootBarrier, "root_barrier"
				t.Access = ""
				if accessRaw != nil {
					if op, err := accessRaw.Uint32(data); err == nil {
						t.Access = rootbarrier.Op(op).String()
					}
				}
			}
			if fromImage != nil {
				image, _ := fromImage.Uint32(data)
				t.FromImage = image != 0
			}
			if origins, ok := defaultOrigins(config.Policy, v, t.Access); ok {
				v.Origins = origins
			}
			logger.L().Info("sandbox file verdict",
				helpers.String("rule", v.Rule), helpers.String("origin", strings.Join(v.Origins, ",")),
				helpers.String("mode", string(v.Mode)), helpers.String("wouldDeny", fmt.Sprint(v.WouldDeny)), helpers.String("reason", v.Reason),
				helpers.Int("slot", int(v.Slot)), helpers.Int("pid", int(v.PID)), helpers.String("cgroup", fmt.Sprint(v.CgroupID)),
				helpers.String("generation", fmt.Sprint(v.Generation)), helpers.String("comm", v.Comm), helpers.String("hook", t.Hook),
				helpers.String("access", t.Access), helpers.String("path", t.Path))
			if e.report != nil {
				e.report(sandboxpolicy.NewFileVerdictEvent(v, sandboxpolicy.Binding{}, t))
			}
			return nil // Reporting never changes enforcement.
		}, 100)
	}))
	// The gadget arms tasks like privilege: give it the runtime's mount
	// namespace, or it falls back to the init task's and judges runc init
	// wherever the runtime runs in another one (kubectl exec and exec probes
	// then fail on runc's write to /proc/self/oom_score_adj).
	runtimeMntns, err := enforcement.RuntimeMountNamespace()
	if err != nil {
		return nil, fmt.Errorf("runtime mount namespace: %w", err)
	}
	// Before Linux 6.9 an allow from inode_setxattr returns 1 where the
	// verifier accepts it, or the kernel skips its capability check of
	// security.* names (see runtime.SetxattrAllowOne).
	params, err := fileruntime.SetxattrParams()
	if err != nil {
		return nil, fmt.Errorf("setxattr hook semantics: %w", err)
	}
	params["operator.oci.ebpf.host-mntns-id"] = strconv.FormatUint(runtimeMntns, 10)
	runtimeConfig := fileruntime.Config{Policy: config.Policy, InitialBindings: config.InitialBindings}
	if err := e.start(ctx, id, params,
		[]operators.DataOperator{fileruntime.New(), events}, fileruntime.WithConfig(runtimeConfig)); err != nil {
		return nil, err
	}
	return instance, nil
}

// defaultOrigins returns every origin of a default verdict: the kernel event
// carries one origin id, the compiled slot keeps all of them per access kind
// (an explicit "" included, a missing origin adding nothing). ok is false
// for a rule verdict and for an access kind with no default table.
func defaultOrigins(c filepolicy.Compiled, v sandboxpolicy.SectionVerdict, access string) ([]string, bool) {
	if v.Reason != "section_default" || int(v.Slot) >= len(c.DefaultOrigins) {
		return nil, false
	}
	for a, kind := range filepolicy.AccessKinds {
		if kind == access && a < filepolicy.KernelAccessKinds {
			return append([]string{}, c.DefaultOrigins[v.Slot][a]...), true
		}
	}
	return nil, false
}

// fileHookRootBarrier is enumName("FILE_HOOK_ROOT_BARRIER", "FILE_HOOK_").
const fileHookRootBarrier = "root_barrier"
