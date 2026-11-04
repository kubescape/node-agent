package igbackend

import (
	"context"
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	fileruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/runtime"
	"oras.land/oras-go/v2"
)

// NewNativeFileEngine uses an already initialized runtime, like
// NewNativeNetworkEngine. Each Start is one node-wide instance. File verdicts
// are logged, like network verdicts.
func NewNativeFileEngine(rt runtime.Runtime, kube operators.DataOperator, store oras.ReadOnlyTarget, image string) (FileEngine, error) {
	if rt == nil || kube == nil || store == nil || image == "" {
		return nil, fmt.Errorf("runtime, Kubernetes operator, OCI store and file image are required")
	}
	manager, err := instancemanager.New(rt)
	if err != nil {
		return nil, err
	}
	return &nativeFileEngine{nativeNodeEngine{manager: manager, kube: kube, store: store, image: image}}, nil
}

type nativeFileEngine struct{ nativeNodeEngine }

func (e *nativeFileEngine) Start(ctx context.Context, id string, config FileConfig) (NodeInstance, error) {
	// faults: the gadget arms tasks like privilege and counts tracking faults
	// per slot. Set it to false if the runtime configures no FaultMap.
	instance := &nativeNodeInstance{manager: e.manager, id: id, section: "file", revision: config.Policy.Generation, faults: true}
	names, origins := config.Policy.RuleNames, config.Policy.Origins
	name := func(list []string, id uint32) string {
		if int(id) < len(list) {
			return list[id]
		}
		return ""
	}
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
		fields := map[string]datasource.FieldAccessor{}
		for _, name := range []string{"generation", "cgroup", "mode", "host_pid", "rule_id", "origin_id", "is_default", "slot", "comm", "hook"} {
			if fields[name] = ds.GetField(name); fields[name] == nil {
				return fmt.Errorf("missing verdict field %q", name)
			}
		}
		// Optional: the access kind and the path the verdict judged.
		access, path := ds.GetField("access"), ds.GetField("path")
		text := func(f datasource.FieldAccessor, data datasource.Data) string {
			if f == nil {
				return ""
			}
			s, _ := f.String(data)
			return s
		}
		return ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			ruleID, _ := fields["rule_id"].Uint32(data)
			originID, _ := fields["origin_id"].Uint32(data)
			mode, _ := fields["mode"].Uint32(data)
			isDefault, _ := fields["is_default"].Uint32(data)
			slot, _ := fields["slot"].Uint32(data)
			pid, _ := fields["host_pid"].Uint32(data)
			cgroup, _ := fields["cgroup"].Uint64(data)
			generation, _ := fields["generation"].Uint64(data)
			comm, _ := fields["comm"].String(data)
			hook, _ := fields["hook"].String(data)
			// mode 1 = audit (wouldDeny, the call was allowed), 2 = enforce.
			logger.L().Info("sandbox file verdict",
				helpers.String("rule", name(names, ruleID)), helpers.String("origin", name(origins, originID)),
				helpers.Int("mode", int(mode)), helpers.String("wouldDeny", fmt.Sprint(mode == 1)), helpers.Int("default", int(isDefault)),
				helpers.Int("slot", int(slot)), helpers.Int("pid", int(pid)), helpers.String("cgroup", fmt.Sprint(cgroup)),
				helpers.String("generation", fmt.Sprint(generation)), helpers.String("comm", comm), helpers.String("hook", hook),
				helpers.String("access", text(access, data)), helpers.String("path", text(path, data)))
			return nil // Reporting never changes enforcement.
		}, 100)
	}))
	runtimeConfig := fileruntime.Config{Policy: config.Policy, InitialBindings: config.InitialBindings}
	if err := e.start(ctx, id, nil, []operators.DataOperator{fileruntime.New(), events}, fileruntime.WithConfig(runtimeConfig)); err != nil {
		return nil, err
	}
	return instance, nil
}
