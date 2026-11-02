package igbackend

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	privruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/runtime"
	"oras.land/oras-go/v2"
)

// NewNativePrivilegeEngine uses an already initialized runtime, like NewNative.
// Each Start is one node-wide instance.
// Privilege verdicts are logged; exporting them as events is not wired yet.
func NewNativePrivilegeEngine(rt runtime.Runtime, kube operators.DataOperator, store oras.ReadOnlyTarget, image string) (PrivilegeEngine, error) {
	if rt == nil || kube == nil || store == nil || image == "" {
		return nil, fmt.Errorf("runtime, Kubernetes operator, OCI store and privilege image are required")
	}
	manager, err := instancemanager.New(rt)
	if err != nil {
		return nil, err
	}
	return &nativePrivilegeEngine{manager: manager, kube: kube, store: store, image: image}, nil
}

type nativePrivilegeEngine struct {
	manager *instancemanager.Manager
	kube    operators.DataOperator
	store   oras.ReadOnlyTarget
	image   string
}

type nativePrivilegeInstance struct {
	manager  *instancemanager.Manager
	id       string
	bindings *enforcement.Bindings
	revision uint64
}

func (i *nativePrivilegeInstance) Ready() error {
	status := i.bindings.Status()
	if !status.Ready || status.Error != nil || status.Revision != i.revision {
		return fmt.Errorf("privilege instance not ready: %+v", status)
	}
	return nil
}

func (i *nativePrivilegeInstance) Bind(b enforcement.Binding) error { return i.bindings.Bind(b) }

func (i *nativePrivilegeInstance) Unbind(identity enforcement.ContainerIdentity) error {
	return i.bindings.Unbind(identity)
}

func (i *nativePrivilegeInstance) Stop(ctx context.Context) error {
	err := i.manager.StopGadget(ctx, i.id)
	if errors.Is(err, instancemanager.ErrNotFound) {
		return nil
	}
	return err
}

func (e *nativePrivilegeEngine) Start(ctx context.Context, id string, config privruntime.Config) (PrivilegeInstance, error) {
	handler := ocihandler.New()
	params := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
	if err := params.Set("allow-enforcement", "true"); err != nil {
		return nil, err
	}
	// Same trust model as NewNative: the archive is administrator-supplied.
	if err := handler.Init(params); err != nil {
		return nil, err
	}
	instance := &nativePrivilegeInstance{manager: e.manager, id: id, revision: config.Policy.Generation}
	names := config.Policy.RuleNames
	events := simple.New("sandbox-privilege-verdict", simple.WithPriority(100), simple.OnInit(func(gc operators.GadgetContext) error {
		ds := gc.GetDataSources()["verdict"]
		if ds == nil {
			return fmt.Errorf("missing privilege verdict datasource")
		}
		var err error
		instance.bindings, err = privruntime.GetBindings(gc)
		if err != nil {
			return err
		}
		fields := map[string]datasource.FieldAccessor{}
		for _, name := range []string{"generation", "cgroup", "deny", "mode", "host_pid", "rule_id", "comm", "hook", "syscall", "capability", "fstype"} {
			if fields[name] = ds.GetField(name); fields[name] == nil {
				return fmt.Errorf("missing verdict field %q", name)
			}
		}
		return ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			ruleID, _ := fields["rule_id"].Uint32(data)
			rule := ""
			if int(ruleID) < len(names) {
				rule = names[ruleID]
			}
			mode, _ := fields["mode"].Uint32(data)
			pid, _ := fields["host_pid"].Uint32(data)
			cgroup, _ := fields["cgroup"].Uint64(data)
			generation, _ := fields["generation"].Uint64(data)
			capability, _ := fields["capability"].Int32(data)
			comm, _ := fields["comm"].String(data)
			hook, _ := fields["hook"].String(data)
			syscall, _ := fields["syscall"].String(data)
			fstype, _ := fields["fstype"].String(data)
			logger.L().Info("sandbox privilege verdict",
				helpers.String("rule", rule), helpers.Int("mode", int(mode)), helpers.Int("pid", int(pid)),
				helpers.String("cgroup", fmt.Sprint(cgroup)), helpers.String("generation", fmt.Sprint(generation)),
				helpers.String("comm", comm), helpers.String("hook", hook), helpers.String("syscall", syscall),
				helpers.Int("capability", int(capability)), helpers.String("fstype", fstype))
			return nil // Reporting never changes enforcement.
		}, 100)
	}))
	runtimeMntns, err := enforcement.RuntimeMountNamespace()
	if err != nil {
		return nil, fmt.Errorf("runtime mount namespace: %w", err)
	}
	desired := &api.GadgetInstance{Id: id, GadgetConfig: &api.GadgetRunRequest{Version: api.VersionGadgetRunProtocol, ImageName: e.image,
		ParamValues: map[string]string{"operator.oci.ebpf.host-mntns-id": strconv.FormatUint(runtimeMntns, 10)}}}
	err = e.manager.StartGadget(ctx, desired,
		gadgetcontext.WithOrasReadonlyTarget(e.store),
		gadgetcontext.WithAdditionalDataOperators(handler, e.kube, privruntime.New(), events),
		privruntime.WithConfig(config))
	if err != nil {
		return nil, err
	}
	return instance, nil
}
