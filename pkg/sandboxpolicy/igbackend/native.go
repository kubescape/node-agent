package igbackend

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	execruntime "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"oras.land/oras-go/v2"
)

// NewNative uses an already initialized runtime. Its caller retains ownership of
// that runtime and must call Backend.Close before runtime.Close.
func NewNative(rt runtime.Runtime, kube operators.DataOperator, store oras.ReadOnlyTarget, image string, receiver sandboxpolicy.VerdictReceiver, onError func(error)) (*Backend, error) {
	if rt == nil || kube == nil || store == nil || image == "" {
		return nil, fmt.Errorf("runtime, Kubernetes operator, OCI store and enforcement image are required")
	}
	manager, err := instancemanager.New(rt)
	if err != nil {
		return nil, err
	}
	return New(&nativeEngine{manager: manager, kube: kube, store: store, image: image, onError: onError}, LinuxValidator{ProcRoot: host.HostProcFs, CgroupRoot: filepath.Join(host.HostRoot, "sys/fs/cgroup")}, receiver, onError)
}

type nativeEngine struct {
	manager *instancemanager.Manager
	kube    operators.DataOperator
	store   oras.ReadOnlyTarget
	image   string
	onError func(error)
}
type nativeInstance struct {
	manager  *instancemanager.Manager
	id       string
	bindings *execruntime.Bindings
	revision uint64
}

func (i *nativeInstance) Ready() error {
	status := i.bindings.Status()
	if !status.Ready || status.Error != nil || status.Bound != 1 || status.RestrictedBindings != 0 || status.Revision != i.revision {
		return fmt.Errorf("enforcement instance not ready: %+v", status)
	}
	return nil
}
func (i *nativeInstance) Unbind(ctx context.Context, identity execruntime.ContainerIdentity) error {
	if !i.bindings.Status().Ready {
		return i.Stop(ctx)
	}
	return i.bindings.Unbind(identity)
}
func (i *nativeInstance) Stop(ctx context.Context) error {
	err := i.manager.StopGadget(ctx, i.id)
	if errors.Is(err, instancemanager.ErrNotFound) {
		return nil
	}
	return err
}
func (e *nativeEngine) Start(ctx context.Context, id string, config execruntime.Config, emit func(RawVerdict)) (Instance, error) {
	handler := ocihandler.New()
	params := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
	if err := params.Set("allow-enforcement", "true"); err != nil {
		return nil, err
	}
	// Keep the upstream verification defaults. NOTE: IG treats an explicit OCI
	// target as pretrusted and does not verify its signatures here. The caller
	// must supply an administrator-trusted archive (privileged executable code),
	// never a policy-provided artifact. This flag alone authenticates no archive.
	if err := handler.Init(params); err != nil {
		return nil, err
	}
	instance := &nativeInstance{manager: e.manager, id: id, revision: config.Entries[0].Generation}
	events := simple.New("sandbox-exec-verdict", simple.WithPriority(100), simple.OnInit(func(gc operators.GadgetContext) error {
		ds := gc.GetDataSources()["verdict"]
		if ds == nil {
			return fmt.Errorf("missing enforcement verdict datasource")
		}
		for _, name := range []string{"generation", "cgroup", "deny", "mode", "path_result", "host_pid", "path"} {
			if ds.GetField(name) == nil {
				return fmt.Errorf("missing verdict field %q", name)
			}
		}
		var err error
		instance.bindings, err = execruntime.GetBindings(gc)
		if err != nil {
			return err
		}
		return ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			raw, err := readVerdict(ds, data)
			if err != nil {
				if e.onError != nil {
					e.onError(err)
				}
				return nil
			}
			emit(raw)
			return nil // Exporter failures never modify enforcement lifecycle.
		}, 100)
	}))
	desired := &api.GadgetInstance{Id: id, GadgetConfig: &api.GadgetRunRequest{Version: api.VersionGadgetRunProtocol, ImageName: e.image}}
	err := e.manager.StartGadget(ctx, desired,
		gadgetcontext.WithOrasReadonlyTarget(e.store),
		gadgetcontext.WithAdditionalDataOperators(handler, e.kube, execruntime.New(), events),
		execruntime.WithConfig(config))
	if err != nil {
		return nil, err
	}
	return instance, nil
}
