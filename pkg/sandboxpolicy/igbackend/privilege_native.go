package igbackend

import (
	"context"
	"errors"
	"fmt"
	privpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/policy"
	"strconv"
	"sync"

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
	return &nativePrivilegeEngine{nativeNodeEngine{manager: manager, kube: kube, store: store, image: image}}, nil
}

// nativeNodeEngine starts node-wide gadget instances from an OCI store.
type nativeNodeEngine struct {
	manager *instancemanager.Manager
	kube    operators.DataOperator
	store   oras.ReadOnlyTarget
	image   string
}

type nativePrivilegeEngine struct{ nativeNodeEngine }

// nativeNodeInstance is one running node-wide gadget instance.
type nativeNodeInstance struct {
	manager  *instancemanager.Manager
	id       string
	section  string
	bindings *enforcement.Bindings
	revision uint64
	// faults: the gadget counts tracking faults per slot.
	faults bool
	// strict: a node tracking fault also fails the health of a Strict slot.
	strict bool
	// publish writes one combination's compiled policy (the section's
	// compiled type, one slot) into a slot of the running instance. Set by
	// the engine.
	publish func(slot uint32, compiled any) error
	// tables maps a publication generation to its compiled policy, so a
	// verdict finds its rule names (see table).
	tables sync.Map
}

// table returns the compiled policy of the publication with this generation.
func (i *nativeNodeInstance) table(generation uint64) (any, bool) {
	return i.tables.Load(generation)
}

// Publish writes compiled into slot in place (see enforcement.Publish). The
// table is known before the flip, so the first verdict finds its names.
func (i *nativeNodeInstance) Publish(slot uint32, compiled any) error {
	if i.publish == nil || i.bindings == nil {
		return fmt.Errorf("%s instance does not publish", i.section)
	}
	return i.publish(slot, compiled)
}

// remember keeps the table of a publication; forgetTable drops it after a
// failed publish.
func (i *nativeNodeInstance) remember(generation uint64, compiled any) {
	i.tables.Store(generation, compiled)
}

func (i *nativeNodeInstance) forgetTable(generation uint64) { i.tables.Delete(generation) }

func (i *nativeNodeInstance) Free(slot uint32) error { return i.bindings.Free(slot) }

func (i *nativeNodeInstance) Available(slot uint32) bool {
	return i.bindings != nil && i.bindings.Available(slot)
}

func (i *nativeNodeInstance) Collect() error { return i.bindings.Collect() }

func (i *nativeNodeInstance) PublishedSlots() map[uint32]uint64 { return i.bindings.PublishedSlots() }

func (i *nativeNodeInstance) DropAdopted(keep func(slot uint32, strict bool) bool) (int, error) {
	return i.bindings.DropAdopted(keep)
}

// Heal arms the slot's bound tasks again and restarts its fault count; with
// node faults it does the same for every bound cgroup. No reload.
func (i *nativeNodeInstance) Heal(slot uint32) error {
	if !i.faults {
		return nil
	}
	errs := []error{i.bindings.Heal(slot)}
	if w, err := i.bindings.ArmingWitness(); err == nil && w.NodeFaults > 0 {
		errs = append(errs, i.bindings.HealNode())
	}
	return errors.Join(errs...)
}

func (i *nativeNodeInstance) Ready() error {
	status := i.bindings.Status()
	if !status.Ready || status.Error != nil || status.Revision != i.revision {
		return fmt.Errorf("%s instance not ready: %+v", i.section, status)
	}
	return nil
}

// SlotHealth fails on a fault counted in the slot, and, for a Strict slot, on
// a node fault (ErrNodeFaultsOnly): a child of an unconfirmed task can start
// in any cgroup (common/arming.h). An unreadable counter is a fault too. An
// Audit slot ignores node faults by design: Audit coverage is reported, but a
// lost Audit judgement never blocks and never makes a policy NotReady.
func (i *nativeNodeInstance) SlotHealth(slot uint32) error {
	if !i.faults {
		return nil
	}
	n, err := i.bindings.SlotFaults(slot)
	if err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%d tracking faults in %s slot %d", n, i.section, slot)
	}
	if !i.strict || !i.bindings.Strict(slot) {
		return nil
	}
	w, err := i.bindings.ArmingWitness()
	if err != nil {
		return err
	}
	if w.NodeFaults > 0 {
		return fmt.Errorf("%w: %d affect Strict %s slot %d", ErrNodeFaultsOnly, w.NodeFaults, i.section, slot)
	}
	return nil
}

func (i *nativeNodeInstance) Bind(b enforcement.Binding) error { return i.bindings.Bind(b) }

func (i *nativeNodeInstance) Unbind(identity enforcement.ContainerIdentity) error {
	return i.bindings.Unbind(identity)
}

func (i *nativeNodeInstance) Stop(ctx context.Context) error {
	err := i.manager.StopGadget(ctx, i.id)
	if errors.Is(err, instancemanager.ErrNotFound) {
		return nil
	}
	return err
}

// start runs one instance with the gadget's data operators and options.
func (e *nativeNodeEngine) start(ctx context.Context, id string, params map[string]string, ops []operators.DataOperator, opts ...gadgetcontext.Option) error {
	handler := ocihandler.New()
	handlerParams := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
	if err := handlerParams.Set("allow-enforcement", "true"); err != nil {
		return err
	}
	// Same trust model as NewNative: the archive is administrator-supplied.
	if err := handler.Init(handlerParams); err != nil {
		return err
	}
	desired := &api.GadgetInstance{Id: id, GadgetConfig: &api.GadgetRunRequest{Version: api.VersionGadgetRunProtocol, ImageName: e.image, ParamValues: params}}
	return e.manager.StartGadget(ctx, desired, append([]gadgetcontext.Option{gadgetcontext.WithOrasReadonlyTarget(e.store),
		gadgetcontext.WithAdditionalDataOperators(append([]operators.DataOperator{handler, e.kube}, ops...)...)}, opts...)...)
}

func (e *nativePrivilegeEngine) Start(ctx context.Context, id string, config privruntime.Config) (PrivilegeInstance, error) {
	instance := &nativeNodeInstance{manager: e.manager, id: id, section: "privilege", revision: config.Policy.Generation, faults: true, strict: true}
	instance.remember(config.Policy.Generation, config.Policy)
	instance.publish = func(slot uint32, compiled any) error {
		c, ok := compiled.(privpolicy.Compiled)
		if !ok || c.Slots != 1 {
			return fmt.Errorf("a privilege publication holds one compiled slot")
		}
		p := privruntime.Publications(c)[0]
		p.Slot = slot
		instance.remember(c.Generation, c)
		if err := instance.bindings.Publish(p); err != nil {
			instance.forgetTable(c.Generation)
			return err
		}
		return nil
	}
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
			generation, _ := fields["generation"].Uint64(data)
			rule := ""
			if t, ok := instance.table(generation); ok {
				if names := t.(privpolicy.Compiled).RuleNames; int(ruleID) < len(names) {
					rule = names[ruleID]
				}
			}
			mode, _ := fields["mode"].Uint32(data)
			pid, _ := fields["host_pid"].Uint32(data)
			cgroup, _ := fields["cgroup"].Uint64(data)
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
	err = e.start(ctx, id, map[string]string{"operator.oci.ebpf.host-mntns-id": strconv.FormatUint(runtimeMntns, 10)},
		[]operators.DataOperator{privruntime.New(), events}, privruntime.WithConfig(config))
	if err != nil {
		return nil, err
	}
	return instance, nil
}
