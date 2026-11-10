package igbackend

import (
	"context"
	"errors"
	"fmt"
	privpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/policy"
	"strconv"
	"strings"
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
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"oras.land/oras-go/v2"
)

// NewNativePrivilegeEngine uses an already initialized runtime, like NewNative.
// Each Start is one node-wide instance.
// Privilege verdicts are logged and passed to report (nil: logged only).
func NewNativePrivilegeEngine(rt runtime.Runtime, kube operators.DataOperator, store oras.ReadOnlyTarget, image string, report SectionReporter) (PrivilegeEngine, error) {
	if rt == nil || kube == nil || store == nil || image == "" {
		return nil, fmt.Errorf("runtime, Kubernetes operator, OCI store and privilege image are required")
	}
	manager, err := instancemanager.New(rt)
	if err != nil {
		return nil, err
	}
	return &nativePrivilegeEngine{nativeNodeEngine{manager: manager, kube: kube, store: store, image: image, report: report}}, nil
}

// nativeNodeEngine starts node-wide gadget instances from an OCI store.
type nativeNodeEngine struct {
	manager *instancemanager.Manager
	kube    operators.DataOperator
	store   oras.ReadOnlyTarget
	image   string
	report  SectionReporter
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
	// slotGate, when set, refuses a slot that cannot protect now (for file:
	// an enforcing slot without an attested root barrier). Bind refuses the
	// slot and SlotHealth reports it.
	slotGate func(slot uint32) error
	// strict reports a Strict slot (nil: none): a node tracking fault also
	// fails its health.
	strict func(slot uint32) bool
	// publish writes one combination's compiled policy (the section's
	// compiled type, one slot) into a slot of the running instance. Set by
	// an engine that publishes in place.
	publish func(slot uint32, compiled any) error
	// tables maps a generation (an instance start or a publication) to its
	// id tables, so a verdict finds its rule names and default origins.
	tables sync.Map
	// slotGens maps a published slot to its publication's generation, so
	// Free drops its tables; onForget drops an engine's own table.
	slotMu   sync.Mutex
	slotGens map[uint32]uint64
	onForget func(generation uint64)
}

// published records the generation of a slot's publication (engines call it
// after a successful publish).
func (i *nativeNodeInstance) published(slot uint32, generation uint64) {
	i.slotMu.Lock()
	defer i.slotMu.Unlock()
	if i.slotGens == nil {
		i.slotGens = map[uint32]uint64{}
	}
	i.slotGens[slot] = generation
}

// slotTable holds the id tables of one compiled policy: rule names, origins
// and, per binding slot, the default origins.
type slotTable struct {
	names, origins []string
	defaultOrigins map[uint32][]string
}

// remember keeps the tables of the compiled policy with this generation. base
// is the binding slot of its slot 0 (0 for an instance start, the slot of a
// publication).
func (i *nativeNodeInstance) remember(generation uint64, names, origins []string, defaults [][]string, base uint32) {
	t := slotTable{names: names, origins: origins, defaultOrigins: map[uint32][]string{}}
	for k, d := range defaults {
		t.defaultOrigins[base+uint32(k)] = d
	}
	i.tables.Store(generation, t)
}

func (i *nativeNodeInstance) forgetTable(generation uint64) { i.tables.Delete(generation) }

// ids returns the rule names and origins of a generation (nil when unknown).
func (i *nativeNodeInstance) ids(generation uint64) ([]string, []string) {
	if t, ok := i.tables.Load(generation); ok {
		return t.(slotTable).names, t.(slotTable).origins
	}
	return nil, nil
}

// defaultOrigins returns the default origins of a default verdict (see
// slotDefaultOrigins).
func (i *nativeNodeInstance) defaultOrigins(v sandboxpolicy.SectionVerdict) ([]string, bool) {
	t, ok := i.tables.Load(v.Generation)
	if !ok || v.Reason != "section_default" {
		return nil, false
	}
	d, ok := t.(slotTable).defaultOrigins[v.Slot]
	return append([]string{}, d...), ok
}

// Publish writes compiled into slot in place (see enforcement.Publish).
func (i *nativeNodeInstance) Publish(slot uint32, compiled any) error {
	if i.publish == nil || i.bindings == nil {
		return fmt.Errorf("%s instance does not publish", i.section)
	}
	return i.publish(slot, compiled)
}

// Free retires an unbound slot and drops the tables of its publication (an
// unbound slot reports no more verdicts).
func (i *nativeNodeInstance) Free(slot uint32) error {
	if err := i.bindings.Free(slot); err != nil {
		return err
	}
	i.slotMu.Lock()
	generation, ok := i.slotGens[slot]
	delete(i.slotGens, slot)
	i.slotMu.Unlock()
	if ok && generation != i.revision {
		i.forgetTable(generation)
		if i.onForget != nil {
			i.onForget(generation)
		}
	}
	return nil
}

func (i *nativeNodeInstance) Available(slot uint32) bool {
	return i.bindings != nil && i.bindings.Available(slot)
}

func (i *nativeNodeInstance) Collect() error { return i.bindings.Collect() }

func (i *nativeNodeInstance) PublishedSlots() map[uint32]uint64 { return i.bindings.PublishedSlots() }

func (i *nativeNodeInstance) DropAdopted(keep func(slot uint32, strict bool) bool) (int, error) {
	return i.bindings.DropAdopted(keep)
}

func (i *nativeNodeInstance) ResetFaults() error { return i.bindings.ResetFaults() }

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

// VerdictCounters reads the gadget's verdict counters (common/verdict.h).
func (i *nativeNodeInstance) VerdictCounters() (enforcement.VerdictCounters, error) {
	if i.bindings == nil {
		return enforcement.VerdictCounters{}, fmt.Errorf("%s instance has no bindings controller", i.section)
	}
	return i.bindings.VerdictCounters()
}

// SlotHealth fails on a fault counted in the slot, and, for a Strict slot, on
// a node fault (ErrNodeFaultsOnly): a child of an unconfirmed task can start
// in any cgroup (common/arming.h). An unreadable counter is a fault too. An
// Audit slot ignores node faults by design: Audit coverage is reported, but a
// lost Audit judgement never blocks and never makes a policy NotReady.
func (i *nativeNodeInstance) SlotHealth(slot uint32) error {
	if i.slotGate != nil {
		if err := i.slotGate(slot); err != nil {
			return err
		}
	}
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
	if i.strict == nil || !i.strict(slot) {
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

func (i *nativeNodeInstance) Bind(b enforcement.Binding) error {
	if i.slotGate != nil {
		if err := i.slotGate(b.Slot); err != nil {
			return fmt.Errorf("%s slot %d refused: %w", i.section, b.Slot, err)
		}
	}
	return i.bindings.Bind(b)
}

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
	instance := &nativeNodeInstance{manager: e.manager, id: id, section: "privilege", revision: config.Policy.Generation, faults: true}
	instance.strict = func(slot uint32) bool { return instance.bindings.Strict(slot) }
	instance.remember(config.Policy.Generation, config.Policy.RuleNames, config.Policy.Origins, config.Policy.DefaultOrigins, 0)
	instance.publish = func(slot uint32, compiled any) error {
		c, ok := compiled.(privpolicy.Compiled)
		if !ok || c.Slots != 1 {
			return fmt.Errorf("a privilege publication holds one compiled slot")
		}
		p := privruntime.Publications(c)[0]
		p.Slot = slot
		instance.remember(c.Generation, c.RuleNames, c.Origins, c.DefaultOrigins, slot)
		if err := instance.bindings.Publish(p); err != nil {
			instance.forgetTable(c.Generation)
			return err
		}
		instance.published(slot, c.Generation)
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
		common, err := newVerdictFields(ds)
		if err != nil {
			return err
		}
		fields := map[string]datasource.FieldAccessor{}
		for _, name := range []string{"syscall", "capability", "fstype"} {
			if fields[name] = ds.GetField(name); fields[name] == nil {
				return fmt.Errorf("missing verdict field %q", name)
			}
		}
		flags, faultRaw := ds.GetField("flags"), ds.GetField("fault_raw") // optional
		return ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			v, hook := common.read(data, sandboxpolicy.SectionPrivilege, instance.ids)
			t := sandboxpolicy.PrivilegeTarget{Hook: enumName(hook, "PRIV_HOOK_")}
			var err error
			if t.Capability, err = fields["capability"].Int32(data); err != nil {
				t.Capability = -1 // unknown, not CAP_CHOWN
			}
			syscall, _ := fields["syscall"].String(data)
			t.Syscall = enumName(syscall, "PRIV_SC_")
			t.FsType, _ = fields["fstype"].String(data)
			if flags != nil {
				t.Flags, _ = flags.Uint64(data)
			}
			if t.Hook == hookFault {
				kind, ok := rawKind(faultRaw, data)
				t.Fault = asFault(&v, kind, ok)
			}
			if origins, ok := instance.defaultOrigins(v); ok {
				v.Origins = origins
			}
			logger.L().Info("sandbox privilege verdict",
				helpers.String("rule", v.Rule), helpers.String("origin", strings.Join(v.Origins, ",")),
				helpers.String("mode", string(v.Mode)), helpers.String("wouldDeny", fmt.Sprint(v.WouldDeny)), helpers.String("reason", v.Reason),
				helpers.Int("slot", int(v.Slot)), helpers.Int("pid", int(v.PID)),
				helpers.String("cgroup", fmt.Sprint(v.CgroupID)), helpers.String("generation", fmt.Sprint(v.Generation)),
				helpers.String("comm", v.Comm), helpers.String("hook", t.Hook), helpers.String("syscall", t.Syscall),
				helpers.Int("capability", int(t.Capability)), helpers.String("fstype", t.FsType))
			if e.report != nil {
				e.report(sandboxpolicy.NewPrivilegeVerdictEvent(v, sandboxpolicy.Binding{}, t))
			}
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
