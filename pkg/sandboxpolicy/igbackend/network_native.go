package igbackend

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/protocols"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	netruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"oras.land/oras-go/v2"
)

// NewNativeNetworkEngine uses an already initialized runtime, like
// NewNativePrivilegeEngine. Each Start is one node-wide instance. Network
// verdicts are logged and reported, like privilege verdicts.
func NewNativeNetworkEngine(rt runtime.Runtime, kube operators.DataOperator, store oras.ReadOnlyTarget, image string, report SectionReporter) (NetworkEngine, error) {
	if rt == nil || kube == nil || store == nil || image == "" {
		return nil, fmt.Errorf("runtime, Kubernetes operator, OCI store and network image are required")
	}
	manager, err := instancemanager.New(rt)
	if err != nil {
		return nil, err
	}
	return &nativeNetworkEngine{nativeNodeEngine{manager: manager, kube: kube, store: store, image: image, report: report}}, nil
}

type nativeNetworkEngine struct{ nativeNodeEngine }

func (e *nativeNetworkEngine) Start(ctx context.Context, id string, config netruntime.Config) (NodeInstance, error) {
	instance := &nativeNodeInstance{manager: e.manager, id: id, section: "network", revision: config.Policy.Generation, faults: true}
	names, origins := config.Policy.RuleNames, config.Policy.Origins
	events := simple.New("sandbox-network-verdict", simple.WithPriority(100), simple.OnInit(func(gc operators.GadgetContext) error {
		ds := gc.GetDataSources()["verdict"]
		if ds == nil {
			return fmt.Errorf("missing network verdict datasource")
		}
		var err error
		instance.bindings, err = netruntime.GetBindings(gc)
		if err != nil {
			return err
		}
		common, err := newVerdictFields(ds)
		if err != nil {
			return err
		}
		addr, port, version := ds.GetField("dst.addr_raw"), ds.GetField("dst.port"), ds.GetField("dst.version")
		proto, protoRaw := ds.GetField("dst.proto"), ds.GetField("dst.proto_raw")
		return ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			v, hook := common.read(data, sandboxpolicy.SectionNetwork, names, origins)
			t := destination(data, addr, port, version, proto, protoRaw)
			t.Hook = enumName(hook, "NET_HOOK_")
			if t.Hook == hookFault {
				t.Fault = asFault(&v, 0, true) // network faults are structural
			}
			if origins, ok := slotDefaultOrigins(config.Policy.DefaultOrigins, v); ok {
				v.Origins = origins
			}
			logger.L().Info("sandbox network verdict",
				helpers.String("rule", v.Rule), helpers.String("origin", strings.Join(v.Origins, ",")),
				helpers.String("mode", string(v.Mode)), helpers.String("wouldDeny", fmt.Sprint(v.WouldDeny)), helpers.String("reason", v.Reason),
				helpers.Int("slot", int(v.Slot)), helpers.Int("pid", int(v.PID)), helpers.String("cgroup", fmt.Sprint(v.CgroupID)),
				helpers.String("generation", fmt.Sprint(v.Generation)), helpers.String("comm", v.Comm), helpers.String("hook", t.Hook),
				helpers.String("dst", t.Addr), helpers.Int("port", int(t.Port)), helpers.String("proto", t.Proto))
			if e.report != nil {
				e.report(sandboxpolicy.NewNetworkVerdictEvent(v, sandboxpolicy.Binding{}, t))
			}
			return nil // Reporting never changes enforcement.
		}, 100)
	}))
	if err := e.start(ctx, id, nil, []operators.DataOperator{netruntime.New(), events}, netruntime.WithConfig(config)); err != nil {
		return nil, err
	}
	return instance, nil
}

// destination decodes the destination of a verdict. A field the gadget does
// not have stays empty; Addr is "" when the address is unknown.
func destination(data datasource.Data, addr, port, version, proto, protoRaw datasource.FieldAccessor) sandboxpolicy.NetworkTarget {
	var t sandboxpolicy.NetworkTarget
	if port != nil {
		t.Port, _ = port.Uint16(data)
	}
	if proto != nil {
		t.Proto, _ = proto.String(data)
	}
	// Without IG's formatter the name field is empty: name the number. An
	// unknown number stays empty.
	if t.Proto == "" && protoRaw != nil {
		if n, err := protoRaw.Uint16(data); err == nil {
			t.Proto, _ = protocols.GetProtocolNameByNumber(int(n))
		}
	}
	if addr == nil || version == nil {
		return t
	}
	raw := addr.Get(data)
	t.Version, _ = version.Uint8(data)
	switch {
	case t.Version == 4 && len(raw) >= 4:
		t.Addr = netip.AddrFrom4([4]byte(raw[:4])).String()
	case t.Version == 6 && len(raw) >= 16:
		t.Addr = netip.AddrFrom16([16]byte(raw[:16])).String()
	}
	return t
}
