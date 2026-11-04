package igbackend

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	netruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/runtime"
	"oras.land/oras-go/v2"
)

// NewNativeNetworkEngine uses an already initialized runtime, like
// NewNativePrivilegeEngine. Each Start is one node-wide instance. Network
// verdicts are logged, like privilege verdicts.
func NewNativeNetworkEngine(rt runtime.Runtime, kube operators.DataOperator, store oras.ReadOnlyTarget, image string, tier NetworkTier) (NetworkEngine, error) {
	if rt == nil || kube == nil || store == nil || image == "" {
		return nil, fmt.Errorf("runtime, Kubernetes operator, OCI store and network image are required")
	}
	if tier != NetworkTierLSM {
		// The cgroup tier selects its programs here when the gadget has them.
		return nil, fmt.Errorf("network tier %q is not supported by this build", tier)
	}
	manager, err := instancemanager.New(rt)
	if err != nil {
		return nil, err
	}
	return &nativeNetworkEngine{nativeNodeEngine{manager: manager, kube: kube, store: store, image: image}}, nil
}

type nativeNetworkEngine struct{ nativeNodeEngine }

func (e *nativeNetworkEngine) Start(ctx context.Context, id string, config netruntime.Config) (NodeInstance, error) {
	instance := &nativeNodeInstance{manager: e.manager, id: id, section: "network", revision: config.Policy.Generation}
	names, origins := config.Policy.RuleNames, config.Policy.Origins
	name := func(list []string, id uint32) string {
		if int(id) < len(list) {
			return list[id]
		}
		return ""
	}
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
		fields := map[string]datasource.FieldAccessor{}
		for _, name := range []string{"generation", "cgroup", "mode", "host_pid", "rule_id", "origin_id", "is_default", "slot", "comm", "hook"} {
			if fields[name] = ds.GetField(name); fields[name] == nil {
				return fmt.Errorf("missing verdict field %q", name)
			}
		}
		addr, port, version := ds.GetField("dst.addr_raw"), ds.GetField("dst.port"), ds.GetField("dst.version")
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
			logger.L().Info("sandbox network verdict",
				helpers.String("rule", name(names, ruleID)), helpers.String("origin", name(origins, originID)),
				helpers.Int("mode", int(mode)), helpers.String("wouldDeny", fmt.Sprint(mode == 1)), helpers.Int("default", int(isDefault)),
				helpers.Int("slot", int(slot)), helpers.Int("pid", int(pid)), helpers.String("cgroup", fmt.Sprint(cgroup)),
				helpers.String("generation", fmt.Sprint(generation)), helpers.String("comm", comm), helpers.String("hook", hook),
				helpers.String("dst", endpoint(data, addr, port, version)))
			return nil // Reporting never changes enforcement.
		}, 100)
	}))
	if err := e.start(ctx, id, nil, []operators.DataOperator{netruntime.New(), events}, netruntime.WithConfig(config)); err != nil {
		return nil, err
	}
	return instance, nil
}

// endpoint formats the destination of a verdict, or "" when the fields are absent.
func endpoint(data datasource.Data, addr, port, version datasource.FieldAccessor) string {
	if addr == nil || port == nil || version == nil {
		return ""
	}
	raw := addr.Get(data)
	v, _ := version.Uint8(data)
	p, _ := port.Uint16(data)
	var a netip.Addr
	switch {
	case v == 4 && len(raw) >= 4:
		a = netip.AddrFrom4([4]byte(raw[:4]))
	case v == 6 && len(raw) >= 16:
		a = netip.AddrFrom16([16]byte(raw[:16]))
	default:
		return ""
	}
	return netip.AddrPortFrom(a, p).String()
}
