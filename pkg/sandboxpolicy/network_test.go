package sandboxpolicy

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	netpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/policy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func netRule(name string, action api.Action, target api.NetworkTarget) api.NetworkRule {
	return api.NetworkRule{Rule: api.Rule{Name: name, Action: action}, Target: target}
}

func netSpec(egress api.Action, rules ...api.NetworkRule) api.PolicySpec {
	return api.PolicySpec{Containers: []string{"*"}, Mode: api.ModeEnforce,
		Network: &api.NetworkSection{Default: api.NetworkDefault{Egress: egress, Listen: api.ActionAllow}, Rules: rules}}
}

func translate(t *testing.T, spec api.PolicySpec, x NetworkExtras, classes DestClasses) *NetworkPlan {
	t.Helper()
	plan, err := TranslateNetwork(spec, x, classes)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func ruleByName(plan *NetworkPlan, name string) *netpolicy.Rule {
	for i, r := range plan.Egress.Policy.Egress.Rules {
		if r.Name == name {
			return &plan.Egress.Policy.Egress.Rules[i]
		}
	}
	return nil
}

func degraded(plan *NetworkPlan, rule string) *api.DegradedRule {
	for i, d := range plan.Report.Degraded {
		if d.Rule == rule {
			return &plan.Report.Degraded[i]
		}
	}
	return nil
}

func TestTranslateNetworkRules(t *testing.T) {
	spec := netSpec(api.ActionDeny,
		netRule("web", api.ActionAllow, api.NetworkTarget{CIDR: []string{"192.0.2.0/24"}, Ports: []intstr.IntOrString{intstr.FromInt32(443), intstr.FromString("8000-8080")}, Proto: []string{"tcp"}}),
		netRule("dns", api.ActionAllow, api.NetworkTarget{Ports: []intstr.IntOrString{intstr.FromInt32(53)}, Proto: []string{"udp", "tcp"}}),
		netRule("no-test-net", api.ActionDeny, api.NetworkTarget{CIDR: []string{"198.51.100.0/24", "2001:db8::/32"}}),
		netRule("serve", api.ActionAllow, api.NetworkTarget{Direction: "listen", CIDR: []string{"127.0.0.0/8"}}),
		netRule("ping", api.ActionAllow, api.NetworkTarget{Proto: []string{"icmp"}}),
	)
	spec.Network.Rules[2].Mode = api.RuleAudit
	spec.Network.Rules[2].Origin = "catalog/E2"
	spec.Network.Default.Listen = api.ActionDeny
	x := NetworkExtras{DefaultMode: NetworkDirections{Egress: "audit"}}
	plan := translate(t, spec, x, DestClasses{})
	eg := plan.Egress.Policy.Egress
	if plan.Egress.Policy.Mode != "enforce" || eg.Default != "deny" || eg.DefaultMode != "audit" {
		t.Fatalf("document header %+v", plan.Egress.Policy)
	}
	web := ruleByName(plan, "web")
	if web == nil || web.Proto != "tcp" || !reflect.DeepEqual(web.Ports, []netpolicy.PortRange{{From: 443}, {From: 8000, To: 8080}}) || !reflect.DeepEqual(web.CIDRs, []string{"192.0.2.0/24"}) {
		t.Fatalf("web %+v", web)
	}
	// Two protocols become two gadget rules; no destination means every address.
	tcp, udp := ruleByName(plan, "dns/tcp"), ruleByName(plan, "dns/udp")
	if tcp == nil || udp == nil || udp.Proto != "udp" || !reflect.DeepEqual(udp.CIDRs, []string{"0.0.0.0/0", "::/0"}) {
		t.Fatalf("dns rules %+v %+v", tcp, udp)
	}
	deny := ruleByName(plan, "no-test-net")
	if deny == nil || deny.Mode != "audit" || deny.Origin != "catalog/E2" || deny.Proto != "any" {
		t.Fatalf("deny %+v", deny)
	}
	if ruleByName(plan, "serve") != nil || ruleByName(plan, "ping") != nil {
		t.Fatal("listen and icmp rules must not reach the gadget")
	}
	notEnforced := strings.Join(plan.Report.NotEnforced, ";")
	for _, want := range []string{"rule serve: listen direction", "rule ping: proto icmp", "default listen deny"} {
		if !strings.Contains(notEnforced, want) {
			t.Errorf("NotEnforced %q lacks %q", notEnforced, want)
		}
	}
	if plan.Report.NotReady != "" || len(plan.Report.Degraded) != 0 || plan.Report.Rules != 5 {
		t.Fatalf("report %+v", plan.Report)
	}
}

func TestTranslateNetworkValidates(t *testing.T) {
	for name, mutate := range map[string]func(*api.PolicySpec, *NetworkExtras){
		"proto":          func(s *api.PolicySpec, _ *NetworkExtras) { s.Network.Rules[0].Target.Proto = []string{"sctp"} },
		"direction":      func(s *api.PolicySpec, _ *NetworkExtras) { s.Network.Rules[0].Target.Direction = "ingress" },
		"destClass":      func(s *api.PolicySpec, _ *NetworkExtras) { s.Network.Rules[0].Target.DestClass = []string{""} },
		"listen default": func(s *api.PolicySpec, _ *NetworkExtras) { s.Network.Default.Listen = "" },
		"actor": func(s *api.PolicySpec, _ *NetworkExtras) {
			s.Network.Rules[0].Actor = &api.Actor{Path: []string{"/bin/curl"}}
		},
		"defaultMode": func(_ *api.PolicySpec, x *NetworkExtras) { x.DefaultMode.Egress = "tripwire" },
		"except on allow": func(s *api.PolicySpec, x *NetworkExtras) {
			s.Network.Rules[0].Action = api.ActionAllow
			x.Except = map[string][]NetworkExcept{"r": {{Target: &api.NetworkTarget{CIDR: []string{"192.0.2.1/32"}}}}}
		},
		"empty except": func(_ *api.PolicySpec, x *NetworkExtras) {
			x.Except = map[string][]NetworkExcept{"r": {{Target: &api.NetworkTarget{}}}}
		},
		"except for unknown rule": func(_ *api.PolicySpec, x *NetworkExtras) {
			x.Except = map[string][]NetworkExcept{"other": {{Target: &api.NetworkTarget{CIDR: []string{"192.0.2.1/32"}}}}}
		},
	} {
		spec := netSpec(api.ActionAllow, netRule("r", api.ActionDeny, api.NetworkTarget{CIDR: []string{"192.0.2.0/24"}}))
		var x NetworkExtras
		mutate(&spec, &x)
		if _, err := TranslateNetwork(spec, x, DestClasses{}); err == nil {
			t.Errorf("%s: invalid input accepted", name)
		}
	}
}

func TestNetworkLocalAndClusterClasses(t *testing.T) {
	spec := netSpec(api.ActionAllow,
		netRule("no-imds", api.ActionDeny, api.NetworkTarget{DestClass: []string{"imds"}}),
		netRule("no-lateral", api.ActionDeny, api.NetworkTarget{DestClass: []string{ClassClusterInternal, "privateRanges"}}),
	)
	cluster := ClusterCIDRs{Pods: []string{"10.244.0.0/24"}, Services: []string{"10.96.0.0/16"}}
	plan := translate(t, spec, NetworkExtras{}, DestClasses{Cluster: cluster})
	if got := ruleByName(plan, "no-imds").CIDRs; !reflect.DeepEqual(got, []string{"169.254.169.254/32", "fd00:ec2::254/128"}) {
		t.Fatalf("imds %v", got)
	}
	lateral := ruleByName(plan, "no-lateral")
	for _, want := range []string{"10.244.0.0/24", "10.96.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		if !strings.Contains(strings.Join(lateral.CIDRs, ","), want) {
			t.Fatalf("lateral %v lacks %s", lateral.CIDRs, want)
		}
	}
	if lateral.Mode != "" || len(plan.Report.Degraded) != 0 || plan.Report.ClassesResolved != 3 {
		t.Fatalf("fully resolved classes must enforce: %+v", plan.Report)
	}
	// Only the pod part found: the rule enforces with it and is reported partial.
	plan = translate(t, spec, NetworkExtras{}, DestClasses{Cluster: ClusterCIDRs{Pods: []string{"10.244.0.0/24"}, Missing: []string{"service CIDRs"}}})
	if d := degraded(plan, "no-lateral"); d == nil || d.Effective != "enforce" || d.Reason != "class-partial" {
		t.Fatalf("partial clusterInternal %+v", plan.Report.Degraded)
	}
}

func TestNetworkBackendClassesAndPolicyAdditions(t *testing.T) {
	spec := netSpec(api.ActionDeny, netRule("models", api.ActionAllow, api.NetworkTarget{DestClass: []string{"modelProvider"}, Ports: []intstr.IntOrString{intstr.FromInt32(443)}}))
	spec.Classes = &api.PolicyClasses{DestClasses: map[string][]string{"modelProvider": {"203.0.113.7"}}}
	shared := DestClasses{Shared: map[string][]string{"modelProvider": {"198.51.100.0/24", "api.example.com"}}}
	plan := translate(t, spec, NetworkExtras{}, shared)
	if got := ruleByName(plan, "models").CIDRs; !reflect.DeepEqual(got, []string{"198.51.100.0/24", "203.0.113.7/32"}) {
		t.Fatalf("backend class with local addition %v", got)
	}
	if d := degraded(plan, "models"); d == nil || d.Reason != "class-partial" {
		t.Fatalf("a DNS-name member must be reported: %+v", plan.Report.Degraded)
	}
	// A class defined in two SandboxPolicyClasses objects is unresolved.
	shared.Ambiguous = map[string]bool{"modelProvider": true}
	spec.Classes = nil
	if plan = translate(t, spec, NetworkExtras{}, shared); plan.Report.NotReady != "ClassUnresolved" {
		t.Fatalf("ambiguous class %+v", plan.Report)
	}
}

func TestNetworkUnresolvedClassDegradation(t *testing.T) {
	// A deny with an unresolved class degrades to audit alone.
	spec := netSpec(api.ActionDeny,
		netRule("loopback", api.ActionAllow, api.NetworkTarget{CIDR: []string{"127.0.0.0/8"}}),
		netRule("no-mcp", api.ActionDeny, api.NetworkTarget{DestClass: []string{"mcp", "linkLocal"}}),
		netRule("no-unknown", api.ActionDeny, api.NetworkTarget{DestClass: []string{"unknown"}}),
	)
	plan := translate(t, spec, NetworkExtras{}, DestClasses{})
	if r := ruleByName(plan, "no-mcp"); r == nil || r.Mode != "audit" || !reflect.DeepEqual(r.CIDRs, []string{"169.254.0.0/16", "fe80::/10"}) {
		t.Fatalf("deny with unresolved class %+v", r)
	}
	if d := degraded(plan, "no-mcp"); d == nil || d.Requested != api.RuleEnforce || d.Effective != "audit" || d.Reason != "class-unresolved" {
		t.Fatalf("degraded %+v", plan.Report.Degraded)
	}
	if d := degraded(plan, "no-unknown"); d == nil || d.Reason != "class-undefined" || ruleByName(plan, "no-unknown") != nil {
		t.Fatalf("unknown class %+v", plan.Report)
	}
	if plan.Report.NotReady != "" || plan.Egress.Policy.Egress.DefaultMode != "" || plan.Report.ClassesUnresolved != 2 {
		t.Fatalf("an unresolved deny must not touch the default or readiness: %+v", plan.Report)
	}

	// An unresolved allow degrades the egress default and makes the policy not ready.
	spec.Network.Rules = append(spec.Network.Rules, netRule("models", api.ActionAllow, api.NetworkTarget{DestClass: []string{"modelProvider"}}))
	plan = translate(t, spec, NetworkExtras{}, DestClasses{})
	if plan.Report.NotReady != "ClassUnresolved" || plan.Egress.Policy.Egress.DefaultMode != "audit" {
		t.Fatalf("unresolved allow %+v / %+v", plan.Report, plan.Egress.Policy.Egress)
	}
	if d := degraded(plan, "default/egress"); d == nil || d.Effective != "audit" {
		t.Fatalf("default not reported: %+v", plan.Report.Degraded)
	}
	if r := ruleByName(plan, "loopback"); r == nil || r.Mode != "" {
		t.Fatal("other rules keep their mode")
	}

	// A dnsName allow cannot be evaluated either: the same degradation.
	spec.Network.Rules = []api.NetworkRule{netRule("api", api.ActionAllow, api.NetworkTarget{DNSName: []string{"api.example.com"}})}
	plan = translate(t, spec, NetworkExtras{}, DestClasses{})
	if plan.Report.NotReady != "DNSNameNotEnforceable" || plan.Egress.Policy.Egress.DefaultMode != "audit" || ruleByName(plan, "api") != nil {
		t.Fatalf("dnsName allow %+v", plan.Report)
	}
}

func TestNetworkExcept(t *testing.T) {
	spec := netSpec(api.ActionAllow, netRule("no-private", api.ActionDeny, api.NetworkTarget{DestClass: []string{"privateRanges"}}))
	x := NetworkExtras{Except: map[string][]NetworkExcept{"no-private": {
		{Target: &api.NetworkTarget{CIDR: []string{"10.1.0.0/16"}}},
		{Target: &api.NetworkTarget{CIDR: []string{"172.16.0.0/12"}}},                                                      // covers a whole rule CIDR
		{Target: &api.NetworkTarget{CIDR: []string{"192.168.1.0/24"}, Ports: []intstr.IntOrString{intstr.FromInt32(443)}}}, // not enforceable
		{Target: &api.NetworkTarget{DestClass: []string{"knownService"}}},                                                  // unresolved
	}}}
	plan := translate(t, spec, x, DestClasses{})
	r := ruleByName(plan, "no-private")
	if r == nil || !reflect.DeepEqual(r.CIDRs, []string{"10.0.0.0/8", "192.168.0.0/16"}) || !reflect.DeepEqual(r.Except, []string{"10.1.0.0/16"}) || r.Mode != "" {
		t.Fatalf("except fitting %+v", r)
	}
	if plan.Report.NotReady != "ClassUnresolved" {
		t.Fatal("an except entry with an unresolved class makes the policy not ready")
	}
	if d := degraded(plan, "no-private"); d == nil || d.Effective != "enforce" || d.Reason != "except-class-unresolved" {
		t.Fatalf("degraded %+v", plan.Report.Degraded)
	}
	if n := strings.Join(plan.Report.NotEnforced, ";"); !strings.Contains(n, "except 2 is disabled") || !strings.Contains(n, "except 3 is disabled") {
		t.Fatalf("NotEnforced %q", n)
	}
}

func TestSplitNetworkExtras(t *testing.T) {
	spec := map[string]any{"network": map[string]any{
		"default":       map[string]any{"egress": "deny", "listen": "deny"},
		"defaultMode":   map[string]any{"egress": "audit"},
		"defaultOrigin": map[string]any{"egress": "catalog/E1"},
		"rules": []any{map[string]any{"name": "r", "action": "deny", "target": map[string]any{}, "except": []any{
			map[string]any{"target": map[string]any{"cidr": []any{"192.0.2.1/32"}}}}}},
	}}
	x, err := splitNetworkExtras(spec)
	if err != nil || x.DefaultMode.Egress != "audit" || x.DefaultOrigin.Egress != "catalog/E1" || len(x.Except["r"]) != 1 {
		t.Fatalf("extras %+v %v", x, err)
	}
	n := spec["network"].(map[string]any)
	if _, ok := n["defaultMode"]; ok {
		t.Fatal("mirrored fields must be removed for strict decoding")
	}
	if _, ok := n["rules"].([]any)[0].(map[string]any)["except"]; ok {
		t.Fatal("except must be removed for strict decoding")
	}
	if _, err := splitNetworkExtras(map[string]any{"network": map[string]any{"defaultMode": map[string]any{"ingress": "audit"}}}); err == nil {
		t.Fatal("unknown defaultMode key accepted")
	}
}

func networkPolicyObject(name string, spec api.PolicySpec, extras map[string]any) *unstructured.Unstructured {
	p := &api.SandboxPolicy{TypeMeta: metav1.TypeMeta{APIVersion: api.SchemeGroupVersion.String(), Kind: "SandboxPolicy"}, ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns", UID: types.UID("uid-" + name), Generation: 1},
		Spec: api.SandboxPolicySpec{PolicySpec: spec}}
	raw, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(p)
	network := raw["spec"].(map[string]any)["network"].(map[string]any)
	for k, v := range extras {
		network[k] = v
	}
	return &unstructured.Unstructured{Object: raw}
}

func TestControllerNetworkPlanAndStatus(t *testing.T) {
	ctx := context.Background()
	spec := netSpec(api.ActionDeny,
		netRule("loopback", api.ActionAllow, api.NetworkTarget{CIDR: []string{"127.0.0.0/8"}}),
		netRule("models", api.ActionAllow, api.NetworkTarget{DestClass: []string{"modelProvider"}}),
		netRule("serve", api.ActionAllow, api.NetworkTarget{Direction: "listen"}))
	c, backend, w, _ := setup(t)
	obj := networkPolicyObject("net", spec, map[string]any{"defaultMode": map[string]any{"egress": "enforce"}})
	c.objects[objectKey(obj)] = obj
	if err := c.SetBindings(ctx, []Binding{binding()}); err != nil {
		t.Fatal(err)
	}
	plan := backend.plans[bindingKey(binding())]
	if len(plan.Policies) != 1 || plan.Policies[0].Network == nil || ruleByName(plan.Policies[0].Network, "loopback") == nil {
		t.Fatalf("network plan not sent to the backend: %+v", plan)
	}
	report := w.reports["uid-net"]
	ready := report.Status.Conditions[0]
	if ready.Status != metav1.ConditionFalse || ready.Reason != "ClassUnresolved" {
		t.Fatalf("ready %+v", ready)
	}
	if report.Status.Counts.Degraded != 2 || report.Status.Compiled == nil || report.Status.Compiled.ClassesUnresolved != 1 {
		t.Fatalf("status %+v", report.Status)
	}
	found := false
	for _, cond := range report.Status.Conditions {
		found = found || (cond.Type == "NetworkNotEnforced" && strings.Contains(cond.Message, "rule serve"))
	}
	if !found {
		t.Fatalf("listen rule not reported: %+v", report.Status.Conditions)
	}

	// The class resolves: the plan changes (new revision) and the policy is ready.
	classes := &api.SandboxPolicyClasses{TypeMeta: metav1.TypeMeta{APIVersion: api.SchemeGroupVersion.String(), Kind: "SandboxPolicyClasses"}, ObjectMeta: metav1.ObjectMeta{Name: "backend", UID: "classes"},
		Spec: api.PolicyClasses{DestClasses: map[string][]string{"modelProvider": {"203.0.113.0/24"}}}}
	raw, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(classes)
	c.objects[objectKey(&unstructured.Unstructured{Object: raw})] = &unstructured.Unstructured{Object: raw}
	if err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	next := backend.plans[bindingKey(binding())]
	if next.Revision == plan.Revision || ruleByName(next.Policies[0].Network, "models") == nil {
		t.Fatal("a class change must give a new plan")
	}
	if ready := w.reports["uid-net"].Status.Conditions[0]; ready.Status != metav1.ConditionTrue {
		t.Fatalf("resolved class must be ready: %+v", ready)
	}
}

func TestNetworkSectionUnavailableIsReported(t *testing.T) {
	ctx := context.Background()
	c, _, w, _ := setup(t)
	obj := networkPolicyObject("net", netSpec(api.ActionAllow), nil)
	c.objects[objectKey(obj)] = obj
	sections, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, nil, nil)
	c.backend = sections
	_ = c.SetBindings(ctx, []Binding{binding()})
	if ready := w.reports["uid-net"].Status.Conditions[0]; ready.Status != metav1.ConditionFalse || ready.Reason != "NetworkNotConfigured" {
		t.Fatalf("ready %+v", ready)
	}
}

// kernelDecision mirrors net_decide in enforce_network/network_policy.h for one
// compiled document: the rank and the rule name that judge a connection.
func kernelDecision(t *testing.T, doc netpolicy.Document, dst string, port uint16, proto uint8) (uint8, string) {
	t.Helper()
	c, err := netpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.AddrFrom16(netip.MustParseAddr(dst).As16())
	best, found := -1, netpolicy.PrefixEntry{}
	for _, p := range c.Prefixes {
		bits := int(p.Key.PrefixLen) - 32
		if netip.PrefixFrom(netip.AddrFrom16(p.Key.Addr), bits).Contains(addr) && bits > best {
			best, found = bits, p
		}
	}
	s := c.Slots[0]
	var docs uint32
	allowed := false
	var m netpolicy.RuleEntry
	if best >= 0 {
		list := c.Lists[found.List]
		for _, r := range list.Rules[:list.Len] {
			if (r.Proto != netpolicy.ProtoAny && r.Proto != proto) || port < r.PortLo || port > r.PortHi {
				continue
			}
			docs |= 1 << r.Doc
			allowed = allowed || r.Rank == netpolicy.RankAllow
			if r.Rank > m.Rank {
				m = r
			}
		}
	}
	switch {
	case m.Rank == netpolicy.RankNone:
		return s.Rank, c.RuleNames[s.RuleID]
	case !allowed && s.DenyEnforceDocs&^docs != 0 && m.Rank < netpolicy.RankDenyEnforce:
		return netpolicy.RankDenyEnforce, "default"
	}
	return m.Rank, c.RuleNames[m.RuleID]
}

func TestNetworkUnresolvableDenyKeepsEnforceDefault(t *testing.T) {
	// A deny on a DNS name has no CIDR. It must not become a deny audit rule
	// on every destination: that hides the enforce default deny.
	for name, target := range map[string]api.NetworkTarget{
		"dnsName":             {DNSName: []string{"evil.example.com"}},
		"dnsName ports proto": {DNSName: []string{"evil.example.com"}, Ports: []intstr.IntOrString{intstr.FromInt32(443)}, Proto: []string{"tcp"}},
	} {
		spec := netSpec(api.ActionDeny,
			netRule("web", api.ActionAllow, api.NetworkTarget{CIDR: []string{"192.0.2.0/24"}}),
			netRule("no-evil", api.ActionDeny, target))
		plan := translate(t, spec, NetworkExtras{}, DestClasses{})
		if ruleByName(plan, "no-evil") != nil {
			t.Fatalf("%s: an unresolvable deny reached the gadget: %+v", name, plan.Egress.Policy.Egress.Rules)
		}
		if n := strings.Join(plan.Report.NotEnforced, ";"); !strings.Contains(n, "rule no-evil: no destination is resolved") {
			t.Fatalf("%s: NotEnforced %q", name, n)
		}
		if rank, rule := kernelDecision(t, plan.Egress, "198.51.100.7", 443, netpolicy.ProtoTCP); rank != netpolicy.RankDenyEnforce || rule != "default" {
			t.Fatalf("%s: 198.51.100.7:443 got rank %d rule %q, want the enforce default deny", name, rank, rule)
		}
		if rank, rule := kernelDecision(t, plan.Egress, "192.0.2.10", 443, netpolicy.ProtoTCP); rank != netpolicy.RankAllow || rule != "web" {
			t.Fatalf("%s: 192.0.2.10:443 got rank %d rule %q, want allow web", name, rank, rule)
		}
	}
}
