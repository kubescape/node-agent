package sandboxpolicy

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	netpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/policy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// NetworkPlan is the network section of one policy, translated to the network
// gadget's policy document: egress only, destination classes resolved to CIDRs.
// Its content is part of the policy revision, so a class change replaces the
// node instance like a policy change.
type NetworkPlan struct {
	Egress netpolicy.Document `json:"egress"`
	Report NetworkReport      `json:"report"`
}

// NetworkReport is what the node status says about the translation.
type NetworkReport struct {
	// Degraded lists rules and defaults that run in another mode, or with
	// a part of their destinations, because a class is not resolved.
	Degraded []api.DegradedRule `json:"degraded,omitempty"`
	// NotEnforced lists what the gadget cannot enforce, with the reason.
	NotEnforced []string `json:"notEnforced,omitempty"`
	// NotReady is the Ready=False reason when an allow rule or an except
	// entry cannot be resolved (ClassUnresolved), else empty.
	NotReady          string `json:"notReady,omitempty"`
	Rules             int64  `json:"rules"`
	ClassesResolved   int64  `json:"classesResolved"`
	ClassesUnresolved int64  `json:"classesUnresolved"`
}

// Fixed destination classes the agent computes locally (sandbox-policy-crd.md
// section 4.2). The design's imds also lists the GCP metadata host name; its
// address is already in 169.254.169.254/32.
var localDestClasses = map[string][]string{
	"imds":                       {"169.254.169.254/32", "fd00:ec2::254/128"},
	"workloadCredentialEndpoint": {"169.254.170.2/32", "169.254.170.23/32", "fd00:ec2::23/128"},
	"linkLocal":                  {"169.254.0.0/16", "fe80::/10"},
	"privateRanges":              {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
}

// ClassClusterInternal is filled from the cluster's pod and service CIDRs.
const ClassClusterInternal = "clusterInternal"

// ClusterCIDRs is what this node learned about the cluster's pod and service
// ranges. Missing names each part that no source gave.
type ClusterCIDRs struct {
	Pods, Services, Missing []string
}

// DestClasses resolves destination classes for the network section: the local
// classes, then the shared SandboxPolicyClasses entries, then the policy's own
// additions (all three are combined).
type DestClasses struct {
	Shared map[string][]string
	// Ambiguous classes are defined in two SandboxPolicyClasses objects;
	// they are unresolved rather than one definition chosen at random.
	Ambiguous map[string]bool
	Cluster   ClusterCIDRs
}

type classResult struct {
	prefixes []netip.Prefix
	// reason is set when the class has no CIDR (unresolved) or only a part.
	reason   string
	resolved bool
}

func (d DestClasses) resolve(name string, local map[string][]string) classResult {
	if d.Ambiguous[name] {
		return classResult{reason: "class-unresolved"}
	}
	members := append(append([]string(nil), localDestClasses[name]...), d.Shared[name]...)
	members = append(members, local[name]...)
	_, defined := localDestClasses[name]
	_, shared := d.Shared[name]
	_, own := local[name]
	defined = defined || shared || own
	partial := false
	if name == ClassClusterInternal {
		defined = true
		members = append(append(members, d.Cluster.Pods...), d.Cluster.Services...)
		partial = len(d.Cluster.Missing) > 0
	}
	var r classResult
	for _, m := range members {
		if p, ok := parseDest(m); ok {
			r.prefixes = append(r.prefixes, p)
		} else {
			partial = true // a DNS name: not enforceable in the kernel
		}
	}
	switch {
	case len(r.prefixes) == 0 && name == "unknown" && !defined:
		r.reason = "class-undefined"
	case len(r.prefixes) == 0:
		r.reason = "class-unresolved"
	case partial:
		r.resolved, r.reason = true, "class-partial"
	default:
		r.resolved = true
	}
	return r
}

// parseDest reads a CIDR or a single address; IPv4-mapped IPv6 becomes IPv4.
func parseDest(s string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, aerr := netip.ParseAddr(s)
		if aerr != nil || a.Zone() != "" {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), true
}

var allDestinations = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

// intersect returns the destinations in both lists (fields of a target AND).
func intersect(a, b []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, x := range a {
		for _, y := range b {
			if x.Overlaps(y) {
				if x.Bits() >= y.Bits() {
					out = append(out, x)
				} else {
					out = append(out, y)
				}
			}
		}
	}
	return out
}

func within(inner, outer netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// fitExcepts drops rule CIDRs that an except covers and keeps the excepts
// that lie inside a remaining CIDR, as the gadget requires.
func fitExcepts(cidrs, excepts []netip.Prefix) (keep, lifted []netip.Prefix) {
	for _, c := range cidrs {
		covered := false
		for _, e := range excepts {
			covered = covered || within(c, e)
		}
		if !covered {
			keep = append(keep, c)
		}
	}
	for _, e := range excepts {
		for _, k := range keep {
			if within(e, k) {
				lifted = append(lifted, e)
				break
			}
		}
	}
	return keep, lifted
}

func prefixStrings(list []netip.Prefix) []string {
	out := make([]string, 0, len(list))
	for _, p := range list {
		out = append(out, p.String())
	}
	return sortedUnique(out)
}

func validMode(m string) bool { return m == "" || m == "audit" || m == "enforce" }

// validateTarget checks what ValidatePolicySpec does not: proto, direction and
// destClass values (the CRD schema checks them only at admission).
func validateTarget(t api.NetworkTarget) error {
	for _, p := range t.Proto {
		if p != "tcp" && p != "udp" && p != "icmp" && p != "unix" {
			return fmt.Errorf("proto %q must be tcp, udp, icmp or unix", p)
		}
	}
	if t.Direction != "" && t.Direction != "egress" && t.Direction != "listen" {
		return fmt.Errorf("direction %q must be egress or listen", t.Direction)
	}
	for _, list := range [][]string{t.DestClass, t.DNSName} {
		for _, v := range list {
			if strings.TrimSpace(v) == "" {
				return fmt.Errorf("destClass and dnsName entries must not be empty")
			}
		}
	}
	for _, c := range t.CIDR {
		if _, err := netip.ParsePrefix(c); err != nil {
			return fmt.Errorf("invalid CIDR %q", c)
		}
		// parseDest is what the translation uses: reject here what it drops.
		if _, ok := parseDest(c); !ok {
			return fmt.Errorf("CIDR %q: an IPv4-mapped IPv6 prefix must be /96 or longer", c)
		}
	}
	for _, p := range t.Ports {
		if _, err := portRange(p); err != nil {
			return err
		}
	}
	return nil
}

func portRange(p intstr.IntOrString) (netpolicy.PortRange, error) {
	if p.Type == intstr.Int {
		if p.IntVal >= 1 && p.IntVal <= 65535 {
			return netpolicy.PortRange{From: uint16(p.IntVal)}, nil
		}
	} else if lo, hi, ok := strings.Cut(p.StrVal, "-"); ok {
		a, err1 := strconv.ParseUint(lo, 10, 16)
		b, err2 := strconv.ParseUint(hi, 10, 16)
		if err1 == nil && err2 == nil && a >= 1 && b >= a {
			return netpolicy.PortRange{From: uint16(a), To: uint16(b)}, nil
		}
	}
	return netpolicy.PortRange{}, fmt.Errorf("port %q must be 1..65535 or an ordered range a-b", p.String())
}

// validateNetwork checks a network section. ValidatePolicySpec checks the
// except entries too; this repeats it for callers that skip it.
func validateNetwork(n api.NetworkSection) error {
	for _, d := range []api.Action{n.Default.Egress, n.Default.Listen} {
		if d != api.ActionAllow && d != api.ActionDeny {
			return fmt.Errorf("network defaults egress and listen must be allow or deny")
		}
	}
	if m := n.DefaultMode; m != nil && (!validMode(string(m.Egress)) || !validMode(string(m.Listen))) {
		return fmt.Errorf("network defaultMode must be audit or enforce")
	}
	for _, r := range n.Rules {
		if r.Action != api.ActionAllow && r.Action != api.ActionDeny {
			return fmt.Errorf("rule %q has invalid action", r.Name)
		}
		if !validMode(string(r.Mode)) {
			return fmt.Errorf("rule %q has invalid mode", r.Name)
		}
		if r.Actor != nil {
			return fmt.Errorf("rule %q: actor predicates are unsupported in the network section", r.Name)
		}
		if err := validateTarget(r.Target); err != nil {
			return fmt.Errorf("rule %q: %w", r.Name, err)
		}
		if r.Except != nil && r.Action != api.ActionDeny {
			return fmt.Errorf("rule %q: except applies to deny rules only", r.Name)
		}
		for i, e := range r.Except {
			if err := e.Validate(); err != nil {
				return fmt.Errorf("rule %q except %d: %w", r.Name, i, err)
			}
			if e.Target != nil {
				if err := validateTarget(*e.Target); err != nil {
					return fmt.Errorf("rule %q except %d: %w", r.Name, i, err)
				}
			}
		}
	}
	return nil
}

// TranslateNetwork translates the network section of one policy to the network
// gadget's document. Only egress is enforced. The CRD rules the gadget cannot
// enforce are reported. An unresolved class never weakens enforcement: a deny
// rule keeps its resolved destinations at its own mode, an allow rule leaves
// the egress default as it is (an enforce default deny over-blocks), and an
// except entry is disabled (its deny applies there). Each makes the policy
// not ready (ClassUnresolved, or DNSNameNotEnforceable for a dnsName). This
// replaces the audit degradation of sandbox-policy-crd.md section 4.3. Origins keep their presence: an
// explicit "" is not a missing origin (rule origin and egress defaultOrigin).
func TranslateNetwork(spec api.PolicySpec, classes DestClasses) (*NetworkPlan, error) {
	n := spec.Network
	if n == nil {
		return nil, nil
	}
	if err := validateNetwork(*n); err != nil {
		return nil, err
	}
	var defaultMode string
	if n.DefaultMode != nil {
		defaultMode = string(n.DefaultMode.Egress)
	}
	var defaultOrigin *string
	if n.DefaultOrigin != nil {
		defaultOrigin = n.DefaultOrigin.Egress
	}
	var local map[string][]string
	if spec.Classes != nil {
		local = spec.Classes.DestClasses
	}
	t := &translator{classes: classes, local: local, seen: map[string]bool{}}
	plan := &NetworkPlan{Egress: netpolicy.Document{Version: 1, Policy: netpolicy.Policy{Mode: string(spec.Mode),
		Egress: netpolicy.Section{Default: string(n.Default.Egress), DefaultMode: defaultMode, DefaultOrigin: defaultOrigin}}}}
	report := &plan.Report
	report.Rules = int64(len(n.Rules))
	notEnforcedRule := func(rule, why string) {
		report.NotEnforced = append(report.NotEnforced, fmt.Sprintf("rule %s: %s", rule, why))
	}
	var emitted []emittedRule
	for _, r := range n.Rules {
		requested := r.Mode
		if requested == "" {
			requested = api.RuleMode(spec.Mode)
		}
		var reasons []string
		effective := string(requested)
		notEnforced := func(why string) { notEnforcedRule(r.Name, why) }
		if r.Target.Direction == "listen" {
			notEnforced("listen direction is not enforced")
			continue
		}
		protos := []string{"any"}
		if len(r.Target.Proto) > 0 {
			protos = nil
			var other []string
			for _, p := range sortedUnique(append([]string(nil), r.Target.Proto...)) {
				if p == "tcp" || p == "udp" {
					protos = append(protos, p)
				} else {
					other = append(other, p)
				}
			}
			if len(other) > 0 {
				notEnforced(fmt.Sprintf("proto %s is not enforceable", strings.Join(other, ",")))
			}
			if len(protos) == 0 {
				continue
			}
		}
		dests, unresolved, partial := t.dests(r.Target)
		if partial != "" {
			reasons = append(reasons, partial)
		}
		ports := make([]netpolicy.PortRange, 0, len(r.Target.Ports))
		for _, p := range r.Target.Ports {
			pr, _ := portRange(p) // validated
			ports = append(ports, pr)
		}
		mode := string(r.Mode)
		if unresolved != "" {
			// A resolution failure never weakens enforcement: a deny keeps
			// its resolved destinations at its own mode, and an allow that
			// cannot resolve leaves the default as it is (an enforce default
			// deny over-blocks). Either way the policy is NotReady.
			reasons = append(reasons, unresolved)
			if report.NotReady == "" || unresolved != "dns-name-not-enforceable" {
				report.NotReady = notReadyReason(unresolved)
			}
			if len(r.Target.DNSName) > 0 {
				// The name is ANDed and has no CIDR. The other fields alone
				// would allow more; for a deny they would give a deny audit
				// rule that hides the policy's own enforce default deny
				// there (common/merge/CONTRACT.md). So no destination.
				dests = nil
			}
		}
		var excepts []netip.Prefix
		for i, e := range r.Except {
			lifted, why, classMissing := t.except(e)
			switch {
			case why != "":
				notEnforced(fmt.Sprintf("except %d is disabled (%s); the deny applies there", i, why))
				if classMissing {
					reasons = append(reasons, "except-class-unresolved")
					report.NotReady = "ClassUnresolved"
				}
			default:
				excepts = append(excepts, lifted...)
			}
		}
		if len(reasons) > 0 {
			report.Degraded = append(report.Degraded, api.DegradedRule{Rule: r.Name, Requested: requested, Effective: effective, Reason: strings.Join(sortedUnique(reasons), ",")})
		}
		cidrs, lifted := fitExcepts(dests, excepts)
		if len(cidrs) == 0 {
			// No CIDR: the fields do not overlap, every destination is
			// excepted, or nothing is resolved (already in Degraded).
			if unresolved != "" && (r.Action == api.ActionDeny || len(r.Target.DNSName) > 0) {
				notEnforced("no destination is resolved")
			}
			continue
		}
		for _, proto := range protos {
			name := r.Name
			if len(protos) > 1 {
				name = r.Name + "/" + proto
			}
			emitted = append(emitted, emittedRule{crd: r.Name, generated: len(protos) > 1, rule: netpolicy.Rule{
				Name: name, Action: string(r.Action), Mode: mode, Origin: r.Origin,
				CIDRs: prefixStrings(cidrs), Except: prefixStrings(lifted), Ports: ports, Proto: proto}})
		}
	}
	plan.Egress.Policy.Egress.Rules = uniqueNames(emitted)
	if n.Default.Listen == api.ActionDeny {
		report.NotEnforced = append(report.NotEnforced, "default listen deny: listen direction is not enforced")
	}
	for _, resolved := range t.seen {
		if resolved {
			report.ClassesResolved++
		} else {
			report.ClassesUnresolved++
		}
	}
	if err := plan.Egress.Validate(); err != nil {
		return nil, fmt.Errorf("network: %w", err)
	}
	// The node instance merges this document with others, so a document over
	// the gadget limits alone fails there in every combination. Report it
	// here, as a reason of this policy.
	if _, err := netpolicy.CompileKernel(plan.Egress, 1); err != nil {
		return nil, fmt.Errorf("network: the policy alone exceeds the network gadget limits "+
			"(at most %d rule entries, one per rule and port range, can cover one destination prefix): %w", netpolicy.KernelListLen, err)
	}
	return plan, nil
}

// emittedRule is a gadget rule with the CRD rule it comes from.
type emittedRule struct {
	crd string
	// generated is set when the name is the CRD name with a "/proto"
	// suffix (a rule with two protocols becomes two gadget rules).
	generated bool
	rule      netpolicy.Rule
}

// uniqueNames gives a generated gadget rule whose name is already taken a
// "~N" suffix (the first free N from 1). The CRD does not restrict the
// characters of a rule name, so a rule can be named "a/tcp" literally, and
// the gadget requires unique names. Literal names never change, and the
// renamed rule stays enforced: dropping it would weaken a deny. Its name still
// starts with the CRD rule name, and its Origin is unchanged.
func uniqueNames(rules []emittedRule) []netpolicy.Rule {
	used := map[string]bool{}
	for _, e := range rules {
		if !e.generated {
			used[e.rule.Name] = true
		}
	}
	out := make([]netpolicy.Rule, 0, len(rules))
	for _, e := range rules {
		if e.generated {
			name := e.rule.Name
			for i := 1; used[name]; i++ {
				name = fmt.Sprintf("%s~%d", e.rule.Name, i)
			}
			used[name] = true
			e.rule.Name = name
		}
		out = append(out, e.rule)
	}
	return out
}

func notReadyReason(unresolved string) string {
	if unresolved == "dns-name-not-enforceable" {
		return "DNSNameNotEnforceable"
	}
	return "ClassUnresolved"
}

type translator struct {
	classes DestClasses
	local   map[string][]string
	// seen: class name -> resolved, for the status counts.
	seen map[string]bool
}

// dests returns the destination prefixes of a target. unresolved names why a
// part cannot be evaluated (a class without CIDRs, a DNS name); partial says a
// class gave only a part of its members.
func (t *translator) dests(target api.NetworkTarget) (dests []netip.Prefix, unresolved, partial string) {
	dests = allDestinations
	if len(target.CIDR) > 0 {
		var cidrs []netip.Prefix
		for _, c := range target.CIDR {
			p, _ := parseDest(c) // validated
			cidrs = append(cidrs, p)
		}
		dests = intersect(dests, cidrs)
	}
	if len(target.DestClass) > 0 {
		var members []netip.Prefix
		for _, name := range target.DestClass {
			r := t.classes.resolve(name, t.local)
			t.seen[name] = r.resolved
			members = append(members, r.prefixes...)
			switch {
			case !r.resolved:
				unresolved = r.reason
			case r.reason != "":
				partial = r.reason
			}
		}
		dests = intersect(dests, members)
	}
	if len(target.DNSName) > 0 && unresolved == "" {
		unresolved = "dns-name-not-enforceable"
	}
	return dests, unresolved, partial
}

// except returns the prefixes an except entry lifts, or why it is disabled.
func (t *translator) except(e api.NetworkException) (lifted []netip.Prefix, why string, classMissing bool) {
	if e.Actor != nil {
		return nil, "actor predicates are unsupported", false
	}
	target := *e.Target
	if len(target.Ports) > 0 || len(target.Proto) > 0 || target.Direction != "" {
		return nil, "ports, proto and direction in an except are not enforceable", false
	}
	dests, unresolved, _ := t.dests(target)
	if unresolved != "" {
		return nil, unresolved, unresolved != "dns-name-not-enforceable"
	}
	return dests, "", false
}

// sortedDegraded orders status entries by rule name.
func sortedDegraded(list []api.DegradedRule) []api.DegradedRule {
	out := append([]api.DegradedRule(nil), list...)
	sort.Slice(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out
}
