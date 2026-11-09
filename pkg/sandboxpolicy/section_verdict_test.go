package sandboxpolicy

import (
	"context"
	"reflect"
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
)

func originPtr(s string) *string { return &s }

func sectionPolicy(name, revision string) CompiledPolicy {
	return CompiledPolicy{Identity: PolicyIdentity{Kind: "SandboxPolicy", Namespace: "ns", Name: name, UID: types.UID("uid-" + name), Generation: 7}, Revision: revision}
}

func TestNewSectionVerdictModeAndReason(t *testing.T) {
	for _, c := range []struct {
		name      string
		mode      uint32
		isDefault bool
		rule      string
		wantMode  api.RuleMode
		wouldDeny bool
		reason    string
	}{
		{"enforced rule", 2, false, "ns/p/deny-ptrace", api.RuleEnforce, false, "matching_rule"},
		{"audited rule", 1, false, "ns/p/deny-ptrace", api.RuleAudit, true, "matching_rule"},
		{"section default flag", 2, true, "default", api.RuleEnforce, false, "section_default"},
		{"default rule name", 1, false, "default", api.RuleAudit, true, "section_default"},
		{"unresolved path", 2, true, "unresolved-path", api.RuleEnforce, false, "path_resolution_error"},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := NewSectionVerdict(SectionFile, 3, 12, c.mode, 41, 1, c.isDefault, c.rule, originPtr("catalog/a"), "cat")
			if v.Verdict != api.ActionDeny || v.Mode != c.wantMode || v.WouldDeny != c.wouldDeny || v.Reason != c.reason {
				t.Fatalf("got verdict %q mode %q wouldDeny %v reason %q", v.Verdict, v.Mode, v.WouldDeny, v.Reason)
			}
			if v.Section != SectionFile || v.Generation != 3 || v.CgroupID != 12 || v.PID != 41 || v.Slot != 1 || v.Comm != "cat" || v.Time.IsZero() {
				t.Fatalf("common fields not kept: %+v", v)
			}
			if !reflect.DeepEqual(v.Origins, []string{"catalog/a"}) {
				t.Fatalf("origins %v", v.Origins)
			}
		})
	}
	// Presence comes from the origin id, not from the string: an absent
	// origin is [] and an explicit empty one is [""], for rules and defaults.
	for _, rule := range []string{"ns/p/r", "default"} {
		if v := NewSectionVerdict(SectionNetwork, 1, 1, 2, 1, 0, rule == "default", rule, nil, ""); v.Origins == nil || len(v.Origins) != 0 {
			t.Fatalf("%s: absent origin became %#v", rule, v.Origins)
		}
		if v := NewSectionVerdict(SectionNetwork, 1, 1, 2, 1, 0, rule == "default", rule, originPtr(""), ""); !reflect.DeepEqual(v.Origins, []string{""}) {
			t.Fatalf("%s: explicit empty origin became %#v", rule, v.Origins)
		}
	}
	explicit := NewSectionVerdict(SectionFile, 1, 1, 2, 1, 0, false, "ns/a/r", originPtr(""), "")
	explicit.Attribute([]CompiledPolicy{sectionPolicy("a", "rev")})
	if m := explicit.Matches[0]; m.Origin != "" || !reflect.DeepEqual(m.Origins, []string{""}) {
		t.Fatalf("explicit empty origin lost in the match: %+v", m)
	}
}

func TestSectionVerdictAttribution(t *testing.T) {
	a, b := sectionPolicy("a", "rev-a"), sectionPolicy("b", "rev-b")
	t.Run("rule names its policy", func(t *testing.T) {
		v := NewSectionVerdict(SectionPrivilege, 1, 1, 1, 1, 0, false, "ns/b/no-mount", originPtr("custom/b/no-mount"), "")
		v.Attribute([]CompiledPolicy{a, b})
		if v.Policy != b.Identity || len(v.PolicySet) != 2 || v.PolicySet[1] != (PolicyRevision{Policy: b.Identity, Revision: "rev-b"}) {
			t.Fatalf("policy %+v set %+v", v.Policy, v.PolicySet)
		}
		want := []RuleMatch{{Policy: b.Identity, Revision: "rev-b", Name: "no-mount", Origin: "custom/b/no-mount", Origins: []string{"custom/b/no-mount"}, Action: api.ActionDeny, Mode: api.RuleAudit}}
		if !reflect.DeepEqual(v.Matches, want) || v.MatchesComplete {
			t.Fatalf("matches %+v complete %v: another policy may also match", v.Matches, v.MatchesComplete)
		}
	})
	t.Run("one policy is complete", func(t *testing.T) {
		v := NewSectionVerdict(SectionPrivilege, 1, 1, 2, 1, 0, false, "ns/a/no-mount", nil, "")
		v.Attribute([]CompiledPolicy{a})
		if v.Policy != a.Identity || len(v.Matches) != 1 || !v.MatchesComplete || v.Matches[0].Mode != api.RuleEnforce {
			t.Fatalf("%+v", v)
		}
	})
	t.Run("default with several policies is ambiguous", func(t *testing.T) {
		v := NewSectionVerdict(SectionNetwork, 1, 1, 2, 1, 0, true, "default", nil, "")
		v.Attribute([]CompiledPolicy{a, b})
		if v.Policy != (PolicyIdentity{}) || v.Matches != nil || len(v.PolicySet) != 2 {
			t.Fatalf("default invented a deciding policy: %+v", v)
		}
	})
	t.Run("default with one policy names it", func(t *testing.T) {
		v := NewSectionVerdict(SectionNetwork, 1, 1, 2, 1, 0, true, "default", nil, "")
		v.Attribute([]CompiledPolicy{b})
		if v.Policy != b.Identity || v.Matches != nil {
			t.Fatalf("%+v", v)
		}
	})
	t.Run("an empty slot leaves the policy set absent", func(t *testing.T) {
		v := NewSectionVerdict(SectionFile, 1, 1, 2, 1, 0, true, "default", nil, "")
		v.Attribute(nil)
		if v.PolicySet != nil || v.Policy != (PolicyIdentity{}) {
			t.Fatalf("%+v", v)
		}
	})
	t.Run("prefix of another policy name does not match", func(t *testing.T) {
		long := sectionPolicy("ab", "rev-ab")
		v := NewSectionVerdict(SectionFile, 1, 1, 2, 1, 0, false, "ns/ab/r", nil, "")
		v.Attribute([]CompiledPolicy{a, long})
		if v.Policy != long.Identity {
			t.Fatalf("policy %+v", v.Policy)
		}
	})
	t.Run("unknown rule names no policy", func(t *testing.T) {
		v := NewSectionVerdict(SectionFile, 1, 1, 2, 1, 0, false, "", nil, "")
		v.Attribute([]CompiledPolicy{a, b})
		if v.Reason != "" || v.Policy != (PolicyIdentity{}) || v.Matches != nil {
			t.Fatalf("%+v", v)
		}
	})
}

func TestSectionEventsAreAuthorizationsNotObservations(t *testing.T) {
	v := NewSectionVerdict(SectionNetwork, 1, 12, 2, 41, 0, false, "ns/a/r", nil, "curl")
	b := binding()
	for _, c := range []struct {
		event utils.EnrichEvent
		key   utils.EventType
	}{
		{NewPrivilegeVerdictEvent(v, b, PrivilegeTarget{Capability: -1}), utils.PrivilegeAuthorizationEventType},
		{NewNetworkVerdictEvent(v, b, NetworkTarget{Addr: "192.0.2.1", Port: 443}), utils.NetworkAuthorizationEventType},
		{NewFileVerdictEvent(v, b, FileTarget{Path: "/etc/shadow"}), utils.FileAuthorizationEventType},
	} {
		if c.event.GetEventType() != c.key {
			t.Fatalf("%T dispatches under %q", c.event, c.event.GetEventType())
		}
		if _, ok := c.event.(utils.OpenEvent); ok {
			t.Fatalf("%T must not be a file observation", c.event)
		}
		if _, ok := c.event.(utils.NetworkEvent); ok {
			t.Fatalf("%T must not be a network observation", c.event)
		}
		if _, ok := c.event.(utils.SyscallEvent); ok {
			t.Fatalf("%T must not be a syscall observation", c.event)
		}
		if c.event.GetPID() != 41 || c.event.GetComm() != "curl" || c.event.GetContainerID() != "container" || c.event.GetPod() != "pod" || c.event.GetNamespace() != "ns" {
			t.Fatalf("actor or binding lost on %T", c.event)
		}
		if c.event.GetUid() != nil || c.event.GetPpid() != 0 || c.event.FieldPresent("uid") || c.event.FieldPresent("ppid") {
			t.Fatalf("%T invented unknown fields", c.event)
		}
	}
	if len(map[utils.EventType]bool{utils.ExecAuthorizationEventType: true, utils.PrivilegeAuthorizationEventType: true, utils.NetworkAuthorizationEventType: true, utils.FileAuthorizationEventType: true,
		utils.ExecveEventType: true, utils.OpenEventType: true, utils.NetworkEventType: true, utils.SyscallEventType: true}) != 8 {
		t.Fatal("authorization keys must differ from each other and from observation keys")
	}
}

func TestSectionEventSnapshotsDoNotAlias(t *testing.T) {
	v := NewSectionVerdict(SectionFile, 1, 12, 1, 41, 0, false, "ns/a/r", originPtr("custom/a/r"), "")
	v.Attribute([]CompiledPolicy{sectionPolicy("a", "rev")})
	event := NewFileVerdictEvent(v, binding(), FileTarget{Path: "/data"})
	v.Origins[0], v.PolicySet[0].Revision = "producer", "producer"
	copy := event.snapshot().(*FileVerdictEvent)
	copy.Verdict.Origins[0], copy.Verdict.Matches[0].Name, copy.Verdict.Matches[0].Origins[0] = "receiver", "receiver", "receiver"
	copy.Binding.PodLabels["app"] = "receiver"
	if event.Verdict.Origins[0] != "custom/a/r" || event.Verdict.Matches[0].Origins[0] != "custom/a/r" || event.Verdict.PolicySet[0].Revision != "rev" || event.Verdict.Matches[0].Name != "r" || event.Binding.PodLabels["app"] != "test" || copy.Target.Path != "/data" {
		t.Fatal("section event aliases producer or receiver memory")
	}
}

func sectionReceivers(key utils.EventType, receivers ...containerwatcher.GenericEventReceiver) *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]] {
	result := &maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]{}
	result.Set(key, mapset.NewSet[containerwatcher.GenericEventReceiver](receivers...))
	return result
}

func TestReportSectionResolvesAttributesAndDispatches(t *testing.T) {
	raw := &rawVerdictReceiver{make(chan utils.K8sEvent, 1)}
	enriched := &enrichedVerdictReceiver{make(chan *events.EnrichedEvent, 1)}
	execOnly := &failingVerdictReceiver{}
	receivers := sectionReceivers(utils.NetworkAuthorizationEventType, raw, enriched, execOnly)
	exec := &rawVerdictReceiver{make(chan utils.K8sEvent, 1)}
	receivers.Set(utils.ExecAuthorizationEventType, mapset.NewSet[containerwatcher.GenericEventReceiver](exec))
	policy := sectionPolicy("a", "rev-a")
	var asked [3]any
	exporter, err := NewSectionExporter(SectionExporterOptions{Capacity: 2, Receivers: receivers,
		ResolveCgroup: func(id uint64) (Binding, bool) { return binding(), id == 12 },
		SlotPolicies: func(section string, generation uint64, slot uint32) ([]CompiledPolicy, bool) {
			asked = [3]any{section, generation, slot}
			return []CompiledPolicy{policy}, true
		}})
	if err != nil {
		t.Fatal(err)
	}
	v := NewSectionVerdict(SectionNetwork, 5, 12, 1, 41, 2, false, "ns/a/no-egress", originPtr("custom/a/no-egress"), "curl")
	if err := exporter.ReportSection(context.Background(), NewNetworkVerdictEvent(v, Binding{}, NetworkTarget{Addr: "192.0.2.1", Port: 443, Proto: "TCP"})); err != nil {
		t.Fatal(err)
	}
	if asked != [3]any{SectionNetwork, uint64(5), uint32(2)} {
		t.Fatalf("attribution asked for %v", asked)
	}
	exporter.dispatch(<-exporter.queue)
	got := (<-raw.received).(*NetworkVerdictEvent)
	if got.Binding.ContainerID != "container" || got.Verdict.Policy != policy.Identity || !got.Verdict.WouldDeny || got.Target.Addr != "192.0.2.1" {
		t.Fatalf("raw receiver got %+v", got)
	}
	e := <-enriched.received
	if e.ContainerID != "container" || e.PID != 41 || e.Event.GetEventType() != utils.NetworkAuthorizationEventType {
		t.Fatalf("enriched receiver got %+v", e)
	}
	if execOnly.calls.Load() != 0 {
		t.Fatal("a section verdict reached an exec VerdictReceiver")
	}
	select {
	case <-exec.received:
		t.Fatal("a section verdict reached the exec dispatch key")
	default:
	}
	// The exec-only receiver is not a section receiver: counted as an error.
	if s := exporter.Stats(); s.Enqueued != 1 || s.Delivered != 2 || s.ReceiverErrors != 1 {
		t.Fatalf("stats %+v", s)
	}
}

func TestReportSectionKeepsUnknownBindingAbsent(t *testing.T) {
	exporter, err := NewSectionExporter(SectionExporterOptions{Capacity: 1, Receivers: sectionReceivers(utils.FileAuthorizationEventType),
		// A binding for another cgroup is never used.
		ResolveCgroup: func(uint64) (Binding, bool) { return binding(), true },
		SlotPolicies:  func(string, uint64, uint32) ([]CompiledPolicy, bool) { return nil, false }})
	if err != nil {
		t.Fatal(err)
	}
	v := NewSectionVerdict(SectionFile, 1, 99, 2, 1, 0, false, "ns/a/r", nil, "")
	if err := exporter.ReportSection(context.Background(), NewFileVerdictEvent(v, Binding{}, FileTarget{})); err != nil {
		t.Fatal(err)
	}
	queued := (<-exporter.queue).(*FileVerdictEvent)
	if queued.Binding.ContainerID != "" || queued.Verdict.PolicySet != nil || queued.Verdict.Policy != (PolicyIdentity{}) {
		t.Fatalf("invented binding or policy: %+v", queued)
	}
	// A full queue drops and counts; it never blocks the gadget.
	if err := exporter.ReportSection(context.Background(), NewFileVerdictEvent(v, Binding{}, FileTarget{})); err != nil {
		t.Fatal(err)
	}
	if err := exporter.ReportSection(context.Background(), NewFileVerdictEvent(v, Binding{}, FileTarget{})); err != ErrVerdictQueueFull || exporter.Stats().Dropped != 1 {
		t.Fatalf("err %v stats %+v", err, exporter.Stats())
	}
}

func TestSectionDenyBurstDropsNoExecVerdict(t *testing.T) {
	receivers := sectionReceivers(utils.ExecAuthorizationEventType, &rawVerdictReceiver{make(chan utils.K8sEvent, 1)})
	exec, err := NewVerdictExporter(ExporterOptions{Capacity: 1, Receivers: receivers})
	if err != nil {
		t.Fatal(err)
	}
	sections, err := NewSectionExporter(SectionExporterOptions{Capacity: 4, Receivers: receivers})
	if err != nil {
		t.Fatal(err)
	}
	v := NewSectionVerdict(SectionPrivilege, 1, 12, 2, 41, 0, false, "ns/a/r", nil, "")
	for i := 0; i < 1000; i++ {
		_ = sections.ReportSection(context.Background(), NewPrivilegeVerdictEvent(v, Binding{}, PrivilegeTarget{}))
	}
	if err := exec.ReportVerdict(context.Background(), sampleVerdict()); err != nil {
		t.Fatalf("a section burst blocked exec: %v", err)
	}
	if s := exec.Stats(); s.Enqueued != 1 || s.Dropped != 0 {
		t.Fatalf("exec stats %+v", s)
	}
	if s := sections.Stats(); s.Enqueued != 4 || s.Dropped != 996 {
		t.Fatalf("section stats %+v: the burst must be dropped and counted", s)
	}
}
