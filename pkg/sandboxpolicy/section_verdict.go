package sandboxpolicy

import (
	"strings"
	"time"

	gadgettypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/utils"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// SectionVerdict is the decision metadata that the node-wide section gadgets
// (privilege, network, file) share. These gadgets report denies only: enforced,
// or audited (WouldDeny). The operation facts are in the typed events below.
// Unknown fields stay absent, never invented.
type SectionVerdict struct {
	Section string
	Time    time.Time
	// PolicySet holds every policy of the slot that judged the call. Policy is
	// set only when exactly one of them can have decided.
	PolicySet []PolicyRevision
	Policy    PolicyIdentity
	// Matches holds the deciding rule. The kernel keeps no other match, so
	// MatchesComplete is false whenever the slot has more than one policy.
	Matches         []RuleMatch
	MatchesComplete bool
	Rule            string
	Origins         []string
	Mode            api.RuleMode
	Verdict         api.Action
	WouldDeny       bool
	Reason          string
	// Generation is the gadget instance that judged the call (the node
	// owner's counter), not a policy generation. Slot indexes its policy table.
	Generation uint64
	Slot       uint32
	CgroupID   uint64
	PID        uint32
	Comm       string
}

// Rule names in the section gadgets that are not policy rules.
const (
	SectionRuleDefault    = "default"
	SectionRuleUnresolved = "unresolved-path"
)

// NewSectionVerdict decodes the common gadget fields: mode 1 is audit, 2 is
// enforce (common/verdict.h). rule and origin are the names that the event's
// rule_id and origin_id index ("" when the table has none).
func NewSectionVerdict(section string, generation, cgroup uint64, mode, pid, slot uint32, isDefault bool, rule, origin, comm string) SectionVerdict {
	// Origins is never nil, like exec's Verdict.Origins: [] means none.
	v := SectionVerdict{Section: section, Time: time.Now(), Verdict: api.ActionDeny, Mode: api.RuleEnforce, Rule: rule, Origins: []string{}, Generation: generation, Slot: slot, CgroupID: cgroup, PID: pid, Comm: comm}
	if mode == 1 {
		v.Mode, v.WouldDeny = api.RuleAudit, true
	}
	if origin != "" {
		v.Origins = append(v.Origins, origin)
	}
	switch {
	case rule == SectionRuleUnresolved:
		v.Reason = "path_resolution_error"
	case isDefault || rule == SectionRuleDefault:
		v.Reason = "section_default"
	case rule != "":
		v.Reason = "matching_rule"
	} // an unknown rule id claims no reason
	return v
}

// Attribute adds the policies of the judging slot. A rule name is
// "<namespace>/<policy>/<rule>" (see igbackend), so it names its policy. A
// default decision names no policy: it is attributed only when the slot has
// one policy.
func (v *SectionVerdict) Attribute(policies []CompiledPolicy) {
	v.PolicySet = nil
	for _, p := range policies {
		v.PolicySet = append(v.PolicySet, PolicyRevision{Policy: p.Identity, Revision: p.Revision})
	}
	var owner *CompiledPolicy
	if v.Reason == "matching_rule" {
		for i, p := range policies {
			if strings.HasPrefix(v.Rule, p.Identity.Namespace+"/"+p.Identity.Name+"/") {
				if owner != nil {
					owner = nil // two policies with the same name: ambiguous
					break
				}
				owner = &policies[i]
			}
		}
	} else if len(policies) == 1 {
		owner = &policies[0]
	}
	if owner == nil {
		return
	}
	v.Policy = owner.Identity
	if v.Reason == "matching_rule" {
		name := strings.TrimPrefix(v.Rule, owner.Identity.Namespace+"/"+owner.Identity.Name+"/")
		origin := ""
		if len(v.Origins) == 1 {
			origin = v.Origins[0]
		}
		v.Matches = []RuleMatch{{Policy: owner.Identity, Revision: owner.Revision, Name: name, Origin: origin, Origins: append([]string{}, v.Origins...), Action: api.ActionDeny, Mode: v.Mode}}
		v.MatchesComplete = len(policies) == 1
	}
}

// PrivilegeTarget is what a privilege verdict judged. Capability is -1 when
// the hook is not a capability check.
type PrivilegeTarget struct {
	Hook       string
	Syscall    string
	Capability int32
	Flags      uint64 // CLONE_NEW* flags of clone/unshare
	FsType     string
}

// NetworkTarget is the destination a network verdict judged.
type NetworkTarget struct {
	Hook    string
	Addr    string // "" when the address is unknown
	Port    uint16
	Proto   string
	Version uint8
}

// FileTarget is the file access a file verdict judged. Path is empty when the
// gadget could not resolve it.
type FileTarget struct {
	Hook      string
	Access    string
	Path      string
	FromImage bool
}

// sectionEvent is the part of the section events that implements
// utils.EnrichEvent. Like ExecVerdictEvent, an authorization is not an
// observation: these events implement no observation interface (OpenEvent,
// NetworkEvent, SyscallEvent) and absent fields are not fabricated.
type sectionEvent struct {
	Verdict SectionVerdict
	Binding Binding
	extra   any
}

func newSectionEvent(verdict SectionVerdict, binding Binding) sectionEvent {
	verdict.PolicySet = append([]PolicyRevision(nil), verdict.PolicySet...)
	verdict.Matches = append([]RuleMatch(nil), verdict.Matches...)
	for i := range verdict.Matches {
		verdict.Matches[i].Origins = append([]string{}, verdict.Matches[i].Origins...)
	}
	if verdict.Origins != nil {
		verdict.Origins = append([]string{}, verdict.Origins...)
	}
	binding.PodLabels = cloneLabels(binding.PodLabels)
	binding.NamespaceLabels = cloneLabels(binding.NamespaceLabels)
	return sectionEvent{Verdict: verdict, Binding: binding}
}

func (e *sectionEvent) GetContainerID() string { return e.Binding.ContainerID }
func (e *sectionEvent) GetNamespace() string   { return e.Binding.Namespace }
func (e *sectionEvent) GetPod() string         { return e.Binding.PodName }
func (e *sectionEvent) GetTimestamp() gadgettypes.Time {
	if e.Verdict.Time.IsZero() {
		return 0
	}
	return gadgettypes.Time(e.Verdict.Time.UnixNano())
}
func (*sectionEvent) HasDroppedEvents() bool            { return false } // loss is in ExporterStats and the kernel counters
func (*sectionEvent) Release()                          {}
func (e *sectionEvent) GetComm() string                 { return e.Verdict.Comm }
func (e *sectionEvent) GetContainer() string            { return e.Binding.ContainerName }
func (*sectionEvent) GetContainerImage() string         { return "" }
func (*sectionEvent) GetContainerImageDigest() string   { return "" }
func (*sectionEvent) GetError() int64                   { return 0 } // unavailable, not success
func (e *sectionEvent) GetExtra() any                   { return e.extra }
func (e *sectionEvent) SetExtra(extra any)              { e.extra = extra }
func (*sectionEvent) GetGid() *uint32                   { return nil }
func (*sectionEvent) GetHostNetwork() bool              { return false }
func (e *sectionEvent) GetMountNsID() uint64            { return e.Binding.MountNamespace }
func (*sectionEvent) GetPcomm() string                  { return "" }
func (e *sectionEvent) GetPID() uint32                  { return e.Verdict.PID }
func (e *sectionEvent) GetPID64() uint64                { return uint64(e.Verdict.PID) }
func (e *sectionEvent) GetPodLabels() map[string]string { return cloneLabels(e.Binding.PodLabels) }
func (*sectionEvent) GetPpid() uint32                   { return 0 }
func (*sectionEvent) GetUid() *uint32                   { return nil }
func (*sectionEvent) GetEcsClusterName() string         { return "" }
func (*sectionEvent) GetEcsClusterARN() string          { return "" }
func (*sectionEvent) GetEcsTaskARN() string             { return "" }
func (*sectionEvent) GetEcsTaskFamily() string          { return "" }
func (*sectionEvent) GetEcsTaskDefinitionARN() string   { return "" }
func (*sectionEvent) GetEcsServiceName() string         { return "" }
func (*sectionEvent) GetEcsContainerName() string       { return "" }
func (*sectionEvent) GetEcsContainerARN() string        { return "" }
func (*sectionEvent) GetEcsContainerInstance() string   { return "" }
func (*sectionEvent) GetEcsAvailabilityZone() string    { return "" }
func (*sectionEvent) GetEcsLaunchType() string          { return "" }
func (e *sectionEvent) FieldPresent(name string) bool {
	switch name {
	case "timestamp":
		return !e.Verdict.Time.IsZero()
	case "pid":
		return e.Verdict.PID != 0
	case "comm":
		return e.Verdict.Comm != ""
	case "mntns_id":
		return e.Binding.MountNamespace != 0
	default:
		return false
	}
}

// PrivilegeVerdictEvent is a privilege authorization (syscall, capability or
// mount check), not an observed syscall.
type PrivilegeVerdictEvent struct {
	sectionEvent
	Target PrivilegeTarget
}

// NetworkVerdictEvent is a network authorization. A denied connect did not
// happen: it is not a connection.
type NetworkVerdictEvent struct {
	sectionEvent
	Target NetworkTarget
}

// FileVerdictEvent is a file authorization, not an observed open.
type FileVerdictEvent struct {
	sectionEvent
	Target FileTarget
}

var (
	_ utils.EnrichEvent = (*PrivilegeVerdictEvent)(nil)
	_ utils.EnrichEvent = (*NetworkVerdictEvent)(nil)
	_ utils.EnrichEvent = (*FileVerdictEvent)(nil)
)

func NewPrivilegeVerdictEvent(v SectionVerdict, b Binding, t PrivilegeTarget) *PrivilegeVerdictEvent {
	return &PrivilegeVerdictEvent{newSectionEvent(v, b), t}
}
func NewNetworkVerdictEvent(v SectionVerdict, b Binding, t NetworkTarget) *NetworkVerdictEvent {
	return &NetworkVerdictEvent{newSectionEvent(v, b), t}
}
func NewFileVerdictEvent(v SectionVerdict, b Binding, t FileTarget) *FileVerdictEvent {
	return &FileVerdictEvent{newSectionEvent(v, b), t}
}

func (*PrivilegeVerdictEvent) GetEventType() utils.EventType {
	return utils.PrivilegeAuthorizationEventType
}
func (*NetworkVerdictEvent) GetEventType() utils.EventType {
	return utils.NetworkAuthorizationEventType
}
func (*FileVerdictEvent) GetEventType() utils.EventType { return utils.FileAuthorizationEventType }

func (e *PrivilegeVerdictEvent) snapshot() SectionEvent {
	c := NewPrivilegeVerdictEvent(e.Verdict, e.Binding, e.Target)
	c.extra = e.extra
	return c
}
func (e *NetworkVerdictEvent) snapshot() SectionEvent {
	c := NewNetworkVerdictEvent(e.Verdict, e.Binding, e.Target)
	c.extra = e.extra
	return c
}
func (e *FileVerdictEvent) snapshot() SectionEvent {
	c := NewFileVerdictEvent(e.Verdict, e.Binding, e.Target)
	c.extra = e.extra
	return c
}

// SectionEvent is one of PrivilegeVerdictEvent, NetworkVerdictEvent and
// FileVerdictEvent.
type SectionEvent interface {
	utils.EnrichEvent
	snapshot() SectionEvent
	section() *sectionEvent
}

func (e *sectionEvent) section() *sectionEvent { return e }
