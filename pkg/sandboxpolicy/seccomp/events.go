package seccomp

import (
	"context"
	"sort"
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/utils"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// Match is a rule of an applied policy that denies the logged syscall. The
// kernel record has no arguments, so a flag rule is a candidate, not a proof.
type Match struct {
	Policy sandboxpolicy.PolicyIdentity
	Rule   string
	Origin string
	Mode   api.RuleMode
	Flags  uint64
}

// Verdict is one seccomp decision for a SandboxPolicy profile. It is an
// authorization record, not a process or syscall observation.
type Verdict struct {
	Time        time.Time
	Namespace   string
	Pod         string
	Container   string
	ContainerID string
	PID         uint32
	Comm        string
	Syscall     string
	// Verdict is deny (enforced) or allow with WouldDeny (audited).
	Verdict   api.Action
	WouldDeny bool
	Mode      api.RuleMode
	// Revision identifies the injected profile.
	Revision string
	Matches  []Match
	// MatchesComplete is false when only flag rules match: the call may have been
	// logged for a flag the record cannot show.
	MatchesComplete bool
}

// VerdictEvent carries a Verdict through the third-party receiver hooks under
// utils.SyscallAuthorizationEventType.
type VerdictEvent struct{ Verdict Verdict }

func (e *VerdictEvent) GetContainerID() string         { return e.Verdict.ContainerID }
func (*VerdictEvent) GetEventType() utils.EventType    { return utils.SyscallAuthorizationEventType }
func (e *VerdictEvent) GetNamespace() string           { return e.Verdict.Namespace }
func (e *VerdictEvent) GetPod() string                 { return e.Verdict.Pod }
func (e *VerdictEvent) GetTimestamp() types.Time       { return types.Time(e.Verdict.Time.UnixNano()) }
func (*VerdictEvent) HasDroppedEvents() bool           { return false }
func (*VerdictEvent) Release()                         {}
func (e *VerdictEvent) GetSyscall() string             { return e.Verdict.Syscall }
func (e *VerdictEvent) GetPID() uint32                 { return e.Verdict.PID }
func (e *VerdictEvent) GetComm() string                { return e.Verdict.Comm }
func (e *VerdictEvent) GetContainer() string           { return e.Verdict.Container }
func (e *VerdictEvent) GetMatches() []Match            { return append([]Match(nil), e.Verdict.Matches...) }
func (e *VerdictEvent) GetVerdict() (api.Action, bool) { return e.Verdict.Verdict, e.Verdict.WouldDeny }
func (e *VerdictEvent) GetMode() api.RuleMode          { return e.Verdict.Mode }
func (e *VerdictEvent) GetProfileRevision() string     { return e.Verdict.Revision }

// VerdictReceiver is the typed receiver interface; EventReceiver also works.
type VerdictReceiver interface {
	ReportSyscallVerdict(context.Context, Verdict) error
}

// seccompActions maps the audit_seccomp code to an action of our profiles.
var seccompActions = map[string]specsAction{
	"SECCOMP_RET_ERRNO": actionDeny,
	"SECCOMP_RET_LOG":   actionLog,
}

type specsAction int

const (
	actionDeny specsAction = iota + 1
	actionLog
)

// seccompEvent is the part of utils.DatasourceEvent the layer reads.
type seccompEvent interface {
	utils.K8sEvent
	GetContainer() string
	GetPID() uint32
	GetComm() string
	GetSyscall() string
	GetSeccompCode() string
}

// ReportEvent receives audit_seccomp events. It keeps only decisions of
// profiles this layer injected, attributes them, and forwards a Verdict.
func (s *Service) ReportEvent(eventType utils.EventType, event utils.K8sEvent) {
	if eventType != utils.AuditSeccompEventType {
		return
	}
	e, ok := event.(seccompEvent)
	if !ok {
		return
	}
	act, ok := seccompActions[e.GetSeccompCode()]
	if !ok {
		return
	}
	// runc joins the container's filter during exec and retries a denied
	// open_tree with the old mount API; that is runtime setup, not the workload.
	// Matching only that syscall limits what a workload can hide by renaming.
	if e.GetSyscall() == "open_tree" && strings.HasPrefix(e.GetComm(), "runc:[") {
		return
	}
	verdict, ok := s.attribute(e, act)
	if !ok {
		return
	}
	s.dispatch(verdict)
}

// attribute uses the rules of the revision injected into the container, so the
// event path does no API calls or profile builds.
func (s *Service) attribute(e seccompEvent, act specsAction) (Verdict, bool) {
	syscall := e.GetSyscall()
	s.mu.Lock()
	entry, ok := s.containers[e.GetContainerID()]
	var c tracked
	var candidates []Match
	if ok {
		c = *entry
		candidates = append(candidates, entry.index[syscall]...)
	}
	s.mu.Unlock()
	if !ok || c.applied == "" || len(candidates) == 0 {
		// not a profile this layer injected, or a denial of the base profile
		return Verdict{}, false
	}
	wantMode := api.RuleEnforce
	if act == actionLog {
		wantMode = api.RuleAudit
	}
	v := Verdict{Time: time.Now(), Namespace: c.namespace, Pod: c.pod, Container: c.container, ContainerID: e.GetContainerID(),
		PID: e.GetPID(), Comm: e.GetComm(), Syscall: syscall, Mode: wantMode, Revision: c.applied}
	if act == actionDeny {
		v.Verdict = api.ActionDeny
	} else {
		v.Verdict, v.WouldDeny = api.ActionAllow, true
	}
	unconditional := false
	for _, m := range candidates {
		if m.Mode != wantMode {
			continue
		}
		v.Matches = append(v.Matches, m)
		unconditional = unconditional || m.Flags == 0
	}
	if len(v.Matches) == 0 {
		return Verdict{}, false
	}
	v.MatchesComplete = unconditional
	sort.SliceStable(v.Matches, func(i, j int) bool { return v.Matches[i].Rule < v.Matches[j].Rule })
	return v, true
}

func (s *Service) dispatch(v Verdict) {
	receivers := s.options.Receivers
	if receivers == nil {
		return
	}
	set, ok := receivers.Load(utils.SyscallAuthorizationEventType)
	if !ok {
		return
	}
	event := &VerdictEvent{Verdict: v}
	for receiver := range set.Iter() {
		switch r := receiver.(type) {
		case VerdictReceiver:
			if err := r.ReportSyscallVerdict(context.Background(), v); err != nil {
				s.options.OnError(err)
			}
		case containerwatcher.EventReceiver:
			r.ReportEvent(utils.SyscallAuthorizationEventType, event)
		}
	}
}

// Receivers is the third-party receiver registry type of node-agent.
type Receivers = *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]
