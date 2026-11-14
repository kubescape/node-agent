//go:build sandbox_shared_qualification

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/utils"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
)

// VerdictLogPrefix starts every verdict line the qualification build writes
// to the agent log: the prefix, then one JSON object, then a newline.
const VerdictLogPrefix = "sandbox-verdict "

// VerdictLogMaxLine bounds a whole line (prefix, JSON and newline) to
// PIPE_BUF, so one Write never interleaves with the agent logger.
const VerdictLogMaxLine = 4096

// withVerdictLog registers the qualification verdict log receiver for exec
// authorization verdicts (QUALIFICATION ONLY: the e2e reads the agent log).
func withVerdictLog(receivers *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]) *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]] {
	if receivers == nil {
		receivers = maps.NewSafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]()
	}
	receiver := &verdictLogReceiver{out: os.Stdout}
	if set, ok := receivers.Load(utils.ExecAuthorizationEventType); ok && set != nil {
		set.Add(receiver)
	} else {
		receivers.Set(utils.ExecAuthorizationEventType, mapset.NewSet[containerwatcher.GenericEventReceiver](receiver))
	}
	return receivers
}

// verdictLogReceiver writes each verdict as one prefixed JSON line of at
// most VerdictLogMaxLine bytes, in a single Write. Argv is never logged (it
// may carry secrets): only its length.
type verdictLogReceiver struct {
	mu  sync.Mutex
	out io.Writer
	// failures counts verdicts not logged: marshal, oversize or Write errors.
	failures atomic.Uint64
}

// Failures reports the verdicts this receiver failed to log.
func (r *verdictLogReceiver) Failures() uint64 { return r.failures.Load() }

type verdictLogLine struct {
	WouldDeny       bool                           `json:"wouldDeny"`
	Deny            bool                           `json:"deny"`
	Verdict         api.Action                     `json:"verdict"`
	Mode            api.RuleMode                   `json:"mode"`
	Reason          string                         `json:"reason"`
	MatchesComplete bool                           `json:"matchesComplete"`
	TargetPath      string                         `json:"targetPath,omitempty"`
	ActorPath       string                         `json:"actorPath,omitempty"`
	FromImage       *bool                          `json:"fromImage,omitempty"`
	ArgvCount       int                            `json:"argvCount"`
	LoadEpoch       *uint64                        `json:"loadEpoch,omitempty"`
	TaskCookie      *uint64                        `json:"taskCookie,omitempty"`
	ExecID          *uint64                        `json:"execId,omitempty"`
	Pass            *uint32                        `json:"pass,omitempty"`
	ExecClass       *uint32                        `json:"execClass,omitempty"`
	Scope           *uint64                        `json:"scope,omitempty"`
	Uncertain       *bool                          `json:"uncertain,omitempty"`
	FactsUnknown    *uint32                        `json:"factsUnknown,omitempty"`
	PID             uint32                         `json:"pid"`
	ContainerID     string                         `json:"containerId"`
	CgroupID        uint64                         `json:"cgroupId"`
	PodUID          types.UID                      `json:"podUid"`
	Namespace       string                         `json:"namespace,omitempty"`
	Pod             string                         `json:"pod,omitempty"`
	Container       string                         `json:"container,omitempty"`
	Policy          sandboxpolicy.PolicyIdentity   `json:"policy"`
	Rule            string                         `json:"rule,omitempty"`
	Revision        string                         `json:"revision"`
	PolicySet       []sandboxpolicy.PolicyRevision `json:"policySet,omitempty"`
	Binding         verdictLogBinding              `json:"binding"`
	// Truncated reports that policySet was dropped or paths were cut to
	// keep the line within VerdictLogMaxLine.
	Truncated bool `json:"truncated,omitempty"`
}

type verdictLogBinding struct {
	PID            uint32 `json:"pid"`
	MountNamespace uint64 `json:"mountNamespace"`
	CgroupID       uint64 `json:"cgroupId"`
	Kind           string `json:"kind,omitempty"`
}

func (r *verdictLogReceiver) ReportEvent(_ utils.EventType, event utils.K8sEvent) {
	e, ok := event.(*sandboxpolicy.ExecVerdictEvent)
	if !ok || e == nil {
		return
	}
	v, b := e.Verdict, e.Binding
	line, err := boundedVerdictLine(verdictLogLine{
		WouldDeny: v.WouldDeny, Deny: v.Verdict == api.ActionDeny, Verdict: v.Verdict, Mode: v.Mode, Reason: v.Reason, MatchesComplete: v.MatchesComplete,
		TargetPath: v.TargetPath, ActorPath: v.ActorPath, FromImage: v.FromImage, ArgvCount: len(v.Argv),
		LoadEpoch: v.LoadEpoch, TaskCookie: v.TaskCookie, ExecID: v.ExecID, Pass: v.Pass, ExecClass: v.ExecClass, Scope: v.Scope, Uncertain: v.Uncertain, FactsUnknown: v.FactsUnknown,
		PID: v.PID, ContainerID: v.ContainerID, CgroupID: v.CgroupID, PodUID: v.PodUID, Namespace: b.Namespace, Pod: b.PodName, Container: b.ContainerName,
		Policy: v.Policy, Rule: v.Rule, Revision: v.Revision, PolicySet: v.PolicySet,
		Binding: verdictLogBinding{PID: v.BindingPID, MountNamespace: v.MountNamespace, CgroupID: b.CgroupID, Kind: b.Kind},
	})
	if err != nil {
		r.failures.Add(1)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.out.Write(line); err != nil {
		r.failures.Add(1)
	}
}

// boundedVerdictLine renders the whole line within VerdictLogMaxLine: it
// drops policySet first, then shortens the longer path, marking either.
func boundedVerdictLine(l verdictLogLine) ([]byte, error) {
	for {
		body, err := json.Marshal(l)
		if err != nil {
			return nil, err
		}
		over := len(VerdictLogPrefix) + len(body) + 1 - VerdictLogMaxLine
		if over <= 0 {
			buf := make([]byte, 0, len(VerdictLogPrefix)+len(body)+1)
			return append(append(append(buf, VerdictLogPrefix...), body...), '\n'), nil
		}
		switch {
		case !l.Truncated:
			// Account for the "truncated":true key itself.
			l.Truncated = true
		case l.PolicySet != nil:
			l.PolicySet = nil
		case l.TargetPath != "" || l.ActorPath != "":
			p := &l.TargetPath
			if len(l.ActorPath) > len(l.TargetPath) {
				p = &l.ActorPath
			}
			*p = truncateUTF8(*p, len(*p)-over)
		default:
			return nil, fmt.Errorf("verdict log line exceeds %d bytes after truncation", VerdictLogMaxLine)
		}
	}
}

// truncateUTF8 cuts s to at most n bytes on a rune boundary.
func truncateUTF8(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if n >= len(s) {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
