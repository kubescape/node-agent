package startgate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"k8s.io/apimachinery/pkg/types"
)

// Buildable reports whether this build may run the NRI start gate
// (startGateBuildable). A release build before S9 must report false
// (scripts/check-startgate-release.sh).
func Buildable() bool { return startGateBuildable }

// buildMarker is the binary-level record of the enablement constant, for
// the release gate (scripts/check-startgate-release.sh, S5 review v2 N3):
// every binary that links this package carries exactly one of the two
// strings below, chosen at compile time from startGateBuildable. The init
// below keeps it linked; -ldflags='-s -w' strips symbols, not string data.
var buildMarker = func() string {
	if startGateBuildable {
		return "kubescape-startgate-buildable=true"
	}
	return "kubescape-startgate-buildable=false"
}()

var buildMarkerSink atomic.Pointer[string]

func init() { buildMarkerSink.Store(&buildMarker) }

// ErrNotBuildable: the build constant is false; the plugin does not exist in
// this build and nothing dials NRI.
var ErrNotBuildable = errors.New("start gate: not buildable in this build (the enablement constant is false)")

// ErrSandboxRemoved: the gate already tombstoned the sandbox (its
// RemovePodSandbox arrived). A Gate returns it wrapped; a removed sandbox
// runs nothing and is never marked again.
var ErrSandboxRemoved = errors.New("start gate: the pod sandbox was removed")

const (
	// PluginName and PluginIndex name the plugin to the runtime
	// (containerd's required_plugins lists "<index>-<name>").
	PluginName  = "kubescape-start-gate"
	PluginIndex = "10"
	// ReturnMargin is the time every handler keeps for its reply before the
	// runtime's request timeout (and the handler context's deadline). A
	// handler that overruns the timeout is fatal at the runtime: its own
	// request context expires (containerd isFatalError: DeadlineExceeded),
	// it closes the plugin and lets that call through, even with
	// containerd's required_plugins naming this plugin (the plugin took part
	// in the request). required_plugins refuses the creates that follow
	// until the plugin reconnects (TestS5WireRegistrationRefusalOverrunReconnect,
	// TestS5WireRequiredPluginsAfterOverrun). The overrunning create is a
	// residual.
	ReturnMargin = 250 * time.Millisecond
	// syncParallel bounds the sandboxes Synchronize reports at a time.
	syncParallel = 8
	// reconnectMin and reconnectMax bound the pause between two
	// registration attempts.
	reconnectMin = time.Second
	reconnectMax = 30 * time.Second
	// alertInterval is the shortest time between two alerts of one kind and
	// key.
	alertInterval = time.Minute
	// statusLimit bounds the pods the status keeps; when it is full the
	// oldest entry is evicted and counted (Evicted).
	statusLimit = 4096
)

// Sandbox is a pod sandbox as the NRI payload names it, with its resolved
// pod cgroup (CgroupID 0: not resolved).
type Sandbox struct {
	UID        types.UID
	Namespace  string
	Name       string
	ID         string
	CgroupID   uint64
	CgroupPath string
	// Annotations are the payload's pod annotations.
	Annotations map[string]string
}

// Gate is the node side of the plugin: the classification, the pod gate
// (integration's podGate) and the backend's NRI sync state. Errors it
// returns may wrap anything; the plugin never passes their identity on.
type Gate interface {
	// Classify is sandboxpolicy.Controller.ClassifyPod with the node's pod
	// source. Every call is a fresh capture.
	Classify(ctx context.Context, req sandboxpolicy.ClassifyRequest) sandboxpolicy.PodClassification
	// Sandbox resolves the payload's pod cgroup (a joined sandbox keeps the
	// cgroup of its join). On an error the returned Sandbox still names the
	// pod and sandbox, with CgroupID 0.
	Sandbox(pod *api.PodSandbox) (Sandbox, error)
	JoinAndMark(ctx context.Context, sb Sandbox, c sandboxpolicy.PodClassification, deadline time.Time) ([]sandboxpolicy.PodSectionResult, error)
	JoinUnselected(sb Sandbox) error
	// PauseAlive reports whether the sandbox's pause process is alive
	// (true when that cannot be decided: fail-closed).
	PauseAlive(pod *api.PodSandbox) bool
	// HoldsMark reports whether the gate holds a mark (a plan) for the pod.
	// It takes no I/O and does not wait.
	HoldsMark(uid types.UID) bool
	// Unmark removes the mark the gate wrote for the pod at an older
	// classification; nil when the gate holds no mark for it.
	Unmark(ctx context.Context, sb Sandbox, seq sandboxpolicy.Seq, deadline time.Time) error
	HoldUntilConfirmed(ctx context.Context, sb Sandbox, c sandboxpolicy.PodClassification, deadline time.Time) ([]sandboxpolicy.PodSectionConfirmation, error)
	ReleaseSandbox(ctx context.Context, sb Sandbox, deadline time.Time) error
	SetNRISynced(epoch uint64, proven map[uint64]bool)
	SetNRIDisconnected(epoch uint64)
	// Registration checks the node-level preconditions (design §6): it runs
	// before every dial and again at Configure.
	Registration() error
}

// Alert kinds (owner decision D12: alerts for a broken policy and a section
// that is not ready; design v5.2: an exempt pod that a policy selects).
const (
	AlertBrokenPolicy      = "BrokenPolicy"
	AlertSectionNotReady   = "SectionNotReady"
	AlertExemptButSelected = "ExemptButSelected"
	AlertUnknownPod        = "UnknownPod"
	// AlertDeadSandbox: Synchronize listed a sandbox with no live pause
	// process and no container, reported as Unselected (owner ruling F1).
	AlertDeadSandbox = "DeadSandbox"
)

// Alert is one alert. Key is what it is about (a pod, a section).
type Alert struct {
	Kind, Key, Message string
}

// Options configure the plugin.
type Options struct {
	// SocketPath is the runtime's NRI socket (empty: the NRI default).
	SocketPath string
	// OnAlert receives the alerts, at most one per kind and key per
	// alertInterval (nil: dropped).
	OnAlert func(Alert)
	// OnError receives the run loop's diagnostics (nil: dropped).
	OnError func(error)
	// dial replaces the stub's dialer (tests only: unexported, so no
	// configuration can set it).
	dial func(string) (net.Conn, error)
}

// Pod start-gate states in the status (S7). None claims protection: a pod
// whose every section was Confirmed is not listed at all.
type PodState string

const (
	// StatePending: a section holds the pod's pending mark, not its policy
	// slot yet (a Strict mark denies; an Audit one allows).
	StatePending PodState = "Pending"
	// StateFaulted: the last decision refused the pod (a mark or a
	// confirmation failed, or an unsupported Strict shape).
	StateFaulted PodState = "Faulted"
	// StateNotStartGated: a Selected Audit pod with no section a pod mark
	// can hold (sources, exec only, or different sets per container).
	StateNotStartGated PodState = "NotStartGated"
	// StateAuditDegraded: an Audit section admitted on its pending mark
	// (owner decision D9(a)): the accounting is degraded until it binds.
	StateAuditDegraded PodState = "AuditDegraded"
)

// PodStatus is one pod's start-gate state.
type PodStatus struct {
	UID       types.UID
	Namespace string
	Name      string
	State     PodState
	Reason    string
	// Policies are the UIDs of the policies that select the pod.
	Policies []types.UID
	// seq orders the entries for eviction (oldest first).
	seq uint64
}

// Plugin is the NRI start gate plugin (design §6).
type Plugin struct {
	gate Gate
	opts Options
	// requestTimeout is the runtime's request timeout (Configure), in
	// nanoseconds; 0 before Configure.
	requestTimeout atomic.Int64
	// readTimeout reads the connected stub's request timeout (Run sets it
	// before each connection; tests set it directly).
	readTimeout atomic.Pointer[func() time.Duration]
	// epoch is the connection epoch: one per connection attempt.
	epoch atomic.Uint64

	alertMu sync.Mutex
	alerted map[string]time.Time

	statusMu  sync.Mutex
	status    map[types.UID]PodStatus
	statusSeq uint64
	evicted   uint64

	// registered: a Synchronize completed on the current connection (the
	// runtime registered the plugin); Run then resets its backoff.
	registered atomic.Bool
}

// NewPlugin returns the plugin, or ErrNotBuildable while the build constant
// is false. It dials nothing; Run does.
func NewPlugin(gate Gate, opts Options) (*Plugin, error) {
	if !startGateBuildable {
		return nil, ErrNotBuildable
	}
	if gate == nil {
		return nil, errors.New("start gate: no gate")
	}
	return newPlugin(gate, opts), nil
}

func newPlugin(gate Gate, opts Options) *Plugin {
	return &Plugin{gate: gate, opts: opts, alerted: map[string]time.Time{}, status: map[types.UID]PodStatus{}}
}

// Run registers the plugin with the runtime whenever the registration gate
// (Gate.Registration) holds, and again after every lost connection, until
// ctx ends. Each connection is a new epoch; its loss is recorded
// (Gate.SetNRIDisconnected), so the backend is not synced until the next
// connection's Synchronize completes.
func (p *Plugin) Run(ctx context.Context) error {
	if !startGateBuildable {
		return ErrNotBuildable
	}
	wait := time.Duration(0)
	for {
		p.registered.Store(false)
		if err := p.connect(ctx); err != nil && ctx.Err() == nil {
			p.report(err)
		}
		wait = nextWait(wait, p.registered.Load())
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// nextWait is the pause before the next registration attempt: it doubles
// from reconnectMin up to reconnectMax while attempts fail, and starts over
// after a connection that registered (S5 review v1 F8), so a node that
// loses a long-lived connection reconnects within reconnectMin.
func nextWait(last time.Duration, registered bool) time.Duration {
	if registered || last == 0 {
		return reconnectMin
	}
	return min(2*last, reconnectMax)
}

// connect runs one connection: the registration gate, then the stub until
// the connection closes.
func (p *Plugin) connect(ctx context.Context) error {
	if err := p.gate.Registration(); err != nil {
		return fmt.Errorf("start gate: not registering: %w", err)
	}
	epoch := p.epoch.Add(1)
	opts := []stub.Option{
		stub.WithPluginName(PluginName),
		stub.WithPluginIdx(PluginIndex),
		stub.WithOnClose(func() { p.gate.SetNRIDisconnected(epoch) }),
	}
	if p.opts.SocketPath != "" {
		opts = append(opts, stub.WithSocketPath(p.opts.SocketPath))
	}
	if p.opts.dial != nil {
		opts = append(opts, stub.WithDialer(p.opts.dial))
	}
	st, err := stub.New(p, opts...)
	if err != nil {
		p.gate.SetNRIDisconnected(epoch)
		return fmt.Errorf("start gate: %w", err)
	}
	read := st.RequestTimeout
	p.readTimeout.Store(&read)
	err = st.Run(ctx)
	// A connection that failed before the stub saw it close: its epoch
	// ends here too (a repeated call is harmless).
	p.gate.SetNRIDisconnected(epoch)
	if err != nil {
		return fmt.Errorf("start gate: NRI connection: %w", err)
	}
	return nil
}

func (p *Plugin) report(err error) {
	if p.opts.OnError != nil {
		p.opts.OnError(err)
	}
}

// reply is every handler's error, as text only. This is defence in depth,
// not the fatal-error guard: ttrpc turns any handler error into a status
// with code Unknown, which containerd's isFatalError never matches. The
// real fatal path is a handler that overruns the runtime's request timeout
// (the runtime's own context expires); every handler works to WorkDeadline
// with ReturnMargin to avoid it (S5 review v1 F4).
func reply(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(err.Error())
}

// Configure subscribes the start gate's events and reads the runtime's
// request timeout. It refuses (no registration) when the registration gate
// does not hold or the timeout leaves no work budget.
func (p *Plugin) Configure(_ context.Context, _, runtime, version string) (api.EventMask, error) {
	if err := p.gate.Registration(); err != nil {
		return 0, reply(fmt.Errorf("start gate: not registering: %w", err))
	}
	// The stub's default before a connection set it.
	timeout := stub.DefaultRequestTimeout
	if read := p.readTimeout.Load(); read != nil {
		timeout = (*read)()
	}
	if timeout <= 2*ReturnMargin {
		return 0, reply(fmt.Errorf("start gate: runtime %s %s request timeout %v leaves no work budget (margin %v)", runtime, version, timeout, ReturnMargin))
	}
	p.requestTimeout.Store(int64(timeout))
	var mask api.EventMask
	mask.Set(api.Event_RUN_POD_SANDBOX, api.Event_CREATE_CONTAINER, api.Event_START_CONTAINER, api.Event_REMOVE_POD_SANDBOX)
	return mask, nil
}

// deadline is the handler's work deadline (WorkDeadline with the runtime's
// request timeout and the handler context's own deadline).
func (p *Plugin) deadline(ctx context.Context, start time.Time) (time.Time, error) {
	parent, _ := ctx.Deadline()
	return WorkDeadline(start, time.Duration(p.requestTimeout.Load()), ReturnMargin, parent)
}

// classify classifies with ctx bounded by the work deadline (the bounded
// GET of an informer miss).
func (p *Plugin) classify(ctx context.Context, req sandboxpolicy.ClassifyRequest, deadline time.Time) sandboxpolicy.PodClassification {
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	return p.gate.Classify(ctx, req)
}

func nriPod(pod *api.PodSandbox) sandboxpolicy.NRIPod {
	return sandboxpolicy.NRIPod{UID: types.UID(pod.GetUid()), Namespace: pod.GetNamespace(), Name: pod.GetName(), Annotations: pod.GetAnnotations()}
}

func podName(pod *api.PodSandbox) string {
	return fmt.Sprintf("%s/%s (%s, sandbox %s)", pod.GetNamespace(), pod.GetName(), pod.GetUid(), pod.GetId())
}

// sandboxOutcome is what reporting one sandbox found.
type sandboxOutcome struct {
	err error
	// cgroup is the sandbox's resolved pod cgroup (0: not resolved);
	// proven: the pod is Unselected and the gate holds no mark for it.
	cgroup uint64
	proven bool
}

// stale reports whether a pod gate write was refused for a newer
// classification (ErrStaleSequence only).
func stale(results []sandboxpolicy.PodSectionResult, err error) bool {
	if err != nil {
		return sandboxpolicy.OnlyStale(err)
	}
	found := false
	for _, r := range results {
		if r.Err == nil {
			continue
		}
		if !sandboxpolicy.OnlyStale(r.Err) {
			return false
		}
		found = true
	}
	return found
}

// strictRefusal is owner decisions D1 and D2 for a Selected pod with a
// Strict policy: the shapes a pod binding cannot express, and exec, which is
// not start-gated before S8. nil when the pod has no Strict policy or none
// of these.
func strictRefusal(c sandboxpolicy.PodClassification) error {
	if !c.Strict {
		return nil
	}
	switch {
	case c.Shape&sandboxpolicy.ShapeSources != 0:
		return errors.New("a Strict pod with ContainerProfile sources is refused (D1)")
	case c.Shape&sandboxpolicy.ShapeDifferentSets != 0:
		return errors.New("a Strict pod whose containers get different policy sets is refused (D1)")
	case c.Shape&sandboxpolicy.ShapeContainerInPodCgroup != 0:
		return errors.New("a Strict pod with a container in the pod cgroup (or one the gate cannot place) is refused (D1)")
	case c.Exec:
		return errors.New("a Strict pod with exec rules is refused: exec is not start-gated before S8 (D2)")
	case len(c.Sections) == 0:
		return errors.New("a Strict pod with no section a pod mark can hold is refused (D1)")
	}
	return nil
}

// classLabel is "Strict" or "Audit".
func classLabel(strict bool) string {
	if strict {
		return "Strict"
	}
	return "Audit"
}

// markFailure judges JoinAndMark's results: every section of c must have
// one, nil or ErrPolicyEntry (an adopted entry as strict as the plan; it
// never admits by itself: the create still needs ConfirmPod). Any other
// result refuses the pod, Strict or Audit (owner decision D3(a)).
func (p *Plugin) markFailure(c sandboxpolicy.PodClassification, results []sandboxpolicy.PodSectionResult) error {
	var errs []error
	for _, name := range sortedSections(c) {
		sec := c.Sections[name]
		i := slices.IndexFunc(results, func(r sandboxpolicy.PodSectionResult) bool { return r.Section == name })
		switch {
		case i < 0:
			errs = append(errs, fmt.Errorf("%s section %s: no mark result", classLabel(sec.Strict), name))
		case results[i].Err == nil, errors.Is(results[i].Err, sandboxpolicy.ErrPolicyEntry):
		default:
			p.sectionAlert(name, results[i].Err.Error())
			if sec.Strict {
				errs = append(errs, fmt.Errorf("strict section %s: mark failed: %v", name, results[i].Err))
			} else {
				errs = append(errs, fmt.Errorf("audit section %s: mark failed or section unavailable, refused (D3a): %v", name, results[i].Err))
			}
		}
	}
	return errors.Join(errs...)
}

func sortedSections(c sandboxpolicy.PodClassification) []string {
	names := make([]string, 0, len(c.Sections))
	for name := range c.Sections {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// confirmDecision judges a create's (or start's) read-back against the
// handler's own classification:
//   - a Strict section needs Confirmed, or Pending with Strict (the pending
//     mark denies; the S2 contract); anything else refuses;
//   - an Audit section is admitted Confirmed, or Pending under owner
//     decision D9(a): ConfirmPod answers Pending only when the kernel entry
//     reads back as the plan's own (Audit) mark, so a read-back that still
//     shows Strict is Faulted and refused (the D9(a) residual);
//   - Faulted or Unavailable refuses, Strict or Audit (D3(a));
//   - a confirmation whose class differs from the classification's refuses.
//
// It returns the pod's state for the status ("" when every section is
// Confirmed).
func (p *Plugin) confirmDecision(c sandboxpolicy.PodClassification, confs []sandboxpolicy.PodSectionConfirmation, holdErr error) (PodState, error) {
	if len(confs) == 0 {
		if holdErr == nil {
			holdErr = errors.New("no confirmation")
		}
		return StateFaulted, fmt.Errorf("not confirmed: %v", holdErr)
	}
	var state PodState
	var errs []error
	for _, name := range sortedSections(c) {
		sec := c.Sections[name]
		i := slices.IndexFunc(confs, func(cf sandboxpolicy.PodSectionConfirmation) bool { return cf.Section == name })
		if i < 0 {
			errs = append(errs, fmt.Errorf("%s section %s: no confirmation", classLabel(sec.Strict), name))
			continue
		}
		cf := confs[i]
		switch {
		case cf.Strict != sec.Strict:
			errs = append(errs, fmt.Errorf("section %s: the backend's plan is %s, the classification's %s", name, classLabel(cf.Strict), classLabel(sec.Strict)))
		case cf.State == sandboxpolicy.PodSectionConfirmed:
		case cf.State == sandboxpolicy.PodSectionPending && sec.Strict:
			state = StatePending
		case cf.State == sandboxpolicy.PodSectionPending:
			if state == "" {
				state = StateAuditDegraded
			}
		case cf.State == sandboxpolicy.PodSectionUnavailable:
			p.sectionAlert(name, cf.Reason)
			errs = append(errs, fmt.Errorf("%s section %s is unavailable (D1/D3a): %s", classLabel(sec.Strict), name, cf.Reason))
		default:
			if strings.Contains(cf.Reason, "not ready") {
				p.sectionAlert(name, cf.Reason)
			}
			errs = append(errs, fmt.Errorf("%s section %s is not confirmed: %s", classLabel(sec.Strict), name, cf.Reason))
		}
	}
	if len(errs) > 0 {
		if holdErr != nil {
			errs = append(errs, holdErr)
		}
		return StateFaulted, errors.Join(errs...)
	}
	return state, nil
}

// unknown alerts on an Unknown classification and returns its error.
func (p *Plugin) unknown(pod *api.PodSandbox, c sandboxpolicy.PodClassification) error {
	kind := AlertUnknownPod
	for _, broken := range []string{"has an error", "configuration unavailable", "does not compile", "class error"} {
		if strings.Contains(c.Reason, broken) {
			kind = AlertBrokenPolicy
		}
	}
	p.alert(kind, string(pod.GetUid()), c.Reason)
	return fmt.Errorf("pod %s cannot be classified: %s", podName(pod), c.Reason)
}

// reportSandbox reports one sandbox to the gate (RunPodSandbox and
// Synchronize; S3 review v1 #1): JoinAndMark for a Selected pod with
// sections, JoinUnselected for every other one (Unselected, exempt, Unknown
// or refused: the sandbox still counts for "the pod's last sandbox"). A
// mark refused as stale is retried once with a fresh classification.
//
// dead (Synchronize only): the sandbox has no live pause process and no
// container in Synchronize's list, so it runs nothing and nothing can be
// created in it (the kubelet makes a new sandbox). Owner ruling (batch 6,
// F1): it joins as Unselected, with an alert, whatever its class. It is
// never proven: its cgroup, when the gate knows it, stays held.
func (p *Plugin) reportSandbox(ctx context.Context, pod *api.PodSandbox, deadline time.Time, dead bool) sandboxOutcome {
	sb, sbErr := p.gate.Sandbox(pod)
	out := sandboxOutcome{cgroup: sb.CgroupID}
	if dead {
		if err := p.gate.JoinUnselected(sb); err != nil && !errors.Is(err, ErrSandboxRemoved) {
			out.err = fmt.Errorf("pod %s: dead sandbox: %v", podName(pod), err)
			return out
		}
		p.alert(AlertDeadSandbox, pod.GetId(), fmt.Sprintf("sandbox %s of pod %s has no live pause process and no container: reported as Unselected", pod.GetId(), podName(pod)))
		return out
	}
	if sbErr != nil {
		out.cgroup = 0
	}
	req := sandboxpolicy.ClassifyRequest{Pod: nriPod(pod)}
	c := p.classify(ctx, req, deadline)
	for attempt := 0; ; attempt++ {
		retry := attempt == 0
		switch c.Class {
		case sandboxpolicy.PodUnselected:
			if c.ExemptButSelected {
				p.alert(AlertExemptButSelected, string(sb.UID), c.Reason)
			}
			if err := p.gate.JoinUnselected(sb); err != nil {
				if errors.Is(err, ErrSandboxRemoved) {
					// Its RemovePodSandbox arrived: it runs nothing (S5
					// review v1 F5). Not proven: its cgroup stays held.
					return out
				}
				out.err = fmt.Errorf("pod %s: %v", podName(pod), err)
				return out
			}
			if err := p.gate.Unmark(ctx, sb, c.Seq, deadline); err != nil {
				if retry && sandboxpolicy.OnlyStale(err) {
					c = p.classify(ctx, req, deadline)
					continue
				}
				out.err = fmt.Errorf("pod %s is Unselected; removing its mark failed: %v", podName(pod), err)
				return out
			}
			p.forget(sb.UID)
			out.proven = out.cgroup != 0
			return out
		case sandboxpolicy.PodSelected:
		default:
			_ = p.gate.JoinUnselected(sb)
			out.err = p.unknown(pod, c)
			return out
		}
		if err := strictRefusal(c); err != nil {
			_ = p.gate.JoinUnselected(sb)
			p.setStatus(pod, c, StateFaulted, err.Error())
			out.err = fmt.Errorf("pod %s: %v", podName(pod), err)
			return out
		}
		if len(c.Sections) == 0 {
			// Audit only (a Strict one was refused above): nothing a pod
			// mark holds; Audit never blocks.
			if err := p.gate.JoinUnselected(sb); err != nil {
				out.err = fmt.Errorf("pod %s: %v", podName(pod), err)
				return out
			}
			p.setStatus(pod, c, StateNotStartGated, "no section a pod mark can hold")
			return out
		}
		results, err := p.gate.JoinAndMark(ctx, sb, c, deadline)
		if retry && stale(results, err) {
			c = p.classify(ctx, req, deadline)
			continue
		}
		if err == nil {
			err = p.markFailure(c, results)
		}
		if err == nil && sbErr != nil {
			err = sbErr
		}
		if err != nil {
			p.setStatus(pod, c, StateFaulted, err.Error())
			out.err = fmt.Errorf("%s pod %s: not marked: %v", classLabel(c.Strict), podName(pod), err)
			return out
		}
		// Marked: the create decides the pod's state (S5 review v1 F7: a
		// Pending recorded here was never cleared).
		p.forget(sb.UID)
		return out
	}
}

// Synchronize reports every sandbox the runtime lists (Ready and NotReady)
// to the gate and marks the Selected ones. It completes only when every
// sandbox was classified and every Selected one marked (owner decision
// D10(a): one Unknown or unmarkable pod fails it, so the plugin does not
// register and the node refuses creates until it is fixed). Only then does
// it record the epoch as synced, with proven: the cgroups of Unselected
// pods the gate holds no mark for (never one a Selected or Unknown sandbox
// also names).
func (p *Plugin) Synchronize(ctx context.Context, pods []*api.PodSandbox, containers []*api.Container) ([]*api.ContainerUpdate, error) {
	err := p.synchronize(ctx, p.epoch.Load(), pods, containers)
	if err == nil {
		p.registered.Store(true)
	}
	return nil, reply(err)
}

func (p *Plugin) synchronize(ctx context.Context, epoch uint64, pods []*api.PodSandbox, containers []*api.Container) error {
	deadline, err := p.deadline(ctx, time.Now())
	if err != nil {
		return fmt.Errorf("start gate: Synchronize: %v", err)
	}
	// The runtime lists every container that has not exited (containerd
	// ListContainers drops EXITED and UNKNOWN): any of them keeps its
	// sandbox live.
	withContainer := map[string]bool{}
	for _, ctr := range containers {
		withContainer[ctr.GetPodSandboxId()] = true
	}
	outcomes := make([]sandboxOutcome, len(pods))
	sem := make(chan struct{}, syncParallel)
	var wg sync.WaitGroup
	for i, pod := range pods {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			dead := !withContainer[pod.GetId()] && !p.gate.PauseAlive(pod)
			outcomes[i] = p.reportSandbox(ctx, pod, deadline, dead)
		}()
	}
	wg.Wait()
	proven := map[uint64]bool{}
	held := map[uint64]bool{}
	var errs []error
	for _, o := range outcomes {
		if o.err != nil {
			errs = append(errs, o.err)
		}
		if o.cgroup == 0 {
			continue
		}
		if o.proven {
			proven[o.cgroup] = true
		} else {
			held[o.cgroup] = true
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("start gate: Synchronize failed for %d of %d pod sandboxes (D10a, not registering): %v", len(errs), len(pods), errors.Join(errs...))
	}
	if !time.Now().Before(deadline) {
		return errors.New("start gate: Synchronize did not complete before its work deadline")
	}
	for id := range held {
		delete(proven, id)
	}
	p.gate.SetNRISynced(epoch, proven)
	// The status keeps only the pods the runtime still lists (F7).
	listed := make(map[types.UID]bool, len(pods))
	for _, pod := range pods {
		listed[types.UID(pod.GetUid())] = true
	}
	p.statusMu.Lock()
	for uid := range p.status {
		if !listed[uid] {
			delete(p.status, uid)
		}
	}
	p.statusMu.Unlock()
	return nil
}

// RunPodSandbox reports the new sandbox and marks a Selected pod:
//   - Unselected or exempt: OK (ExemptButSelected alerts);
//   - Unknown: a non-fatal error (the runtime fails the sandbox);
//   - Selected Strict with a D1 shape or exec (D2): refused;
//   - Selected: the mark; a failure refuses, Strict or Audit (D3(a)).
func (p *Plugin) RunPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	deadline, err := p.deadline(ctx, time.Now())
	if err != nil {
		return reply(fmt.Errorf("start gate: RunPodSandbox %s: %v", podName(pod), err))
	}
	return reply(p.reportSandbox(ctx, pod, deadline, false).err)
}

// CreateContainer is the create hold: it reclassifies for the container,
// marks again (a class change since RunPodSandbox), and holds until the
// sections confirm or the deadline passes (confirmDecision).
func (p *Plugin) CreateContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	return nil, nil, reply(p.admitContainer(ctx, pod, ctr, true))
}

// StartContainer confirms again, with the same rules as CreateContainer
// (no new mark).
func (p *Plugin) StartContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	return reply(p.admitContainer(ctx, pod, ctr, false))
}

// RemovePodSandbox tombstones the sandbox and releases the pod when it was
// its last joined sandbox (podGate.ReleaseSandbox).
func (p *Plugin) RemovePodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	deadline, err := p.deadline(ctx, time.Now())
	if err != nil {
		return reply(fmt.Errorf("start gate: RemovePodSandbox %s: %v", podName(pod), err))
	}
	sb, _ := p.gate.Sandbox(pod)
	// The pod's status goes with its sandbox, whatever the release answers
	// (F7): S2 retries a failed unbind on its own.
	p.forget(sb.UID)
	if err := p.gate.ReleaseSandbox(ctx, sb, deadline); err != nil {
		return reply(fmt.Errorf("start gate: RemovePodSandbox %s: %v", podName(pod), err))
	}
	return nil
}

// ContainerInPodCgroup reports whether the container would not get a cgroup
// of its own under the pod cgroup (the D1 shape "container in the pod
// cgroup"). A path the gate cannot place under the pod cgroup counts as in
// it: fail-closed, a Strict pod is refused.
//   - systemd: the container's CgroupsPath is "<slice>:<prefix>:<name>"; it
//     has its own scope when <slice> is the pod's CgroupParent and
//     <prefix>, <name> are set.
//   - cgroupfs: the container's CgroupsPath is a path; it has its own
//     cgroup when its parent directory is the pod's CgroupParent.
func ContainerInPodCgroup(pod *api.PodSandbox, ctr *api.Container) bool {
	parent := pod.GetLinux().GetCgroupParent()
	cpath := ctr.GetLinux().GetCgroupsPath()
	if parent == "" || cpath == "" {
		return true
	}
	if strings.HasPrefix(parent, "/") {
		return path.Clean(cpath) != cpath || path.Dir(cpath) != parent || cpath == parent
	}
	parts := strings.Split(cpath, ":")
	return len(parts) != 3 || parts[0] != parent || parts[1] == "" || parts[2] == ""
}

// admitContainer is CreateContainer (mark set) and StartContainer.
//   - Unknown: refused.
//   - Unselected: a mark the gate wrote at an older classification is
//     removed, then OK.
//   - Exempt: see exemptContainer.
//   - Selected: D1/D2 refusals for Strict; an Audit pod with no section is
//     not start-gated (OK); otherwise mark (create only), hold and
//     confirmDecision.
func (p *Plugin) admitContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container, mark bool) error {
	req := sandboxpolicy.ClassifyRequest{Pod: nriPod(pod), Container: ctr.GetName(), ContainerInPodCgroup: ContainerInPodCgroup(pod, ctr)}
	deadline, err := p.deadline(ctx, time.Now())
	if err != nil {
		return p.noWorkBudget(ctx, pod, ctr, req, err)
	}
	c := p.classify(ctx, req, deadline)
	sb, sbErr := p.gate.Sandbox(pod)
	for attempt := 0; ; attempt++ {
		retry := attempt == 0
		switch c.Class {
		case sandboxpolicy.PodUnselected:
			if c.ExemptButSelected {
				p.alert(AlertExemptButSelected, string(sb.UID), c.Reason)
			}
			if c.Exempt {
				return p.exemptContainer(ctx, pod, ctr, deadline)
			}
			if err := p.gate.Unmark(ctx, sb, c.Seq, deadline); err != nil {
				if retry && sandboxpolicy.OnlyStale(err) {
					c = p.classify(ctx, req, deadline)
					continue
				}
				return fmt.Errorf("start gate: container %s of %s: the pod is Unselected; removing its mark failed: %v", ctr.GetName(), podName(pod), err)
			}
			p.forget(sb.UID)
			return nil
		case sandboxpolicy.PodSelected:
		default:
			return fmt.Errorf("start gate: container %s: %v", ctr.GetName(), p.unknown(pod, c))
		}
		if err := strictRefusal(c); err != nil {
			p.setStatus(pod, c, StateFaulted, err.Error())
			return fmt.Errorf("start gate: container %s of %s: %v", ctr.GetName(), podName(pod), err)
		}
		if len(c.Sections) == 0 {
			p.setStatus(pod, c, StateNotStartGated, "no section a pod mark can hold")
			return nil
		}
		if mark {
			results, err := p.gate.JoinAndMark(ctx, sb, c, deadline)
			if retry && stale(results, err) {
				c = p.classify(ctx, req, deadline)
				continue
			}
			if err == nil {
				err = p.markFailure(c, results)
			}
			if err == nil && sbErr != nil {
				err = sbErr
			}
			if err != nil {
				p.setStatus(pod, c, StateFaulted, err.Error())
				return fmt.Errorf("start gate: container %s of %s pod %s: not marked: %v", ctr.GetName(), classLabel(c.Strict), podName(pod), err)
			}
		}
		confs, holdErr := p.gate.HoldUntilConfirmed(ctx, sb, c, deadline)
		state, err := p.confirmDecision(c, confs, holdErr)
		if err != nil {
			p.setStatus(pod, c, StateFaulted, err.Error())
			return fmt.Errorf("start gate: container %s of %s pod %s refused: %v", ctr.GetName(), classLabel(c.Strict), podName(pod), err)
		}
		if state == "" {
			p.forget(sb.UID)
		} else {
			p.setStatus(pod, c, state, "admitted on a pending mark")
		}
		return nil
	}
}

// noWorkBudget decides a create or start whose timing inputs leave no work
// budget (WorkDeadline's error). Lead ruling under owner decision D3(a)
// (S5 review v2 N2): with no budget there is no mark and no read-back, so
// a Selected pod is refused, Audit as well as Strict (D3(a) refuses an Audit
// pod whose mark failed; D9(a) admits Audit only on a read-back), as are
// Unknown and exempt containers. Only a plain Unselected container of a
// pod the gate holds no mark for is admitted: nothing would judge it. The
// pod is classified from the caches only (an already canceled context: no
// GET, no wait). RunPodSandbox refuses on this error too.
func (p *Plugin) noWorkBudget(ctx context.Context, pod *api.PodSandbox, ctr *api.Container, req sandboxpolicy.ClassifyRequest, timing error) error {
	cached, cancel := context.WithCancel(context.WithoutCancel(ctx))
	cancel()
	c := p.gate.Classify(cached, req)
	if c.Class == sandboxpolicy.PodUnselected && !c.Exempt && !p.gate.HoldsMark(types.UID(pod.GetUid())) {
		return nil
	}
	if c.Class == sandboxpolicy.PodSelected {
		p.setStatus(pod, c, StateFaulted, "no work budget: refused (D3a)")
	}
	return fmt.Errorf("start gate: container %s of %s: no work budget, refused (D3a): %v", ctr.GetName(), podName(pod), timing)
}

// exemptContainer decides a container the exemption annotation exempts
// (S4 review v1 7(a)). The container's cgroup is created under the pod
// cgroup, so the pod's mark or binding judges it whatever its exemption:
// the exemption cannot lift a Strict pod's mark for one container before
// S8's container binding. Decision (fail-closed): the pod is classified
// without the container; a Strict Selected pod refuses the exempt container
// (instead of admitting it to run under EPERM or under policies it is
// exempt from), an Unknown pod refuses it, and an Unselected, exempt or
// Audit-only pod admits it (Audit never blocks; its tasks are counted under
// the pod's Audit mark).
func (p *Plugin) exemptContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container, deadline time.Time) error {
	c := p.classify(ctx, sandboxpolicy.ClassifyRequest{Pod: nriPod(pod)}, deadline)
	switch {
	case c.Class == sandboxpolicy.PodUnselected:
		return nil
	case c.Class == sandboxpolicy.PodSelected && !c.Strict:
		return nil
	case c.Class == sandboxpolicy.PodSelected:
		return fmt.Errorf("start gate: container %s of %s is exempt, but its pod is Strict: the pod's mark would judge it; refused until container binding (S8)", ctr.GetName(), podName(pod))
	}
	return fmt.Errorf("start gate: exempt container %s: %v", ctr.GetName(), p.unknown(pod, c))
}

// alert sends an alert unless one of the same kind and key went out within
// alertInterval.
func (p *Plugin) alert(kind, key, message string) {
	if p.opts.OnAlert == nil {
		return
	}
	id := kind + "/" + key
	now := time.Now()
	p.alertMu.Lock()
	if last, ok := p.alerted[id]; ok && now.Sub(last) < alertInterval {
		p.alertMu.Unlock()
		return
	}
	p.alerted[id] = now
	for k, at := range p.alerted {
		if now.Sub(at) >= alertInterval {
			delete(p.alerted, k)
		}
	}
	p.alertMu.Unlock()
	p.opts.OnAlert(Alert{Kind: kind, Key: key, Message: message})
}

func (p *Plugin) sectionAlert(section, reason string) {
	p.alert(AlertSectionNotReady, section, fmt.Sprintf("section %s: %s", section, reason))
}

// setStatus records the pod's start-gate state from the handler's own
// decision (never from slot counters).
func (p *Plugin) setStatus(pod *api.PodSandbox, c sandboxpolicy.PodClassification, state PodState, reason string) {
	uid := types.UID(pod.GetUid())
	policies := make([]types.UID, 0, len(c.Policies))
	for _, id := range c.Policies {
		policies = append(policies, id.UID)
	}
	p.statusMu.Lock()
	defer p.statusMu.Unlock()
	if _, ok := p.status[uid]; !ok && len(p.status) >= statusLimit {
		// Full: the oldest entry goes, and is counted (S5 review v1 F7);
		// a new pod is never dropped silently.
		var oldest types.UID
		first := true
		for k, v := range p.status {
			if first || v.seq < p.status[oldest].seq {
				oldest, first = k, false
			}
		}
		delete(p.status, oldest)
		p.evicted++
	}
	p.statusSeq++
	p.status[uid] = PodStatus{UID: uid, Namespace: pod.GetNamespace(), Name: pod.GetName(), State: state, Reason: reason, Policies: policies, seq: p.statusSeq}
}

// Evicted counts the status entries evicted because the status was full.
func (p *Plugin) Evicted() uint64 {
	p.statusMu.Lock()
	defer p.statusMu.Unlock()
	return p.evicted
}

func (p *Plugin) forget(uid types.UID) {
	p.statusMu.Lock()
	delete(p.status, uid)
	p.statusMu.Unlock()
}

// Status returns the pods with a start-gate state, sorted by namespace and
// name. A pod whose every section was Confirmed is not listed.
func (p *Plugin) Status() []PodStatus {
	p.statusMu.Lock()
	out := make([]PodStatus, 0, len(p.status))
	for _, s := range p.status {
		s.Policies = slices.Clone(s.Policies)
		out = append(out, s)
	}
	p.statusMu.Unlock()
	slices.SortFunc(out, func(a, b PodStatus) int {
		return strings.Compare(a.Namespace+"/"+a.Name+"/"+string(a.UID), b.Namespace+"/"+b.Name+"/"+string(b.UID))
	})
	return out
}
