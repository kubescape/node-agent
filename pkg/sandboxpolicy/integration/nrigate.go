package integration

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/startgate"
	sandboxapi "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// nriSyncer is the backend's NRI sync state (sandboxpolicy.PodGate).
type nriSyncer interface {
	SetNRISynced(epoch uint64, proven map[uint64]bool)
	SetNRIDisconnected(epoch uint64)
}

// reclassifyBudget bounds one refresh's reclassification of the
// unbound marked pods (nriGate.reclassifyUnbound).
const reclassifyBudget = 5 * time.Second

// reclassifyBackoffMin and reclassifyBackoffMax bound the delay before a
// pod whose reclassification keeps failing at one sequence is tried again
// (nriGate.reclassifyUnbound; S5 review v4 V4-2).
const (
	reclassifyBackoffMin = 5 * time.Second
	reclassifyBackoffMax = 60 * time.Second
)

// nriGate is startgate.Gate on the service: the classification snapshot with
// the node's informers, the pod cgroup resolver and the pod gate (S5).
type nriGate struct {
	s        *Service
	gate     *podGate
	sync     nriSyncer
	procRoot string
	source   sandboxpolicy.PodSource
	resolve  func(podSandbox) (string, uint64, error)
	// alive reports whether a host PID's process exists (pidfd_open;
	// replaced in tests). restartSurvival reports whether restart survival
	// is on (RestartPinRoot; replaced in tests).
	alive           func(pid uint32) bool
	restartSurvival func() bool
	// now is the reclassification backoff's clock (replaced in tests).
	now func() time.Time

	// payloads are the NRI payloads of the marked pods, for the
	// reclassification of pods the API path never lists (S3 review v1
	// LOW 7). Released pods are dropped.
	mu       sync.Mutex
	payloads map[types.UID]nriPayload
}

type nriPayload struct {
	pod sandboxpolicy.NRIPod
	sb  startgate.Sandbox
	// seq is the sequence of the pod's last classification here (its mark,
	// or its last definitive reclassification).
	seq sandboxpolicy.Seq
	// fails counts the pod's failed marks or unmarks in a row at failSeq,
	// and retryAt is the earliest time of the next try (S5 review v4 V4-2).
	// A definitive outcome, an Unknown classification or a new mark clears
	// them.
	fails   int
	failSeq sandboxpolicy.Seq
	retryAt time.Time
}

var _ startgate.Gate = (*nriGate)(nil)

// EnableNRIStartGate turns the NRI start gate on. While the build constant
// is false (startgate.Buildable), it returns startgate.ErrNotBuildable and
// changes nothing: no gate, no goroutine, no socket. Otherwise it checks
// that node-agent shares the host PID namespace (HostPIDNamespace, by PID
// namespace inode), enables the pod gate (enableStartGate, which refuses
// once Start ran) and creates the plugin; Start runs it after the informers
// synced. Call it once, before Start, from the goroutine that calls Start
// (S3 review v3 R2).
func (s *Service) EnableNRIStartGate(ctx context.Context) error {
	if !startgate.Buildable() {
		return startgate.ErrNotBuildable
	}
	return s.enableNRIStartGate(ctx, linuxHandleSyscalls, filepath.Join(host.HostRoot, "proc"), filepath.Join(host.HostRoot, "var/run/nri/nri.sock"))
}

func (s *Service) enableNRIStartGate(ctx context.Context, sys handleSyscalls, procRoot, socket string) error {
	if s.Controller == nil || s.pods == nil || s.namespaces == nil {
		return errors.New("start gate: needs a privilege, network or file section (the pod informers)")
	}
	syncer, ok := s.backend.(nriSyncer)
	if !ok {
		return errors.New("start gate: the backend has no NRI sync state")
	}
	if err := HostPIDNamespace(procRoot); err != nil {
		return fmt.Errorf("start gate: %w", err)
	}
	n := s.newNRIGate(syncer, procRoot)
	plugin, err := startgate.NewPlugin(n, startgate.Options{
		SocketPath: socket,
		OnAlert: func(a startgate.Alert) {
			logger.L().Error("sandbox start gate alert", helpers.String("kind", a.Kind), helpers.String("key", a.Key), helpers.String("message", a.Message))
		},
		OnError: s.report,
	})
	if err != nil {
		return err
	}
	if err := s.enableStartGate(ctx, sys); err != nil {
		return err
	}
	n.gate = s.gate.Load()
	s.nriGate = n
	s.nriPlugin.Store(plugin)
	return nil
}

// newNRIGate builds the gate's sources from the service: the informers (the
// classification's Lookup), a bounded API GET for an informer miss (Fetch),
// and the pod cgroup resolver with the learned layout.
func (s *Service) newNRIGate(syncer nriSyncer, procRoot string) *nriGate {
	n := &nriGate{s: s, sync: syncer, procRoot: procRoot, payloads: map[types.UID]nriPayload{}, alive: pidAlive, restartSurvival: func() bool { return RestartPinRoot() != "" }, now: time.Now}
	pods := s.pods.Core().V1().Pods().Lister()
	namespaces := s.namespaces.Core().V1().Namespaces().Lister()
	n.source = sandboxpolicy.PodSource{
		InputEpoch: s.inputEpoch.Load,
		Lookup: func(namespace, name string) (sandboxpolicy.PodFacts, bool) {
			pod, err := pods.Pods(namespace).Get(name)
			if err != nil {
				return sandboxpolicy.PodFacts{}, false
			}
			ns, err := namespaces.Get(namespace)
			if err != nil {
				return sandboxpolicy.PodFacts{}, false
			}
			return podFacts(pod, ns.Labels), true
		},
		Fetch: func(ctx context.Context, namespace, name string) (sandboxpolicy.PodFacts, bool) {
			pod, err := s.options.Kubernetes.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return sandboxpolicy.PodFacts{}, false
			}
			ns, err := s.options.Kubernetes.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
			if err != nil {
				return sandboxpolicy.PodFacts{}, false
			}
			return podFacts(pod, ns.Labels), true
		},
	}
	n.resolve = func(pod podSandbox) (string, uint64, error) {
		layout, known, _, _, _ := s.podCgroupLayout()
		return newPodCgroupResolver(layout, known, procRoot, s.podCgroupID).resolve(pod)
	}
	return n
}

// podFacts is the classification's view of a pod: init, regular and
// ephemeral containers, by kind.
func podFacts(pod *corev1.Pod, namespaceLabels map[string]string) sandboxpolicy.PodFacts {
	f := sandboxpolicy.PodFacts{UID: pod.UID, Labels: pod.Labels, Annotations: pod.Annotations, NamespaceLabels: namespaceLabels}
	for _, c := range pod.Spec.InitContainers {
		f.Containers = append(f.Containers, sandboxpolicy.PodContainer{Name: c.Name, Kind: "init"})
	}
	for _, c := range pod.Spec.Containers {
		f.Containers = append(f.Containers, sandboxpolicy.PodContainer{Name: c.Name, Kind: "regular"})
	}
	for _, c := range pod.Spec.EphemeralContainers {
		f.Containers = append(f.Containers, sandboxpolicy.PodContainer{Name: c.Name, Kind: "ephemeral"})
	}
	return f
}

func (n *nriGate) Classify(ctx context.Context, req sandboxpolicy.ClassifyRequest) sandboxpolicy.PodClassification {
	return n.s.Controller.ClassifyPod(ctx, req, n.source)
}

func toGate(sb startgate.Sandbox) gateSandbox {
	return gateSandbox{UID: sb.UID, Namespace: sb.Namespace, Name: sb.Name, SandboxID: sb.ID, CgroupID: sb.CgroupID, CgroupPath: sb.CgroupPath}
}

// Sandbox resolves the payload's pod cgroup. A joined sandbox keeps the
// cgroup of its join (its pause process may be gone by RemovePodSandbox).
func (n *nriGate) Sandbox(pod *api.PodSandbox) (startgate.Sandbox, error) {
	sb := startgate.Sandbox{UID: types.UID(pod.GetUid()), Namespace: pod.GetNamespace(), Name: pod.GetName(), ID: pod.GetId(), Annotations: pod.GetAnnotations()}
	n.gate.podMu.Lock()
	if p := n.gate.pods[sb.UID]; p != nil && !p.released {
		if id := p.sandboxes[sb.ID]; id != 0 {
			sb.CgroupID = id
			if p.sandbox.CgroupID == id {
				sb.CgroupPath = p.sandbox.CgroupPath
			}
		}
	}
	n.gate.podMu.Unlock()
	if sb.CgroupID != 0 {
		return sb, nil
	}
	var qos corev1.PodQOSClass
	if p, err := n.s.pods.Core().V1().Pods().Lister().Pods(sb.Namespace).Get(sb.Name); err == nil && p.UID == sb.UID {
		qos = p.Status.QOSClass
	}
	path, id, err := n.resolve(podSandbox{UID: sb.UID, QoS: qos, CgroupParent: pod.GetLinux().GetCgroupParent(), PausePID: pod.GetPid()})
	if err != nil {
		return sb, fmt.Errorf("pod cgroup of sandbox %s: %w", sb.ID, err)
	}
	sb.CgroupID, sb.CgroupPath = id, path
	return sb, nil
}

func (n *nriGate) JoinAndMark(ctx context.Context, sb startgate.Sandbox, c sandboxpolicy.PodClassification, deadline time.Time) ([]sandboxpolicy.PodSectionResult, error) {
	res, err := n.gate.JoinAndMark(ctx, toGate(sb), c, deadline)
	if sb.CgroupID != 0 {
		n.mu.Lock()
		n.payloads[sb.UID] = nriPayload{pod: sandboxpolicy.NRIPod{UID: sb.UID, Namespace: sb.Namespace, Name: sb.Name, Annotations: sb.Annotations}, sb: sb, seq: c.Seq}
		n.mu.Unlock()
	}
	return res, err
}

func (n *nriGate) JoinUnselected(sb startgate.Sandbox) error {
	return n.gate.JoinUnselected(toGate(sb))
}

// PauseAlive reports whether the sandbox's pause process exists. A PID of
// 0 is not alive. The process is looked up in node-agent's PID namespace,
// which Registration checked is the host's.
func (n *nriGate) PauseAlive(pod *api.PodSandbox) bool {
	return pod.GetPid() != 0 && n.alive(pod.GetPid())
}

// pidAlive reports whether pid names a process: only ESRCH says it does
// not; any other answer (a permission error, a lack of pidfd support) says
// it may, which keeps the sandbox live (fail-closed).
func pidAlive(pid uint32) bool { return pidAliveWith(unix.PidfdOpen, pid) }

// pidAliveWith is pidAlive with the pidfd_open call injected (tests).
func pidAliveWith(pidfdOpen func(pid, flags int) (int, error), pid uint32) bool {
	fd, err := pidfdOpen(int(pid), 0)
	if err != nil {
		return !errors.Is(err, unix.ESRCH)
	}
	_ = unix.Close(fd)
	return true
}

// HoldsMark reports whether the gate holds a plan (a mark) for the pod.
func (n *nriGate) HoldsMark(uid types.UID) bool {
	n.gate.podMu.Lock()
	defer n.gate.podMu.Unlock()
	p := n.gate.pods[uid]
	return p != nil && !p.released && len(p.plan.Policies) > 0
}

// Unmark removes the mark the gate holds for the pod (an older
// classification's plan); nil when it holds none.
func (n *nriGate) Unmark(ctx context.Context, sb startgate.Sandbox, seq sandboxpolicy.Seq, deadline time.Time) error {
	if !n.HoldsMark(sb.UID) {
		return nil
	}
	if err := n.gate.Unmark(ctx, toGate(sb), seq, deadline); err != nil {
		return err
	}
	// Unselected and unmarked: nothing left to reclassify (S5 review v1 F6).
	n.mu.Lock()
	delete(n.payloads, sb.UID)
	n.mu.Unlock()
	return nil
}

func (n *nriGate) HoldUntilConfirmed(ctx context.Context, sb startgate.Sandbox, c sandboxpolicy.PodClassification, deadline time.Time) ([]sandboxpolicy.PodSectionConfirmation, error) {
	return n.gate.HoldUntilConfirmed(ctx, sb.UID, sb.ID, c, deadline)
}

func (n *nriGate) ReleaseSandbox(ctx context.Context, sb startgate.Sandbox, deadline time.Time) error {
	err := n.gate.ReleaseSandbox(ctx, toGate(sb), deadline)
	n.gate.podMu.Lock()
	p := n.gate.pods[sb.UID]
	released := p == nil || p.released
	n.gate.podMu.Unlock()
	if released {
		n.mu.Lock()
		delete(n.payloads, sb.UID)
		n.mu.Unlock()
	}
	return err
}

func (n *nriGate) SetNRISynced(epoch uint64, proven map[uint64]bool) {
	n.sync.SetNRISynced(epoch, proven)
}
func (n *nriGate) SetNRIDisconnected(epoch uint64) { n.sync.SetNRIDisconnected(epoch) }

// Registration is the node-level registration gate (design §6, v5): the
// pod gate is enabled (enableStartGate, with its cgroup-gone self-test),
// node-agent shares the host PID namespace, restart survival is on (a mark
// must outlive node-agent), and the informers synced once. The lifetime
// lock (L2) and the lift marker belong to S6, which adds them here; the
// build constant keeps the gate off until S9, after S6.
func (n *nriGate) Registration() error {
	if n.gate == nil || n.s.gate.Load() != n.gate {
		return errors.New("the pod gate is not enabled")
	}
	if err := HostPIDNamespace(n.procRoot); err != nil {
		return err
	}
	if !n.restartSurvival() {
		return errors.New("restart survival is off (no BPF filesystem)")
	}
	if !n.s.pods.Core().V1().Pods().Informer().HasSynced() || !n.s.namespaces.Core().V1().Namespaces().Informer().HasSynced() {
		return errors.New("the pod and namespace informers have not synced")
	}
	return nil
}

// reclassifyUnbound reclassifies the marked pods (those with a payload)
// that the refresh's bind does not send with a plan (bound):
//   - a pod the API never lists (S3 review v1 LOW 7): the refresh never
//     sends it at a newer sequence, so it would keep its last NRI plan;
//   - a pod the API lists with no plan (S5 review v2 N1): its policy was
//     deleted, set to off, or no longer matches its labels. BindPodsAt
//     keeps a start gate record that is missing from its list, so only
//     this unmarks it.
//
// A Selected pod is marked at the new classification, an Unselected one
// unmarked (which drops its payload), and an Unknown one keeps its mark
// (fail-closed). The refresh stays bounded (S5 review v1 F6): a pod is
// reclassified only when the refresh's sequence (seq: configSeq and input
// epoch) differs from its payload's memo, and the whole pass stops at
// reclassifyBudget. The memo advances only on a definitive outcome (S5
// review v3 V3-1, V3-2): an Unselected pod's unmark succeeded, or a
// Selected pod's mark succeeded in every section (or it has no section to
// mark). An Unknown classification (often a transient GET failure, or the
// budget expiring mid-GET), a write error, a section's mark failure, or a
// budget cut-off leaves the memo unchanged, so a later refresh tries the
// pod again. (For a failed section of a Selected pod, merge would also
// send the entry's new plan in the next BindPodsAt while the refresh
// sequence is not newer than the entry's; the retry here does not rely on
// it.)
//
// A pod whose mark or unmark keeps failing (a write error or a section's
// mark failure) at one sequence backs off (S5 review v4 V4-2): the first
// retry runs on the next refresh, later ones wait reclassifyBackoffMin,
// doubling up to reclassifyBackoffMax. This thins its error reports and
// writes while the sequence is stable; any sequence change (a policy
// change, or any container event on the node, which moves the input
// epoch) retries at once and restarts the schedule, so on a busy node the
// backoff rarely applies. The backoff never leaves a weaker mark in place
// for longer: a Selected pod's new plan is already in the pod gate
// (JoinAndMark stores it before it writes) and merge sends it in every
// BindPodsAt while the refresh sequence is not newer than the plan's; a
// failed unmark keeps an old mark of a pod no policy selects, which only
// over-enforces. An Unknown classification never backs off (S5b review v1
// B1): only its retry can strengthen an Audit-marked pod that the API path
// never lists once the API answers again, so it is retried on every
// refresh, bounded by reclassifyBudget, and clears any backoff. A
// definitive outcome or a new mark clears it too.
func (n *nriGate) reclassifyUnbound(ctx context.Context, bound map[types.UID]bool, seq sandboxpolicy.Seq) {
	n.mu.Lock()
	now := n.now()
	var todo []nriPayload
	for uid, p := range n.payloads {
		if bound[uid] || p.seq == seq {
			continue
		}
		if p.fails > 0 && p.failSeq == seq && now.Before(p.retryAt) {
			continue
		}
		todo = append(todo, p)
	}
	n.mu.Unlock()
	if len(todo) == 0 {
		return
	}
	deadline := time.Now().Add(reclassifyBudget)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	for _, p := range todo {
		if !time.Now().Before(deadline) {
			n.s.report(fmt.Errorf("start gate: reclassification stopped at its %v budget; the rest waits for the next refresh", reclassifyBudget))
			return
		}
		c := n.Classify(ctx, sandboxpolicy.ClassifyRequest{Pod: p.pod})
		var err error
		switch c.Class {
		case sandboxpolicy.PodSelected:
			if len(c.Sections) > 0 {
				var results []sandboxpolicy.PodSectionResult
				results, err = n.gate.JoinAndMark(ctx, toGate(p.sb), c, deadline)
				for _, r := range results {
					if err == nil && r.Err != nil && !errors.Is(r.Err, sandboxpolicy.ErrPolicyEntry) {
						err = fmt.Errorf("section %s: %w", r.Section, r.Err)
					}
				}
			}
		case sandboxpolicy.PodUnselected:
			err = n.Unmark(ctx, p.sb, c.Seq, deadline)
		default:
			// Unknown: the mark and the memo stay, and the pod is retried on
			// the next refresh, with no backoff (S5b review v1 B1).
			n.mu.Lock()
			if q, ok := n.payloads[p.pod.UID]; ok && q.sb.ID == p.sb.ID {
				q.fails, q.failSeq, q.retryAt = 0, sandboxpolicy.Seq{}, time.Time{}
				n.payloads[p.pod.UID] = q
			}
			n.mu.Unlock()
			continue
		}
		if err != nil && !errors.Is(err, errSandboxRemoved) {
			n.s.report(fmt.Errorf("start gate: reclassifying pod %s/%s: %w", p.pod.Namespace, p.pod.Name, err))
		}
		n.mu.Lock()
		if q, ok := n.payloads[p.pod.UID]; ok && q.sb.ID == p.sb.ID {
			if err == nil {
				q.seq, q.fails, q.failSeq, q.retryAt = seq, 0, sandboxpolicy.Seq{}, time.Time{}
			} else {
				if q.failSeq != seq {
					q.fails = 0
				}
				q.fails++
				q.failSeq = seq
				q.retryAt = n.now()
				// The shift is clamped to [0, 4] on its own, so no edit of the
				// guard can make it negative (S5b review v1 B7).
				if q.fails > 1 {
					q.retryAt = q.retryAt.Add(min(reclassifyBackoffMin<<min(max(q.fails-2, 0), 4), reclassifyBackoffMax))
				}
			}
			n.payloads[p.pod.UID] = q
		}
		n.mu.Unlock()
	}
}

// startGateStatus is the plugin's per-pod start-gate state (nil with the
// gate off).
func (s *Service) startGateStatus() []startgate.PodStatus {
	if p := s.nriPlugin.Load(); p != nil {
		return p.Status()
	}
	return nil
}

// startGateEvicted is the plugin's evicted status entries (0 with the gate
// off).
func (s *Service) startGateEvicted() uint64 {
	if p := s.nriPlugin.Load(); p != nil {
		return p.Evicted()
	}
	return 0
}

// startGateStatusLimit bounds the pods one condition lists.
const startGateStatusLimit = 20

// startGateStatusWriter adds the start-gate state of the pods a policy
// selects to its node status (S7): one condition, StartGatePods, False,
// listing pending, faulted, not start-gated and Audit-degraded pods. It
// comes from the plugin's own decisions, never from slot counters, and it
// claims no protection: Confirmed pods are not listed and the condition is
// never True. With the gate off (no states) the report passes unchanged.
type startGateStatusWriter struct {
	inner  sandboxpolicy.StatusWriter
	states func() []startgate.PodStatus
	// evicted counts the entries the plugin evicted when its status was
	// full (nil: none).
	evicted func() uint64
}

func (w startGateStatusWriter) WriteStatus(ctx context.Context, report *sandboxapi.SandboxPolicyNodeStatus) error {
	var states []startgate.PodStatus
	var evicted uint64
	if report != nil && report.Status != nil {
		if w.states != nil {
			for _, st := range w.states() {
				if slices.Contains(st.Policies, report.Spec.PolicyRef.UID) {
					states = append(states, st)
				}
			}
		}
		if w.evicted != nil {
			evicted = w.evicted()
		}
	}
	// The overflow notice goes on every policy's report, even one whose
	// entries were all evicted (S5 review v2 N5).
	if len(states) == 0 && evicted == 0 {
		return w.inner.WriteStatus(ctx, report)
	}
	out := report.DeepCopy()
	parts := make([]string, 0, min(len(states), startGateStatusLimit)+2)
	for i, st := range states {
		if i == startGateStatusLimit {
			parts = append(parts, fmt.Sprintf("and %d more", len(states)-i))
			break
		}
		parts = append(parts, fmt.Sprintf("%s/%s: %s (%s)", st.Namespace, st.Name, st.State, st.Reason))
	}
	if evicted > 0 {
		parts = append(parts, fmt.Sprintf("the node's start-gate status overflowed: %d older entries evicted, so pods of this policy may be missing from this list", evicted))
	}
	out.Status.Conditions = append(out.Status.Conditions, metav1.Condition{
		Type: "StartGatePods", Status: metav1.ConditionFalse, Reason: "StartGateStates",
		Message:            fmt.Sprintf("%d pods selected by this policy were not confirmed by the start gate at its last decision: %s", len(states), strings.Join(parts, "; ")),
		LastTransitionTime: out.Status.LastReported,
	})
	return w.inner.WriteStatus(ctx, out)
}
