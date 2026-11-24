// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package httpgateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Paths of the gateway's health listener. Each is answered by a different
// process, so one of them dying does not hide the others.
const (
	HealthPathEnvoy     = "/healthz/envoy"
	HealthPathProcessor = "/healthz/processor"
	HealthPathCerts     = "/healthz/certs"
)

// Health is the result of one round of probes.
type Health struct {
	// Envoy and Processor: the process answered 200.
	Envoy, Processor bool
	// CertsAnswered: the node controller answered; the fields below are set
	// only then.
	CertsAnswered bool
	// CanDecrypt is false when the node's intermediate CA is about to run out
	// with no renewal.
	CanDecrypt bool
	// DecryptValidUntil is the earliest expiry among the certificates the
	// gateway serves with.
	DecryptValidUntil time.Time
	// RootFingerprint is the root CA the node's intermediate chains to.
	RootFingerprint string
}

// Prober asks the gateway for its health. The context carries the timeout.
type Prober interface {
	Probe(ctx context.Context) Health
}

// HTTPProber probes the health listener at Base, for example
// "http://192.168.1.10:18444".
type HTTPProber struct {
	Base   string
	Client *http.Client
}

// Probe runs the three probes at once.
func (p HTTPProber) Probe(ctx context.Context) Health {
	client := p.Client
	if client == nil {
		client = http.DefaultClient
	}
	get := func(path string) ([]byte, bool) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Base+path, nil)
		if err != nil {
			return nil, false
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, false
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return body, err == nil && resp.StatusCode == http.StatusOK
	}
	var h Health
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); _, h.Envoy = get(HealthPathEnvoy) }()
	go func() { defer wg.Done(); _, h.Processor = get(HealthPathProcessor) }()
	go func() {
		defer wg.Done()
		body, ok := get(HealthPathCerts)
		if !ok {
			return
		}
		var certs struct {
			CanDecrypt        bool      `json:"canDecrypt"`
			DecryptValidUntil time.Time `json:"decryptValidUntil"`
			RootFingerprint   string    `json:"rootFingerprint"`
		}
		if json.Unmarshal(body, &certs) != nil {
			return
		}
		h.CertsAnswered, h.CanDecrypt = true, certs.CanDecrypt
		h.DecryptValidUntil, h.RootFingerprint = certs.DecryptValidUntil, normalizeFingerprint(certs.RootFingerprint)
	}()
	wg.Wait()
	return h
}

// GateConfig holds the gate's timers.
type GateConfig struct {
	// Interval between probe rounds, and Timeout of one round.
	Interval, Timeout time.Duration
	// HealthyFor is how long every signal must stay healthy before a
	// fail-open window ends.
	HealthyFor time.Duration
	// CertMargin: the gate applies the posture when the last known
	// certificate expiry is closer than this.
	CertMargin time.Duration
}

// DefaultGateConfig returns the default timers.
func DefaultGateConfig() GateConfig {
	return GateConfig{Interval: 500 * time.Millisecond, Timeout: 400 * time.Millisecond, HealthyFor: 10 * time.Second, CertMargin: 5 * time.Minute}
}

// GateMaps is what the gate needs from the pinned maps.
type GateMaps interface {
	Bindings() (map[uint64]Binding, error)
	SetBinding(cgroup uint64, b Binding) error
}

// Killer closes a pod's direct connections to AI addresses. It returns
// ErrKillUnsupported when the kernel cannot, and ErrKillSkipped when it must
// not (a pod that shares the node's network namespace).
type Killer interface {
	Kill(ctx context.Context, pod PodState) (KillResult, error)
}

// ErrKillUnsupported means the kernel has no bpf_sock_destroy (before Linux
// 6.5): connections opened before the bind cannot be closed from here.
var ErrKillUnsupported = errors.New("httpgateway: this kernel cannot destroy sockets from eBPF (needs Linux 6.5)")

// KillResult counts one run of the socket kill.
type KillResult struct {
	Seen, Destroyed uint64
}

// ErrKillSkipped means the kill did not run for a pod because it could not be
// limited to that pod's sockets.
var ErrKillSkipped = errors.New("httpgateway: socket kill skipped for this pod")

// GateStatus is the gate as the node status reports it.
type GateStatus struct {
	// State is the node-wide state. In GateFailingOpen and GateRecovering,
	// pods with posture allow are not covered; pods with posture deny keep
	// redirecting and their AI connections fail.
	State Gate
	// Unhealthy: the last round found the gateway unable to serve.
	Unhealthy bool
	// NodeControllerDegraded: the certificate probe is not answering.
	NodeControllerDegraded bool
	// RootFingerprint is the last one the gateway reported ("" until then).
	RootFingerprint string
	// DecryptValidUntil is the last known value (zero until then).
	DecryptValidUntil time.Time
	// PreAttachBypass counts, per pod UID, the kills that did not run: the
	// pod may still hold direct connections to AI addresses.
	PreAttachBypass map[string]int64
}

// HealthGate turns the gateway's health into the gate value of each binding.
//
// It opens on the first round in which Envoy or the processor does not answer,
// the gateway says it cannot decrypt, or the last known certificate expiry is
// closer than the margin. Open means: bindings with posture allow get
// GateFailingOpen, so their new connections keep their own route; bindings
// with posture deny are left redirecting. A certificate probe that does not
// answer changes nothing by itself: the last answer stands, and the node
// controller is reported as degraded.
//
// It closes in two steps once every signal has been healthy for HealthyFor.
// First the bindings go to GateRecovering, which redirects new connections.
// Then the direct connections the pods opened during the window are closed.
// Only after that do the bindings go back to GateRedirecting and the state
// read by Status changes.
type HealthGate struct {
	cfg  GateConfig
	maps GateMaps
	kill Killer
	now  func() time.Time
	// Pods returns the bound pods (the reconciler's States).
	pods func() []PodState
	// OnChange is called, outside the lock, after Observe changed what Status
	// returns.
	OnChange func()

	mu           sync.Mutex
	started      bool
	state        Gate
	unhealthy    bool
	degraded     bool
	haveCerts    bool
	canDecrypt   bool
	validUntil   time.Time
	root         string
	healthySince time.Time
	// opened holds the binding ids that failed open in the current window.
	opened map[uint32]bool
	bypass map[string]int64
}

// NewHealthGate returns a gate. pods returns the bound pods of the last
// reconcile; kill may be nil (no kill runs, and every skipped kill is counted).
func NewHealthGate(cfg GateConfig, maps GateMaps, kill Killer, pods func() []PodState, now func() time.Time) *HealthGate {
	if now == nil {
		now = time.Now
	}
	return &HealthGate{cfg: cfg, maps: maps, kill: kill, pods: pods, now: now, opened: map[uint32]bool{}, bypass: map[string]int64{}}
}

// start reads the state the last process left in the map. A window that was
// open, or half closed, is still open: its direct connections were not all
// closed.
func (g *HealthGate) start() error {
	if g.started {
		return nil
	}
	bindings, err := g.maps.Bindings()
	if err != nil {
		return fmt.Errorf("httpgateway: read bindings: %w", err)
	}
	for _, b := range bindings {
		if b.Gate != GateRedirecting {
			g.state = GateFailingOpen
			g.opened[b.ID] = true
		}
	}
	g.started = true
	return nil
}

// InitialGate is the gate value of a binding created now: the reconciler's
// InitialGate hook.
func (g *HealthGate) InitialGate(p Posture) Gate {
	g.mu.Lock()
	defer g.mu.Unlock()
	if p == PostureDeny || g.state == GateRedirecting {
		return GateRedirecting
	}
	return GateFailingOpen
}

// Status returns the gate as it is now.
func (g *HealthGate) Status() GateStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.status()
}

func (g *HealthGate) status() GateStatus {
	bypass := make(map[string]int64, len(g.bypass))
	for uid, n := range g.bypass {
		bypass[uid] = n
	}
	return GateStatus{State: g.state, Unhealthy: g.unhealthy, NodeControllerDegraded: g.degraded, RootFingerprint: g.root, DecryptValidUntil: g.validUntil, PreAttachBypass: bypass}
}

// Observe takes one round of probes through the state machine.
func (g *HealthGate) Observe(ctx context.Context, h Health) error {
	g.mu.Lock()
	before := g.status()
	err := g.observe(ctx, h)
	after := g.status()
	g.mu.Unlock()
	if g.OnChange != nil && (before.State != after.State || before.Unhealthy != after.Unhealthy ||
		before.NodeControllerDegraded != after.NodeControllerDegraded || before.RootFingerprint != after.RootFingerprint ||
		len(before.PreAttachBypass) != len(after.PreAttachBypass)) {
		g.OnChange()
	}
	return err
}

func (g *HealthGate) observe(ctx context.Context, h Health) error {
	if err := g.start(); err != nil {
		return err
	}
	now := g.now()
	if h.CertsAnswered {
		g.haveCerts, g.canDecrypt, g.validUntil, g.root = true, h.CanDecrypt, h.DecryptValidUntil, h.RootFingerprint
	}
	g.degraded = !h.CertsAnswered
	// The certificate signal is the last answer, whether or not the node
	// controller still answers. Before the first answer there is none.
	certs := g.haveCerts && (!g.canDecrypt || g.validUntil.Sub(now) < g.cfg.CertMargin)
	g.unhealthy = !h.Envoy || !h.Processor || certs

	if g.unhealthy {
		g.healthySince = time.Time{}
		if g.state == GateFailingOpen {
			// Bindings created since the window opened are already open
			// (InitialGate); nothing to write.
			return nil
		}
		// From redirecting, or from a recovery that did not finish.
		g.state = GateFailingOpen
		return g.setGate(GateFailingOpen, func(b Binding) bool { return b.Gate != GateFailingOpen })
	}
	if g.state == GateRedirecting {
		return nil
	}
	if g.healthySince.IsZero() {
		g.healthySince = now
	}
	if g.state == GateFailingOpen {
		if now.Sub(g.healthySince) < g.cfg.HealthyFor {
			return nil
		}
		// Step one: new connections go to the gateway again.
		g.state = GateRecovering
		if err := g.setGate(GateRecovering, func(b Binding) bool { return b.Gate == GateFailingOpen }); err != nil {
			return err
		}
	}
	// Step two: close the direct connections of the window. A pod whose kill
	// fails keeps the node recovering; the next healthy round tries again.
	var errs []error
	for _, pod := range g.pods() {
		if !pod.Decision.Bound || pod.Decision.Posture == PostureDeny || !g.opened[pod.BindingID] {
			continue
		}
		if err := g.killPod(ctx, pod); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(g.opened, pod.BindingID)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	// Step three: the window is over.
	if err := g.setGate(GateRedirecting, func(b Binding) bool { return b.Gate != GateRedirecting }); err != nil {
		return err
	}
	g.opened = map[uint32]bool{}
	g.state = GateRedirecting
	return nil
}

// setGate writes gate to every allow binding that match selects, and records
// the bindings that fail open.
func (g *HealthGate) setGate(gate Gate, match func(Binding) bool) error {
	bindings, err := g.maps.Bindings()
	if err != nil {
		return fmt.Errorf("httpgateway: read bindings: %w", err)
	}
	var errs []error
	for cgroup, b := range bindings {
		if b.Posture == PostureDeny || !match(b) {
			continue
		}
		b.Gate = gate
		if err := g.maps.SetBinding(cgroup, b); err != nil {
			errs = append(errs, fmt.Errorf("httpgateway: set gate of cgroup %d: %w", cgroup, err))
			continue
		}
		if gate == GateFailingOpen {
			g.opened[b.ID] = true
		}
	}
	return errors.Join(errs...)
}

// killPod runs the kill for one pod. A kill that cannot run is counted and is
// not an error: the pod may keep direct connections, and the status says so.
func (g *HealthGate) killPod(ctx context.Context, pod PodState) error {
	if g.kill == nil {
		g.bypass[pod.Pod.UID]++
		return nil
	}
	_, err := g.kill.Kill(ctx, pod)
	if errors.Is(err, ErrKillUnsupported) || errors.Is(err, ErrKillSkipped) {
		g.bypass[pod.Pod.UID]++
		return nil
	}
	if err != nil {
		return fmt.Errorf("httpgateway: close direct connections of pod %s/%s: %w", pod.Pod.Namespace, pod.Pod.Name, err)
	}
	return nil
}

// Bound is called after a reconcile with the states it returned. A pod bound
// just now may hold connections it opened before: they are closed here, unless
// the gate is open, in which case the recovery closes them.
func (g *HealthGate) Bound(ctx context.Context, states []PodState) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.start(); err != nil {
		return err
	}
	live := map[string]bool{}
	var errs []error
	for _, pod := range states {
		live[pod.Pod.UID] = true
		if !pod.New || !pod.Decision.Bound {
			continue
		}
		if g.state != GateRedirecting && pod.Decision.Posture == PostureAllow {
			g.opened[pod.BindingID] = true
			continue
		}
		errs = append(errs, g.killPod(ctx, pod))
	}
	for uid := range g.bypass {
		if !live[uid] {
			delete(g.bypass, uid)
		}
	}
	return errors.Join(errs...)
}

// Run probes at once and then every Interval, until ctx ends. report receives
// the errors of the state machine (map writes, kills); nil drops them.
func (g *HealthGate) Run(ctx context.Context, prober Prober, report func(error)) {
	ticker := time.NewTicker(g.cfg.Interval)
	defer ticker.Stop()
	for {
		probeCtx, cancel := context.WithTimeout(ctx, g.cfg.Timeout)
		h := prober.Probe(probeCtx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err := g.Observe(ctx, h); err != nil && report != nil {
			report(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
