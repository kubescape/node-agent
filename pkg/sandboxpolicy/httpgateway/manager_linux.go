// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package httpgateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sync"
	"time"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// ManagerOptions configure the node-agent side of the gateway.
type ManagerOptions struct {
	// PinDir and CgroupRoot are the loader's (Options).
	PinDir, CgroupRoot string
	// Gateway is the gateway's redirect listener on this node.
	Gateway netip.AddrPort
	// HealthURL is the base of the gateway's health listener, for example
	// "http://192.168.1.10:18444". Prober replaces it when set.
	HealthURL string
	Prober    Prober
	Gate      GateConfig
	// LookupSocket is the path of the workload lookup socket ("" serves none).
	LookupSocket string
	// StaticAI is written to every binding's AI set.
	StaticAI []netip.Addr

	// Pods returns the pods of the node that a policy with an http section
	// selects. An error keeps the bindings as they are.
	Pods func(context.Context) ([]Pod, error)
	// Exempt returns the destinations that keep their own route (nil: none).
	// An error keeps the set as it is.
	Exempt func(context.Context) ([]netip.Prefix, error)
	// Rotation returns the root rotation state (nil: no rotation). An error
	// keeps the last state read.
	Rotation func(context.Context) (Rotation, error)
	// RefreshInterval is the longest time between two reconciles (0: 5 s).
	// Kick asks for one sooner.
	RefreshInterval time.Duration

	// Report receives errors that do not stop the manager (nil drops them).
	Report func(error)
	// OnStatus is called when a policy's status may have changed.
	OnStatus func()
	// Now replaces the clock (tests).
	Now func() time.Time
}

// Manager runs the redirect for one node: it loads the programs, keeps the
// bindings equal to the binding decisions, runs the health gate and serves
// the lookup socket.
type Manager struct {
	opts     ManagerOptions
	redirect *Redirect
	rec      *Reconciler
	gate     *HealthGate

	cancel context.CancelFunc
	wg     sync.WaitGroup
	kick   chan struct{}

	mu       sync.Mutex
	rotation Rotation
}

// StartManager loads the redirect and starts the loops. The pinned state of an
// earlier process is adopted: its bindings keep their ids and gate values, the
// socket kill does not run again for pods that were already bound, and the
// first health probe goes out at once.
func StartManager(ctx context.Context, opts ManagerOptions) (*Manager, error) {
	if opts.Pods == nil {
		return nil, errors.New("httpgateway: Pods is required")
	}
	if opts.Prober == nil {
		if opts.HealthURL == "" {
			return nil, errors.New("httpgateway: HealthURL or Prober is required")
		}
		opts.Prober = HTTPProber{Base: opts.HealthURL, Client: &http.Client{}}
	}
	if opts.Gate == (GateConfig{}) {
		opts.Gate = DefaultGateConfig()
	}
	if opts.RefreshInterval <= 0 {
		opts.RefreshInterval = 5 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	redirect, err := Load(Options{PinDir: opts.PinDir, CgroupRoot: opts.CgroupRoot, Gateway: opts.Gateway})
	if err != nil {
		return nil, err
	}
	m := &Manager{opts: opts, redirect: redirect, kick: make(chan struct{}, 1)}
	m.rec = NewReconciler(redirect)
	m.rec.StaticAI = opts.StaticAI
	m.gate = NewHealthGate(opts.Gate, redirect, NetNSKiller{Redirect: redirect}, m.rec.States, opts.Now)
	m.rec.InitialGate = m.gate.InitialGate
	// A change of the gate can change who is bindable (the root the gateway
	// reports) and every policy's status.
	m.gate.OnChange = func() {
		m.Kick()
		m.statusChanged()
	}

	runCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.wg.Add(2)
	go func() {
		defer m.wg.Done()
		m.gate.Run(runCtx, opts.Prober, m.report)
	}()
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(opts.RefreshInterval)
		defer ticker.Stop()
		for {
			if err := m.Refresh(runCtx); err != nil && runCtx.Err() == nil {
				m.report(err)
			}
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
			case <-m.kick:
			}
		}
	}()
	if opts.LookupSocket != "" {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			if err := ServeLookup(runCtx, opts.LookupSocket, m.rec.Owner); err != nil {
				m.report(fmt.Errorf("httpgateway: lookup socket: %w", err))
			}
		}()
	}
	return m, nil
}

func (m *Manager) report(err error) {
	if err != nil && m.opts.Report != nil {
		m.opts.Report(err)
	}
}

func (m *Manager) statusChanged() {
	if m.opts.OnStatus != nil {
		m.opts.OnStatus()
	}
}

// Kick asks for a reconcile soon: a pod or a policy changed.
func (m *Manager) Kick() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// Refresh reads the inputs and reconciles once.
func (m *Manager) Refresh(ctx context.Context) error {
	var errs []error
	if m.opts.Exempt != nil {
		if set, err := m.opts.Exempt(ctx); err != nil {
			errs = append(errs, fmt.Errorf("httpgateway: exempt ranges (the last set stays): %w", err))
		} else if err := m.redirect.ReplaceExempt(set); err != nil {
			errs = append(errs, err)
		}
	}
	m.mu.Lock()
	if m.opts.Rotation != nil {
		if rotation, err := m.opts.Rotation(ctx); err != nil {
			errs = append(errs, fmt.Errorf("httpgateway: rotation state (the last one stays): %w", err))
		} else {
			m.rotation = rotation
		}
	}
	rotation := m.rotation
	m.mu.Unlock()
	pods, err := m.opts.Pods(ctx)
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("httpgateway: pods (the bindings stay): %w", err))...)
	}
	before := m.rec.States()
	states, err := m.rec.Apply(pods, m.gate.Status().RootFingerprint, rotation, m.opts.Now())
	errs = append(errs, err)
	if states != nil {
		errs = append(errs, m.gate.Bound(ctx, states))
		if !sameStates(before, states) {
			m.statusChanged()
		}
	}
	return errors.Join(errs...)
}

// sameStates reports whether two reconciles would give the same statuses.
func sameStates(a, b []PodState) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.Pod.UID != y.Pod.UID || x.BindingID != y.BindingID || x.Decision.Bound != y.Decision.Bound ||
			x.Decision.Posture != y.Decision.Posture || x.Decision.NeedRestart != y.Decision.NeedRestart || len(x.Decision.Policies) != len(y.Decision.Policies) {
			return false
		}
		for j := range x.Decision.Policies {
			if x.Decision.Policies[j] != y.Decision.Policies[j] {
				return false
			}
		}
	}
	return true
}

// PolicyStatus returns the http block of one policy's node status.
func (m *Manager) PolicyStatus(policyUID string) (api.HTTPNodeStatus, bool) {
	return PolicyStatus(policyUID, m.rec.States(), m.gate.Status())
}

// States returns the pod states of the last reconcile.
func (m *Manager) States() []PodState { return m.rec.States() }

// GateStatus returns the health gate as it is now.
func (m *Manager) GateStatus() GateStatus { return m.gate.Status() }

// Close stops the loops and releases the handles. The redirect keeps running
// from its pins, with the bindings and gate values as they are.
func (m *Manager) Close() {
	m.cancel()
	m.wg.Wait()
	m.redirect.Close()
}
