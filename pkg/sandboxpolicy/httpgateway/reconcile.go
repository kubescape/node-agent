// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package httpgateway

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// AIDst is one entry of a binding's AI set.
type AIDst struct {
	Binding uint32
	Addr    netip.Addr
}

// Maps is what the reconciler needs from the pinned maps. *Redirect
// implements it.
type Maps interface {
	Bindings() (map[uint64]Binding, error)
	SetBinding(cgroup uint64, b Binding) error
	DeleteBinding(cgroup uint64) error
	AIDsts() (map[AIDst]uint64, error)
	SetAIDst(binding uint32, addr netip.Addr, expiry uint64) error
	DeleteAIDst(binding uint32, addr netip.Addr) error
	Conns() (map[ConnKey]Conn, error)
}

// Workload is who owns a bound cgroup: the answer of the lookup socket.
type Workload struct {
	Namespace  string `json:"namespace"`
	Pod        string `json:"pod"`
	Container  string `json:"container"`
	Controller struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"controller"`
	BindingID uint32      `json:"bindingId"`
	Policies  []PolicyRef `json:"policies"`
}

// PodState is the outcome of one Apply for one pod that a policy covers.
type PodState struct {
	Pod      Pod
	Decision Decision
	// BindingID is 0 when the pod is not bound.
	BindingID uint32
	// New: this Apply bound the pod; its entries were not in the map before.
	New bool
}

// Reconciler keeps the bindings map equal to the binding decisions. It is the
// only writer of binding ids and postures. The gate value of an entry belongs
// to the health gate: the reconciler keeps it when it rewrites an entry, and
// asks InitialGate for the value of a new one.
type Reconciler struct {
	maps Maps
	// StaticAI is written to every binding's AI set with no expiry. It
	// stands in for the DNS feed until that exists.
	StaticAI []netip.Addr
	// InitialGate returns the gate value of a new binding (nil: redirecting).
	InitialGate func(Posture) Gate

	mu      sync.RWMutex
	nextID  uint32
	started bool
	// byPod is the binding id of each bound pod, by pod UID.
	byPod map[string]uint32
	// unsettled holds the pods whose binding writes did not all succeed. Such
	// a pod is reported New until they do, so the caller's bind-time work
	// (the socket kill) runs again.
	unsettled map[string]bool
	// owners is who owns each bound cgroup.
	owners map[uint64]Workload
	states []PodState
}

// NewReconciler returns a reconciler over maps.
func NewReconciler(maps Maps) *Reconciler {
	return &Reconciler{maps: maps, byPod: map[string]uint32{}, unsettled: map[string]bool{}, owners: map[uint64]Workload{}}
}

// start reads the ids already in the kernel, so a new binding never gets an
// id that a live connection, an AI set entry or an adopted binding carries.
func (r *Reconciler) start(existing map[uint64]Binding) error {
	if r.started {
		return nil
	}
	highest := uint32(0)
	for _, b := range existing {
		highest = max(highest, b.ID)
	}
	ai, err := r.maps.AIDsts()
	if err != nil {
		return fmt.Errorf("httpgateway: read ai_dsts: %w", err)
	}
	for k := range ai {
		highest = max(highest, k.Binding)
	}
	conns, err := r.maps.Conns()
	if err != nil {
		return fmt.Errorf("httpgateway: read conns: %w", err)
	}
	for _, c := range conns {
		highest = max(highest, c.BindingID)
	}
	r.nextID = highest + 1
	r.started = true
	return nil
}

// Apply decides every pod and makes the maps match. pods are all the pods of
// the node that a policy with an http section selects. It returns the state of
// each of them; the same states are served by States until the next Apply.
//
// A binding found in the map from an earlier process is adopted: a pod whose
// cgroup is already bound keeps that binding id, and is not reported as New.
// While nodeRoot is "" no pod is newly bound, and a bound pod stays bound
// unless the rotation rule unbinds it.
//
// A pod is reported bound only once its AI set and every binding entry are
// written. When a write fails, the pod keeps its binding id, is reported not
// bound (or, if it was bound before, keeps the entries it had), and the next
// Apply tries again; until all writes succeed it is reported New.
//
// AI set entries with expiry 0 belong to StaticAI: an address that is no
// longer in StaticAI is removed from every binding. Other writers of the AI
// set use a nonzero expiry.
func (r *Reconciler) Apply(pods []Pod, nodeRoot string, rotation Rotation, now time.Time) ([]PodState, error) {
	existing, err := r.maps.Bindings()
	if err != nil {
		return nil, fmt.Errorf("httpgateway: read bindings: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.start(existing); err != nil {
		return nil, err
	}
	var errs []error
	want := map[uint64]Binding{}
	owners := map[uint64]Workload{}
	byPod := map[string]uint32{}
	states := make([]PodState, 0, len(pods))
	for _, pod := range pods {
		state := PodState{Pod: pod, Decision: Decide(pod, nodeRoot, rotation, now)}
		cgroups := podCgroups(pod)
		if state.Decision.Reason == ReasonRootUnknown && slices.ContainsFunc(cgroups, func(c podCgroup) bool { _, ok := existing[c.id]; return ok }) {
			// The gateway has not said which root it chains to (it is down,
			// or node-agent just started). A pod that is already bound was
			// bound under a root it trusts: it stays bound.
			state.Decision.Bound, state.Decision.Reason = true, ""
		}
		if state.Decision.Bound && len(cgroups) == 0 {
			// Nothing to bind yet: the pod has no cgroup the node knows.
			state.Decision.Bound = false
		}
		if !state.Decision.Bound {
			if len(state.Decision.Policies) > 0 {
				states = append(states, state)
			}
			continue
		}
		id, known := r.byPod[pod.UID]
		if !known {
			for _, c := range cgroups {
				if b, ok := existing[c.id]; ok {
					id, known = b.ID, true
					break
				}
			}
		}
		if !known {
			id = r.nextID
			r.nextID++
		}
		state.New = !known || r.unsettled[pod.UID]
		state.BindingID = id
		byPod[pod.UID] = id
		for _, c := range cgroups {
			b := Binding{ID: id, Posture: state.Decision.Posture}
			if old, ok := existing[c.id]; ok && old.ID == id {
				b.Gate = old.Gate
			} else if r.InitialGate != nil {
				b.Gate = r.InitialGate(b.Posture)
			}
			// A deny pod never fails open, whatever the entry held.
			if b.Posture == PostureDeny {
				b.Gate = GateRedirecting
			}
			want[c.id] = b
			owners[c.id] = workloadOf(pod, c.container, id, state.Decision.Policies)
		}
		states = append(states, state)
	}

	// The AI set before the binding: a connect that sees the binding finds
	// its addresses. A binding whose set could not be written is not
	// activated; its pods are retried on the next Apply.
	live := map[uint32]bool{}
	for _, b := range want {
		live[b.ID] = true
	}
	failed := map[uint32]bool{}
	for id := range live {
		for _, addr := range r.StaticAI {
			if err := r.maps.SetAIDst(id, addr, 0); err != nil {
				failed[id] = true
				errs = append(errs, fmt.Errorf("httpgateway: add %s to the AI set of binding %d: %w", addr, id, err))
			}
		}
	}
	// inKernel: the cgroup's entry carries its binding id after this pass.
	inKernel := map[uint64]bool{}
	for cgroup, b := range want {
		old, had := existing[cgroup]
		if had && old == b {
			inKernel[cgroup] = true
			continue
		}
		if failed[b.ID] {
			inKernel[cgroup] = had && old.ID == b.ID
			continue
		}
		if err := r.maps.SetBinding(cgroup, b); err != nil {
			failed[b.ID] = true
			inKernel[cgroup] = had && old.ID == b.ID
			errs = append(errs, fmt.Errorf("httpgateway: bind cgroup %d: %w", cgroup, err))
			continue
		}
		inKernel[cgroup] = true
	}
	for cgroup := range existing {
		if _, ok := want[cgroup]; ok {
			continue
		}
		if err := r.maps.DeleteBinding(cgroup); err != nil {
			errs = append(errs, fmt.Errorf("httpgateway: unbind cgroup %d: %w", cgroup, err))
		}
	}
	// A pod whose writes failed is reported bound only if every one of its
	// cgroups carries its binding id. The lookup socket answers for each
	// cgroup that does, since the kernel redirects it.
	unsettled := map[string]bool{}
	for i := range states {
		st := &states[i]
		if !st.Decision.Bound || !failed[st.BindingID] {
			continue
		}
		unsettled[st.Pod.UID] = true
		for _, c := range podCgroups(st.Pod) {
			if !inKernel[c.id] {
				st.Decision.Bound = false
				delete(owners, c.id)
			}
		}
		if !st.Decision.Bound {
			st.Decision.Reason = "the binding could not be written; retrying"
		}
	}
	// The AI set of a binding that is gone goes with it, and a static
	// address that is no longer configured goes from every binding.
	static := map[netip.Addr]bool{}
	for _, a := range r.StaticAI {
		static[a.Unmap()] = true
	}
	ai, err := r.maps.AIDsts()
	if err != nil {
		errs = append(errs, fmt.Errorf("httpgateway: read ai_dsts: %w", err))
	}
	for k, expiry := range ai {
		if live[k.Binding] && (expiry != 0 || static[k.Addr]) {
			continue
		}
		if err := r.maps.DeleteAIDst(k.Binding, k.Addr); err != nil {
			errs = append(errs, fmt.Errorf("httpgateway: remove %s from the AI set of binding %d: %w", k.Addr, k.Binding, err))
		}
	}
	r.unsettled = unsettled
	r.byPod, r.owners, r.states = byPod, owners, states
	return slices.Clone(states), errors.Join(errs...)
}

// States returns the pod states of the last Apply.
func (r *Reconciler) States() []PodState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.states)
}

// Owner returns who owns a bound cgroup, as of the last Apply.
func (r *Reconciler) Owner(cgroup uint64) (Workload, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	w, ok := r.owners[cgroup]
	return w, ok
}

type podCgroup struct {
	id        uint64
	container string // "" for the pod cgroup
}

// podCgroups returns the cgroups to bind for a pod, in a fixed order.
func podCgroups(pod Pod) []podCgroup {
	var out []podCgroup
	if pod.PodCgroup != 0 {
		out = append(out, podCgroup{id: pod.PodCgroup})
	}
	names := make([]string, 0, len(pod.Containers))
	for name := range pod.Containers {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if id := pod.Containers[name]; id != 0 && id != pod.PodCgroup {
			out = append(out, podCgroup{id: id, container: name})
		}
	}
	return out
}

func workloadOf(pod Pod, container string, binding uint32, policies []PolicyRef) Workload {
	w := Workload{Namespace: pod.Namespace, Pod: pod.Name, Container: container, BindingID: binding, Policies: slices.Clone(policies)}
	w.Controller.Kind, w.Controller.Name = pod.ControllerKind, pod.ControllerName
	return w
}

// ExemptSet returns the destinations that always keep their own route: the
// cluster's pod and service ranges, the node's own addresses, and extra ranges
// from configuration. Entries that do not parse are returned in bad.
func ExemptSet(podCIDRs, serviceCIDRs, nodeAddresses, extra []string) (set []netip.Prefix, bad []string) {
	seen := map[netip.Prefix]bool{}
	add := func(p netip.Prefix) {
		p = p.Masked()
		if !seen[p] {
			seen[p] = true
			set = append(set, p)
		}
	}
	for _, list := range [][]string{podCIDRs, serviceCIDRs, extra} {
		for _, s := range list {
			if p, err := netip.ParsePrefix(s); err == nil {
				add(p)
			} else if a, err := netip.ParseAddr(s); err == nil {
				add(netip.PrefixFrom(a, a.BitLen()))
			} else {
				bad = append(bad, s)
			}
		}
	}
	for _, s := range nodeAddresses {
		a, err := netip.ParseAddr(s)
		if err != nil {
			bad = append(bad, s)
			continue
		}
		a = a.Unmap()
		add(netip.PrefixFrom(a, a.BitLen()))
	}
	slices.SortFunc(set, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return set, bad
}
