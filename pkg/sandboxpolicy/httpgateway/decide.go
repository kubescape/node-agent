// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package httpgateway

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// PreparedAnnotation is set on a pod by the gateway's admission webhook when
// it injected the trust bundle. Its value is the fingerprints of the root CAs
// the pod trusts, comma separated. A pod without it is never bound: its
// clients would refuse the gateway's certificates.
const PreparedAnnotation = "sandbox.kubescape.io/gateway-prepared"

// PolicyRef names one policy object that covers a pod.
type PolicyRef struct {
	UID        string `json:"uid"`
	Generation int64  `json:"generation"`
}

// Policy is what the binding decision needs from one policy object that has an
// http section and selects the pod.
type Policy struct {
	Ref PolicyRef
	// Off: spec.mode is "off". The policy binds nothing.
	Off bool
	// Deny: http.onUnavailable is "deny".
	Deny bool
}

// Pod is one pod of the node, with the policies that select it.
type Pod struct {
	UID, Namespace, Name           string
	ControllerKind, ControllerName string
	// Prepared is the value of PreparedAnnotation ("" when absent).
	Prepared string
	Policies []Policy
	// PodCgroup is the id of the pod cgroup (0 when not known yet), and
	// Containers the id of each container cgroup, by container name.
	PodCgroup  uint64
	Containers map[string]uint64
	// HostNetwork: the pod shares the node's network namespace.
	HostNetwork bool
	// NetNS is a path to the pod's network namespace, for example
	// /proc/<pid>/ns/net of one of its containers ("" when not known).
	NetNS string
}

// Rotation is the root rotation state the operator publishes.
type Rotation struct {
	CurrentRoot string
	NextRoot    string
	// WindowEnds is zero when no rotation is under way.
	WindowEnds time.Time
	Emergency  bool
}

// ParseRotation reads rotation.json:
//
//	{"currentRoot": "<sha256>", "nextRoot": "<sha256 or null>",
//	 "windowEnds": "<RFC 3339 or null>", "emergency": false}
func ParseRotation(data []byte) (Rotation, error) {
	var raw struct {
		CurrentRoot string     `json:"currentRoot"`
		NextRoot    *string    `json:"nextRoot"`
		WindowEnds  *time.Time `json:"windowEnds"`
		Emergency   bool       `json:"emergency"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return Rotation{}, fmt.Errorf("httpgateway: rotation state: %w", err)
	}
	out := Rotation{CurrentRoot: normalizeFingerprint(raw.CurrentRoot), Emergency: raw.Emergency}
	if raw.NextRoot != nil {
		out.NextRoot = normalizeFingerprint(*raw.NextRoot)
	}
	if raw.WindowEnds != nil {
		out.WindowEnds = *raw.WindowEnds
	}
	return out, nil
}

// mustHaveNext reports whether pods have to trust the next root by now.
func (r Rotation) mustHaveNext(now time.Time) bool {
	if r.NextRoot == "" {
		return false
	}
	return r.Emergency || (!r.WindowEnds.IsZero() && !now.Before(r.WindowEnds))
}

func normalizeFingerprint(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// preparedRoots returns the fingerprints in a PreparedAnnotation value.
func preparedRoots(annotation string) []string {
	var out []string
	for _, part := range strings.Split(annotation, ",") {
		if part = normalizeFingerprint(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// Why a pod is not bound.
const (
	ReasonNoPolicy       = "no active policy with an http section selects the pod"
	ReasonNotPrepared    = "the pod has no gateway-prepared annotation"
	ReasonRootUnknown    = "the node's root fingerprint is not known yet"
	ReasonNodeRootAbsent = "the pod does not trust the root of this node's gateway"
	ReasonNextRootAbsent = "the pod does not trust the next root and the rotation window has ended"
)

// Decision says whether a pod is bound, and how.
type Decision struct {
	Bound   bool
	Posture Posture
	// Policies are the active policies that cover the pod, bound or not.
	Policies []PolicyRef
	// NeedRestart: a policy covers the pod, but it cannot be bound until it
	// restarts and the webhook prepares it.
	NeedRestart bool
	// Reason says why the pod is not bound ("" when it is).
	Reason string
}

// Decide applies the binding rule to one pod. A pod is bound when a policy
// with an http section selects it, that policy's mode is not "off", and the
// pod's prepared annotation holds the root that this node's gateway chains to
// (nodeRoot, from the gateway's health answer). The posture is deny when any
// covering policy says deny. Once a rotation window has ended, or under an
// emergency rotation, the pod must also trust the next root.
func Decide(pod Pod, nodeRoot string, rotation Rotation, now time.Time) Decision {
	var d Decision
	for _, p := range pod.Policies {
		if p.Off {
			continue
		}
		d.Policies = append(d.Policies, p.Ref)
		if p.Deny {
			d.Posture = PostureDeny
		}
	}
	slices.SortFunc(d.Policies, func(a, b PolicyRef) int { return strings.Compare(a.UID, b.UID) })
	if len(d.Policies) == 0 {
		d.Posture = PostureAllow
		d.Reason = ReasonNoPolicy
		return d
	}
	roots := preparedRoots(pod.Prepared)
	nodeRoot = normalizeFingerprint(nodeRoot)
	switch {
	case len(roots) == 0:
		d.NeedRestart, d.Reason = true, ReasonNotPrepared
	case nodeRoot == "":
		d.Reason = ReasonRootUnknown
	case !slices.Contains(roots, nodeRoot):
		d.NeedRestart, d.Reason = true, ReasonNodeRootAbsent
	case rotation.mustHaveNext(now) && !slices.Contains(roots, rotation.NextRoot):
		d.NeedRestart, d.Reason = true, ReasonNextRootAbsent
	default:
		d.Bound = true
	}
	return d
}
