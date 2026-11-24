// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package httpgateway

import (
	"slices"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// PolicyStatus builds the http block of one policy's node status from the
// last reconcile and the gate. truncated is set when needRestart had more
// names than the status holds.
//
//   - boundPods: the pods this policy covers that are bound.
//   - needRestart: "<namespace>/<pod>" of the covered pods that cannot be bound
//     until they restart.
//   - preAttachBypass: the bound pods that may still hold direct connections
//     to AI addresses, because the socket kill could not run for them.
//   - gate: not_bound with no bound pod. Otherwise failing_open while the
//     window is open (until its direct connections are closed) and a bound pod
//     has posture allow; failing_closed while the gateway cannot serve and the
//     bound pods have posture deny; redirecting in every other case.
func PolicyStatus(policyUID string, states []PodState, gate GateStatus) (status api.HTTPNodeStatus, truncated bool) {
	status.Gate = api.HTTPGateNotBound
	status.NodeControllerDegraded = gate.NodeControllerDegraded
	var allow, deny bool
	for _, pod := range states {
		if !slices.ContainsFunc(pod.Decision.Policies, func(ref PolicyRef) bool { return ref.UID == policyUID }) {
			continue
		}
		if pod.Decision.NeedRestart {
			status.NeedRestart = append(status.NeedRestart, pod.Pod.Namespace+"/"+pod.Pod.Name)
		}
		if !pod.Decision.Bound {
			continue
		}
		status.BoundPods++
		if gate.PreAttachBypass[pod.Pod.UID] > 0 {
			status.PreAttachBypass++
		}
		if pod.Decision.Posture == PostureDeny {
			deny = true
		} else {
			allow = true
		}
	}
	slices.Sort(status.NeedRestart)
	if len(status.NeedRestart) > api.MaxStatusPodNames {
		status.NeedRestart, truncated = status.NeedRestart[:api.MaxStatusPodNames], true
	}
	switch {
	case status.BoundPods == 0:
	case allow && gate.State != GateRedirecting:
		status.Gate = api.HTTPGateFailingOpen
	case deny && gate.Unhealthy:
		status.Gate = api.HTTPGateFailingClosed
	default:
		status.Gate = api.HTTPGateRedirecting
	}
	return status, truncated
}
