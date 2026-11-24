// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package httpgateway

import (
	"fmt"
	"reflect"
	"testing"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

func statePod(name string, bound bool, posture Posture, needRestart bool, policies ...string) PodState {
	s := PodState{Pod: Pod{UID: "uid-" + name, Namespace: "ns", Name: name}, Decision: Decision{Bound: bound, Posture: posture, NeedRestart: needRestart}}
	for _, uid := range policies {
		s.Decision.Policies = append(s.Decision.Policies, PolicyRef{UID: uid})
	}
	return s
}

func TestPolicyStatus(t *testing.T) {
	states := []PodState{
		statePod("allow-1", true, PostureAllow, false, "p", "q"),
		statePod("allow-2", true, PostureAllow, false, "p"),
		statePod("deny-1", true, PostureDeny, false, "d", "q"),
		statePod("zz-no-annotation", false, PostureAllow, true, "p"),
		statePod("aa-old-root", false, PostureAllow, true, "p"),
		statePod("root-unknown", false, PostureAllow, false, "p"),
		statePod("other", true, PostureAllow, false, "other"),
	}
	healthy := GateStatus{PreAttachBypass: map[string]int64{"uid-allow-2": 3, "uid-other": 1}}
	open := GateStatus{State: GateFailingOpen, Unhealthy: true}
	recovering := GateStatus{State: GateRecovering}
	degraded := GateStatus{NodeControllerDegraded: true}
	for _, tc := range []struct {
		name   string
		policy string
		gate   GateStatus
		want   api.HTTPNodeStatus
	}{
		{"bound pods, restart list sorted, bypass counted per pod", "p", healthy,
			api.HTTPNodeStatus{BoundPods: 2, PreAttachBypass: 1, NeedRestart: []string{"ns/aa-old-root", "ns/zz-no-annotation"}, Gate: api.HTTPGateRedirecting}},
		{"allow pods while the gateway is down", "p", open,
			api.HTTPNodeStatus{BoundPods: 2, NeedRestart: []string{"ns/aa-old-root", "ns/zz-no-annotation"}, Gate: api.HTTPGateFailingOpen}},
		{"still failing open until the window's connections are closed", "p", recovering,
			api.HTTPNodeStatus{BoundPods: 2, NeedRestart: []string{"ns/aa-old-root", "ns/zz-no-annotation"}, Gate: api.HTTPGateFailingOpen}},
		{"deny pods while the gateway is down", "d", open,
			api.HTTPNodeStatus{BoundPods: 1, Gate: api.HTTPGateFailingClosed}},
		{"deny pods are redirecting again as soon as the gateway serves", "d", recovering,
			api.HTTPNodeStatus{BoundPods: 1, Gate: api.HTTPGateRedirecting}},
		{"a policy with an allow pod and a deny pod reports the open one", "q", open,
			api.HTTPNodeStatus{BoundPods: 2, Gate: api.HTTPGateFailingOpen}},
		{"a policy with no pod on the node", "nobody", open,
			api.HTTPNodeStatus{Gate: api.HTTPGateNotBound}},
		{"the node controller does not answer", "d", degraded,
			api.HTTPNodeStatus{BoundPods: 1, Gate: api.HTTPGateRedirecting, NodeControllerDegraded: true}},
	} {
		got, truncated := PolicyStatus(tc.policy, states, tc.gate)
		if !reflect.DeepEqual(got, tc.want) || truncated {
			t.Errorf("%s:\n got %+v (truncated %v)\nwant %+v", tc.name, got, truncated, tc.want)
		}
	}
}

func TestPolicyStatusTruncatesNeedRestart(t *testing.T) {
	var states []PodState
	for i := 0; i < api.MaxStatusPodNames+5; i++ {
		states = append(states, statePod(fmt.Sprintf("pod-%03d", i), false, PostureAllow, true, "p"))
	}
	got, truncated := PolicyStatus("p", states, GateStatus{})
	if len(got.NeedRestart) != api.MaxStatusPodNames || !truncated || got.NeedRestart[0] != "ns/pod-000" || got.Gate != api.HTTPGateNotBound {
		t.Errorf("%d names, truncated %v, first %q, gate %q", len(got.NeedRestart), truncated, got.NeedRestart[0], got.Gate)
	}
}
