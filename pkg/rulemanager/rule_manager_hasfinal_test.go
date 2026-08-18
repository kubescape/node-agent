package rulemanager

import (
	"context"
	"errors"
	"testing"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/objectcache/callstackcache"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

// stateCPCFake is a ContainerProfileCache whose GetContainerProfileState is
// driven by a per-containerID map, so the enforce/learn gate in
// HasFinalApplicationProfile can be exercised across profile states without a
// cluster. Only GetContainerProfileState is meaningful; the rest satisfy the
// interface via the embedded (nil) ContainerProfileCache and are never called
// by HasFinalApplicationProfile.
type stateCPCFake struct {
	objectcache.ContainerProfileCache
	states map[string]*objectcache.ProfileState
}

func (f *stateCPCFake) GetContainerProfileState(containerID string) *objectcache.ProfileState {
	return f.states[containerID]
}

func (f *stateCPCFake) GetProjectedContainerProfile(string) *objectcache.ProjectedContainerProfile {
	return nil
}
func (f *stateCPCFake) GetCallStackSearchTree(string) *callstackcache.CallStackSearchTree { return nil }
func (f *stateCPCFake) SetProjectionSpec(objectcache.RuleProjectionSpec)                  {}
func (f *stateCPCFake) ContainerCallback(containercollection.PubSubEvent)                 {}
func (f *stateCPCFake) Start(context.Context)                                             {}

// stateObjectCacheFake is an ObjectCache that only wires ContainerProfileCache;
// HasFinalApplicationProfile touches nothing else.
type stateObjectCacheFake struct {
	objectcache.ObjectCache
	cpc objectcache.ContainerProfileCache
}

func (f *stateObjectCacheFake) ContainerProfileCache() objectcache.ContainerProfileCache {
	return f.cpc
}

func podWithContainerID(id string) *corev1.Pod {
	return &corev1.Pod{
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "c", ContainerID: id},
			},
		},
	}
}

// TestHasFinalApplicationProfile pins the profile-complete enforce/learn gate:
// a Completed+Full state enforces (true); any non-terminal state, an errored
// state, or a nil state leaves it in learn mode (false).
func TestHasFinalApplicationProfile(t *testing.T) {
	const cid = "containerd://abc123"
	trimmed := "abc123" // utils.TrimRuntimePrefix(cid)

	testCases := []struct {
		name  string
		state *objectcache.ProfileState
		want  bool
	}{
		{
			name:  "completed and full -> enforce",
			state: &objectcache.ProfileState{Status: helpersv1.Completed, Completion: helpersv1.Full},
			want:  true,
		},
		{
			name:  "completed but partial -> learn",
			state: &objectcache.ProfileState{Status: helpersv1.Completed, Completion: helpersv1.Partial},
			want:  false,
		},
		{
			name:  "non-terminal status -> learn",
			state: &objectcache.ProfileState{Status: helpersv1.Initializing, Completion: helpersv1.Full},
			want:  false,
		},
		{
			name:  "errored state -> learn",
			state: &objectcache.ProfileState{Error: errors.New("profile not found")},
			want:  false,
		},
		{
			name:  "nil state -> learn",
			state: nil,
			want:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cpc := &stateCPCFake{states: map[string]*objectcache.ProfileState{trimmed: tc.state}}
			rm := &RuleManager{objectCache: &stateObjectCacheFake{cpc: cpc}}
			got := rm.HasFinalApplicationProfile(podWithContainerID(cid))
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestHasFinalApplicationProfileNoContainers confirms a pod with no container
// statuses is never final.
func TestHasFinalApplicationProfileNoContainers(t *testing.T) {
	cpc := &stateCPCFake{states: map[string]*objectcache.ProfileState{}}
	rm := &RuleManager{objectCache: &stateObjectCacheFake{cpc: cpc}}
	assert.False(t, rm.HasFinalApplicationProfile(&corev1.Pod{}))
}
