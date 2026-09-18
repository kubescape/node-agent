package ruleadapters

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// k8sLookupSpy counts the live Kubernetes lookups setRuntimeAlertK8sDetails
// performs, so a host regression (doing a pod-cache lookup on the synthetic
// host coordinates) fails loudly instead of silently producing a fabricated UID.
type k8sLookupSpy struct {
	*objectcachev1.RuleObjectCacheMock
	getPodCalls        int
	getSharedDataCalls int
}

func (s *k8sLookupSpy) GetPod(_, _ string) *corev1.Pod {
	s.getPodCalls++
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "fabricated-pod-uid"}}
}

func (s *k8sLookupSpy) GetSharedContainerData(containerID string) *objectcache.WatchedContainerData {
	s.getSharedDataCalls++
	return s.RuleObjectCacheMock.GetSharedContainerData(containerID)
}

func (s *k8sLookupSpy) K8sObjectCache() objectcache.K8sObjectCache { return s }

func newK8sLookupSpy() *k8sLookupSpy {
	return &k8sLookupSpy{RuleObjectCacheMock: &objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}}
}

// k8sDetailsEvent is a trigger event supplying only the getters
// setRuntimeAlertK8sDetails consults.
type k8sDetailsEvent struct {
	MockEnrichEvent
	namespace string
	pod       string
	container string
}

func (e *k8sDetailsEvent) GetNamespace() string            { return e.namespace }
func (e *k8sDetailsEvent) GetPod() string                  { return e.pod }
func (e *k8sDetailsEvent) GetContainer() string            { return e.container }
func (e *k8sDetailsEvent) GetContainerImage() string       { return "" }
func (e *k8sDetailsEvent) GetContainerImageDigest() string { return "" }
func (e *k8sDetailsEvent) GetHostNetwork() bool            { return true }

// TestSetRuntimeAlertK8sDetails_HostSkipsLiveLookups is a guard test for the host path.
//
// The pre-existing host skip lives in setProfileMetadata, a DIFFERENT function
// that returns before this one is ever entered — it does not cover the
// PodUID/WorkloadUID lookups here. The host's shared data is
// non-nil, so without its own guard this path would read synthetic fields and
// run a live pod-cache lookup on Namespace "host" / PodName "host-<hostID>".
//
// This asserts the actual output is sane, not merely that nothing panicked:
// both UIDs stay EMPTY (nothing fabricated), no live pod lookup happens, and
// the non-UID details the event supplied are still carried through.
func TestSetRuntimeAlertK8sDetails_HostSkipsLiveLookups(t *testing.T) {
	objCache := newK8sLookupSpy()

	// Deliberately poison the host entry with a WorkloadUID the guard must not
	// copy: the real builder leaves it empty, and a future change that fills it
	// in must not leak a synthetic UID into an alert.
	hostData := hostidentity.BuildHostWatchedContainerData("node-1")
	hostData.WorkloadUID = "synthetic-workload-uid"
	objCache.SetSharedContainerData(armotypes.HostContainerID, hostData)

	ruleFailure := &types.GenericRuleFailure{
		RuntimeAlertK8sDetails: armotypes.RuntimeAlertK8sDetails{
			ContainerID: armotypes.HostContainerID,
			Namespace:   "host",
			PodName:     "host-node-1",
		},
		TriggerEvent: &k8sDetailsEvent{namespace: "host", pod: "host-node-1", container: "host"},
	}

	creator := &RuleFailureCreator{containerIdToPid: new(maps.SafeMap[string, uint32])}
	creator.setRuntimeAlertK8sDetails(ruleFailure, objCache)

	details := ruleFailure.GetRuntimeAlertK8sDetails()
	assert.Equal(t, "", details.PodUID, "host must not receive a pod UID fabricated from a synthetic pod name")
	assert.Equal(t, "", details.WorkloadUID, "host must not receive the synthetic workload UID")
	assert.Zero(t, objCache.getPodCalls, "host must not perform a live pod-cache lookup")
	assert.Zero(t, objCache.getSharedDataCalls, "host must not read shared data for UID enrichment")
	// The details the event already supplied are still preserved for host.
	assert.Equal(t, armotypes.HostContainerID, details.ContainerID)
	assert.Equal(t, "host", details.Namespace)
	assert.Equal(t, "host-node-1", details.PodName)
	assert.Equal(t, "host", details.ContainerName)
	if assert.NotNil(t, details.HostNetwork) {
		assert.True(t, *details.HostNetwork)
	}
}

// TestSetRuntimeAlertK8sDetails_NonHostStillEnriches pins that the host guard
// left the real-container path untouched: shared data is still read for the
// WorkloadUID and the pod cache is still consulted for the PodUID.
func TestSetRuntimeAlertK8sDetails_NonHostStillEnriches(t *testing.T) {
	objCache := newK8sLookupSpy()
	objCache.SetSharedContainerData("cid", &objectcache.WatchedContainerData{WorkloadUID: "real-workload-uid"})

	ruleFailure := &types.GenericRuleFailure{
		RuntimeAlertK8sDetails: armotypes.RuntimeAlertK8sDetails{
			ContainerID: "cid",
			Namespace:   "ns",
			PodName:     "pod-a",
		},
		TriggerEvent: &k8sDetailsEvent{namespace: "ns", pod: "pod-a", container: "c"},
	}

	creator := &RuleFailureCreator{containerIdToPid: new(maps.SafeMap[string, uint32])}
	creator.setRuntimeAlertK8sDetails(ruleFailure, objCache)

	details := ruleFailure.GetRuntimeAlertK8sDetails()
	assert.Equal(t, "real-workload-uid", details.WorkloadUID)
	assert.Equal(t, "fabricated-pod-uid", details.PodUID)
	assert.Equal(t, 1, objCache.getPodCalls)
	assert.Equal(t, 1, objCache.getSharedDataCalls)
}

// TestSetProfileMetadata_PresenceBased_HostUsesProfileWhenPresent is a
// creator.go test: the old blanket "skip profile metadata for host" check is
// gone. When a profile genuinely exists for host (GetContainerProfileState
// returns no Error), it is attached exactly as it would be for any other
// container.
func TestSetProfileMetadata_PresenceBased_HostUsesProfileWhenPresent(t *testing.T) {
	objCache := newK8sLookupSpy()
	objCache.SetContainerProfileState(&objectcache.ProfileState{
		Status:     helpersv1.Completed,
		Completion: "complete",
		Name:       "host-node-1",
	})

	rule := typesv1.Rule{
		ProfileDependency: armotypes.Required,
		Tags:              []string{types.ApplicationProfile},
	}
	ruleFailure := &types.GenericRuleFailure{
		TriggerEvent: &MockEnrichEvent{containerID: armotypes.HostContainerID},
	}

	creator := &RuleFailureCreator{}
	creator.setProfileMetadata(rule, ruleFailure, objCache)

	pm := ruleFailure.GetBaseRuntimeAlert().ProfileMetadata
	require.NotNil(t, pm, "host must receive profile metadata now that a profile is present")
	assert.Equal(t, helpersv1.Completed, pm.Status)
	assert.True(t, pm.FailOnProfile)
	assert.Equal(t, "host-node-1", pm.Name)
	assert.Empty(t, pm.Error)
}

// TestSetProfileMetadata_HostSurfacesErrorWhenAbsent proves that with no
// profile primed yet (the mock's default "not found" state), host still gets
// ProfileMetadata attached -- with the Error field populated -- exactly like
// any other container with no profile yet. Metadata is never withheld: the
// error signal must reach alert consumers instead of being silently dropped.
func TestSetProfileMetadata_HostSurfacesErrorWhenAbsent(t *testing.T) {
	objCache := newK8sLookupSpy() // default GetContainerProfileState -> absent/error

	rule := typesv1.Rule{
		ProfileDependency: armotypes.Required,
		Tags:              []string{types.ApplicationProfile},
	}
	ruleFailure := &types.GenericRuleFailure{
		TriggerEvent: &MockEnrichEvent{containerID: armotypes.HostContainerID},
	}

	creator := &RuleFailureCreator{}
	creator.setProfileMetadata(rule, ruleFailure, objCache)

	pm := ruleFailure.GetBaseRuntimeAlert().ProfileMetadata
	require.NotNil(t, pm, "host must still receive profile metadata carrying the error, not be silently skipped")
	assert.NotEmpty(t, pm.Error)
	assert.False(t, pm.FailOnProfile)
}

// TestSetProfileMetadata_RealContainerUnaffected pins that real (non-host)
// containers behave identically before and after the host fix: present ->
// full metadata with no error; absent -> metadata with the Error field
// populated (never withheld) so the error signal still reaches alert
// consumers, exactly as it did before host support was added.
func TestSetProfileMetadata_RealContainerUnaffected(t *testing.T) {
	rule := typesv1.Rule{
		ProfileDependency: armotypes.Required,
		Tags:              []string{types.ApplicationProfile},
	}
	creator := &RuleFailureCreator{}

	t.Run("present", func(t *testing.T) {
		objCache := newK8sLookupSpy()
		objCache.SetContainerProfileState(&objectcache.ProfileState{Status: helpersv1.Completed, Name: "real-cp"})
		ruleFailure := &types.GenericRuleFailure{TriggerEvent: &MockEnrichEvent{containerID: "real-container"}}
		creator.setProfileMetadata(rule, ruleFailure, objCache)
		pm := ruleFailure.GetBaseRuntimeAlert().ProfileMetadata
		require.NotNil(t, pm)
		assert.Equal(t, "real-cp", pm.Name)
		assert.Empty(t, pm.Error)
	})

	t.Run("absent (early lifecycle)", func(t *testing.T) {
		objCache := newK8sLookupSpy()
		ruleFailure := &types.GenericRuleFailure{TriggerEvent: &MockEnrichEvent{containerID: "real-container"}}
		creator.setProfileMetadata(rule, ruleFailure, objCache)
		pm := ruleFailure.GetBaseRuntimeAlert().ProfileMetadata
		require.NotNil(t, pm, "profile metadata must still be attached so the error reaches alert consumers")
		assert.NotEmpty(t, pm.Error)
	})
}
