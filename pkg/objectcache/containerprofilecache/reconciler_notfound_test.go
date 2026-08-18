package containerprofilecache

import (
	"context"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type scriptedProfileClient struct {
	byName    map[string]*v1beta1.ContainerProfile
	errByName map[string]error
}

func (s *scriptedProfileClient) GetContainerProfile(_ context.Context, _, name string) (*v1beta1.ContainerProfile, error) {
	if err, ok := s.errByName[name]; ok {
		return nil, err
	}
	if cp, ok := s.byName[name]; ok {
		return cp, nil
	}
	return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "containerprofiles"}, name)
}

func notFound(name string) error {
	return apierrors.NewNotFound(schema.GroupResource{Resource: "containerprofiles"}, name)
}

// Differential oracles for the refresh 404-vs-transient contract (B1 learned / B2 authored / F1 both-gone). Authored-section resolution shared with the add path is covered in resolve_authored_section_test.go.

func TestRefresh_LearnedCP_NotFoundEvictsVsTransientKeeps(t *testing.T) {
	learned := func() *v1beta1.ContainerProfile {
		return &v1beta1.ContainerProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name: "cp", Namespace: "default", ResourceVersion: "100",
				Annotations: map[string]string{
					helpersv1.StatusMetadataKey:     helpersv1.Completed,
					helpersv1.CompletionMetadataKey: helpersv1.Full,
				},
			},
			Spec: v1beta1.ContainerProfileSpec{Capabilities: []string{"SYS_ADMIN"}},
		}
	}

	t.Run("notfound-evicts-learned", func(t *testing.T) {
		client := &scriptedProfileClient{errByName: map[string]error{"cp": notFound("cp")}}
		metrics := newCountingMetrics()
		c := newReconcilerCache(t, client, newControllableK8sCache(), metrics)
		entry := newEntry(learned(), "nginx", "nginx-abc", "default", "uid-1")
		c.entries.Set("c1", entry)

		c.refreshAllEntries(context.Background())

		_, ok := c.entries.Load("c1")
		assert.False(t, ok, "learned 404 with no other source must evict the entry, not freeze or synthesize")
		assert.Equal(t, 1, metrics.eviction("profile_deleted"), "eviction must be reported")
	})

	t.Run("transient-keeps-learned", func(t *testing.T) {
		client := &scriptedProfileClient{errByName: map[string]error{"cp": assertErr{}}}
		c := newReconcilerCache(t, client, newControllableK8sCache(), nil)
		entry := newEntry(learned(), "nginx", "nginx-abc", "default", "uid-1")
		c.entries.Set("c1", entry)

		c.refreshAllEntries(context.Background())

		stored, ok := c.entries.Load("c1")
		require.True(t, ok)
		assert.Same(t, entry, stored, "transient learned error must preserve the entry")
		assert.Equal(t, "100", stored.RV, "transient error must not clear the RV")
	})
}

func TestRefresh_AuthoredCP_NotFoundUnpinsVsTransientKeeps(t *testing.T) {
	for _, learnedStatus := range []string{helpersv1.Completed, helpersv1.Learning} {
		learned := &v1beta1.ContainerProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name: "cp", Namespace: "default", ResourceVersion: "100",
				Annotations: map[string]string{helpersv1.StatusMetadataKey: learnedStatus},
			},
		}
		mkAuthoredEntry := func() *CachedContainerProfile {
			return &CachedContainerProfile{
				Projected:     Apply(nil, learned, nil),
				State:         &objectcache.ProfileState{Status: helpersv1.Completed, Completion: helpersv1.Full, Name: "override"},
				ContainerName: "nginx",
				PodName:       "nginx-abc",
				Namespace:     "default",
				PodUID:        "uid-1",
				CPName:        "cp",
				RV:            "100",
				UserCPRef:     &namespacedName{Namespace: "default", Name: "override"},
				UserCPRV:      "9",
			}
		}

		t.Run("notfound-unpins/learned="+learnedStatus, func(t *testing.T) {
			client := &scriptedProfileClient{byName: map[string]*v1beta1.ContainerProfile{"cp": learned}}
			c := newReconcilerCache(t, client, newControllableK8sCache(), nil)
			c.entries.Set("c1", mkAuthoredEntry())

			c.refreshAllEntries(context.Background())

			stored, ok := c.entries.Load("c1")
			require.True(t, ok)
			assert.Equal(t, "", stored.UserCPRV,
				"authored 404 must clear UserCPRV (unpin) even when learned="+learnedStatus)
			assert.NotEqual(t, "override", stored.State.Name,
				"enforcement must not stay pinned to the deleted authored profile")
		})

		t.Run("transient-keeps/learned="+learnedStatus, func(t *testing.T) {
			client := &scriptedProfileClient{
				byName:    map[string]*v1beta1.ContainerProfile{"cp": learned},
				errByName: map[string]error{"override": assertErr{}},
			}
			c := newReconcilerCache(t, client, newControllableK8sCache(), nil)
			entry := mkAuthoredEntry()
			c.entries.Set("c1", entry)

			c.refreshAllEntries(context.Background())

			stored, ok := c.entries.Load("c1")
			require.True(t, ok)
			assert.Same(t, entry, stored,
				"transient authored error must preserve the entry (learned="+learnedStatus+")")
			assert.Equal(t, "9", stored.UserCPRV, "transient error must not clear UserCPRV")
		})
	}
}

// TestRefresh_AuthoredCP_TransientErrorBeforeFirstFetchKeepsEntry reproduces a
// regression where the authored-CP transient-error guard was gated on
// `e.UserCPRV != ""`, so it never fired while the authored CP had never yet
// been successfully fetched (UserCPRef set, UserCPRV still ""; e.g. right
// after the overlay label was added). If, in that same tick, the learned CP
// ALSO genuinely 404s, refreshOneEntry saw cp == nil && userDefinedCP == nil
// and permanently evicted the entry — even though the authored side only had
// a transient blip, not a real "gone" condition. The entry must be preserved
// regardless of UserCPRV's prior value.
func TestRefresh_AuthoredCP_TransientErrorBeforeFirstFetchKeepsEntry(t *testing.T) {
	priorLearned := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "cp", Namespace: "default", ResourceVersion: "50"},
		Spec:       v1beta1.ContainerProfileSpec{Capabilities: []string{"SYS_ADMIN"}},
	}
	client := &scriptedProfileClient{
		errByName: map[string]error{
			"cp":       notFound("cp"), // learned CP genuinely gone this tick
			"override": assertErr{},    // authored CP fetch fails transiently
		},
	}
	metrics := newCountingMetrics()
	c := newReconcilerCache(t, client, newControllableK8sCache(), metrics)

	entry := &CachedContainerProfile{
		Projected:     Apply(nil, priorLearned, nil),
		State:         &objectcache.ProfileState{Name: "cp"},
		ContainerName: "nginx",
		PodName:       "nginx-abc",
		Namespace:     "default",
		PodUID:        "uid-1",
		CPName:        "cp",
		RV:            "50",
		UserCPRef:     &namespacedName{Namespace: "default", Name: "override"},
		UserCPRV:      "", // authored ref set, never yet fetched successfully
	}
	c.entries.Set("c1", entry)

	c.refreshAllEntries(context.Background())

	stored, ok := c.entries.Load("c1")
	require.True(t, ok, "transient authored-CP error before UserCPRV is set must not evict the entry")
	assert.Same(t, entry, stored, "entry pointer must be unchanged when the authored CP fetch fails transiently")
	assert.Equal(t, 0, metrics.eviction("profile_deleted"), "no eviction must be reported for a transient blip")
}

// TestRefresh_LearnedCP_TransientErrorBeforeFirstFetchKeepsEntry is the
// symmetric case for the learned CP: an entry built purely from an authored
// CP (learned CP never present, so e.RV == "") must also be preserved when
// the learned-CP fetch fails transiently, even if the authored CP genuinely
// 404s in the same tick. Before the fix, the learned-CP guard's
// `e.RV != ""` gate skipped the "keep the entry" return whenever RV was
// still empty, so a transient learned-CP error combined with a genuine
// authored-CP 404 fell through to cp == nil && userDefinedCP == nil and
// evicted the entry — even though the learned side's true state was unknown
// (transient error), not confirmed gone.
func TestRefresh_LearnedCP_TransientErrorBeforeFirstFetchKeepsEntry(t *testing.T) {
	priorAuthored := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "override", Namespace: "default", ResourceVersion: "9"},
		Spec:       v1beta1.ContainerProfileSpec{Capabilities: []string{"SYS_ADMIN"}},
	}
	client := &scriptedProfileClient{
		errByName: map[string]error{
			"cp":       assertErr{},          // learned CP fetch fails transiently
			"override": notFound("override"), // authored CP genuinely gone this tick
		},
	}
	metrics := newCountingMetrics()
	c := newReconcilerCache(t, client, newControllableK8sCache(), metrics)

	entry := &CachedContainerProfile{
		Projected:     Apply(nil, priorAuthored, nil),
		State:         &objectcache.ProfileState{Status: helpersv1.Completed, Completion: helpersv1.Full, Name: "override"},
		ContainerName: "nginx",
		PodName:       "nginx-abc",
		Namespace:     "default",
		PodUID:        "uid-1",
		CPName:        "cp",
		RV:            "", // learned CP genuinely never present; pure authored-only entry
		UserCPRef:     &namespacedName{Namespace: "default", Name: "override"},
		UserCPRV:      "9",
	}
	c.entries.Set("c1", entry)

	c.refreshAllEntries(context.Background())

	stored, ok := c.entries.Load("c1")
	require.True(t, ok, "transient learned-CP error must not evict an entry whose e.RV is still empty")
	assert.Same(t, entry, stored, "entry pointer must be unchanged when the learned CP fetch fails transiently")
	assert.Equal(t, "9", stored.UserCPRV, "transient learned-CP error must not clear UserCPRV")
	assert.Equal(t, 0, metrics.eviction("profile_deleted"), "no eviction must be reported for a transient blip")
}

func TestRefresh_NoSourcesAfterDelete_EvictsInsteadOfSyntheticComplete(t *testing.T) {
	client := &scriptedProfileClient{}
	metrics := newCountingMetrics()
	c := newReconcilerCache(t, client, newControllableK8sCache(), metrics)

	prior := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "override", Namespace: "default"},
		Spec:       v1beta1.ContainerProfileSpec{Capabilities: []string{"SYS_ADMIN"}},
	}
	entry := &CachedContainerProfile{
		Projected:     Apply(nil, prior, nil),
		State:         &objectcache.ProfileState{Status: helpersv1.Completed, Completion: helpersv1.Full, Name: "override"},
		ContainerName: "nginx",
		PodName:       "nginx-abc",
		Namespace:     "default",
		PodUID:        "uid-1",
		CPName:        "cp",
		RV:            "",
		UserCPRef:     &namespacedName{Namespace: "default", Name: "override"},
		UserCPRV:      "9",
	}
	c.entries.Set("c1", entry)

	c.refreshAllEntries(context.Background())

	_, ok := c.entries.Load("c1")
	assert.False(t, ok, "both sources 404 must evict, not fabricate a Completed/Full empty profile")
	assert.Equal(t, 1, metrics.eviction("profile_deleted"), "eviction must be reported")
}
