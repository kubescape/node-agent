package containerprofilecache

// Tests for the multi-container authored-document contract: one ContainerProfile
// document per pod, carrying containers/initContainers/ephemeralContainers
// subtype groups (the shape the legacy AP/NN specs expressed), with the read
// path selecting this container's section by name. Pins the review finding
// that the container subtypes were dropped in the migration and the
// multi-container component fixture only exercised two REGULAR containers.

import (
	"context"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func groupedDoc() *v1beta1.ContainerProfile {
	return &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "mc-doc", Namespace: "default", ResourceVersion: "1"},
		Spec: v1beta1.ContainerProfileSpec{
			Architectures: []string{"amd64"},
			Containers: []v1beta1.ContainerProfileContainer{
				{Name: "app", Execs: []v1beta1.ExecCalls{{Path: "/bin/app", Args: []string{"/bin/app"}}}},
			},
			InitContainers: []v1beta1.ContainerProfileContainer{
				{Name: "setup", Execs: []v1beta1.ExecCalls{{Path: "/bin/setup", Args: []string{"/bin/setup"}}}},
			},
			EphemeralContainers: []v1beta1.ContainerProfileContainer{
				{Name: "debug", Execs: []v1beta1.ExecCalls{{Path: "/bin/debug", Args: []string{"/bin/debug"}}}},
			},
		},
	}
}

func TestResolveAuthoredContainerSection(t *testing.T) {
	doc := groupedDoc()

	t.Run("nil document", func(t *testing.T) {
		assert.Nil(t, resolveAuthoredContainerSection(nil, "app"))
	})

	t.Run("flat document passes through unchanged", func(t *testing.T) {
		flat := &v1beta1.ContainerProfile{
			ObjectMeta: metav1.ObjectMeta{Name: "flat", Namespace: "default"},
			Spec: v1beta1.ContainerProfileSpec{
				Execs: []v1beta1.ExecCalls{{Path: "/bin/only"}},
			},
		}
		assert.Same(t, flat, resolveAuthoredContainerSection(flat, "anything"))
	})

	t.Run("selects by name across all three subtype groups", func(t *testing.T) {
		for name, exec := range map[string]string{
			"app":   "/bin/app",   // containers
			"setup": "/bin/setup", // initContainers
			"debug": "/bin/debug", // ephemeralContainers
		} {
			got := resolveAuthoredContainerSection(doc, name)
			require.NotNil(t, got, "section %q must resolve", name)
			require.Len(t, got.Spec.Execs, 1)
			assert.Equal(t, exec, got.Spec.Execs[0].Path)
			assert.Empty(t, got.Spec.Containers, "flattened view must not carry the groups")
			assert.Empty(t, got.Spec.InitContainers)
			assert.Empty(t, got.Spec.EphemeralContainers)
			assert.Equal(t, []string{"amd64"}, got.Spec.Architectures,
				"pod-level architectures inherited from the document")
			assert.Equal(t, "mc-doc", got.Name,
				"identity stays the document's, so UserCPRef re-fetches the same object")
		}
	})

	t.Run("grouped document not covering the container resolves to nil", func(t *testing.T) {
		assert.Nil(t, resolveAuthoredContainerSection(doc, "not-in-doc"),
			"a container the document does not enumerate has no authored profile")
	})
}

// TestUserDefinedCP_GroupedDocumentPerSubtype drives the add path with ONE
// grouped document bound via the pod label: a regular, an init, and an
// ephemeral container each adopt their own section, with no cross-container
// bleed; a container the document does not cover gets NO profile (stays
// pending) instead of inheriting a sibling's section.
func TestUserDefinedCP_GroupedDocumentPerSubtype(t *testing.T) {
	client := &fakeProfileClient{
		cp:            nil,
		cpErr:         apierrors.NewNotFound(schema.GroupResource{Resource: "containerprofiles"}, "learned"),
		userCPsByName: map[string]*v1beta1.ContainerProfile{"mc-doc": groupedDoc()},
	}
	c, k8s := newTestCache(t, client)
	c.SetProjectionSpec(execsAllSpec("grouped-doc"))

	cases := []struct {
		id, cname, ownExec string
	}{
		{"cid-app", "app", "/bin/app"},
		{"cid-setup", "setup", "/bin/setup"},
		{"cid-debug", "debug", "/bin/debug"},
	}
	allExecs := []string{"/bin/app", "/bin/setup", "/bin/debug"}

	for _, tc := range cases {
		primeSharedData(t, k8s, tc.id, "wlid://cluster-a/namespace-default/deployment-nginx")
		ev := eventContainer(tc.id)
		ev.Runtime.ContainerName = tc.cname
		ev.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "mc-doc"}
		require.NoError(t, c.addContainer(ev, context.Background()))
	}

	for _, tc := range cases {
		entry, ok := c.entries.Load(tc.id)
		require.True(t, ok, "entry present for %s", tc.cname)
		require.NotNil(t, entry.UserCPRef)
		assert.Equal(t, "mc-doc", entry.UserCPRef.Name,
			"%s re-fetches the shared grouped document", tc.cname)
		proj := c.GetProjectedContainerProfile(tc.id)
		require.NotNil(t, proj)
		for _, exec := range allExecs {
			_, has := proj.Execs.Values[exec]
			if exec == tc.ownExec {
				assert.True(t, has, "%s must adopt its own section (%s)", tc.cname, exec)
			} else {
				assert.False(t, has, "%s must NOT see sibling exec %s", tc.cname, exec)
			}
		}
	}

	// A container the grouped document does not cover: no profile, stays pending.
	id := "cid-uncovered"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-nginx")
	ev := eventContainer(id)
	ev.Runtime.ContainerName = "not-in-doc"
	ev.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "mc-doc"}
	require.NoError(t, c.addContainer(ev, context.Background()))
	_, ok := c.entries.Load(id)
	assert.False(t, ok, "uncovered container must not get an entry (would enforce a sibling's profile)")
	assert.Nil(t, c.GetProjectedContainerProfile(id))
}
