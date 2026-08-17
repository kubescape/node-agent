package containerprofilecache

import (
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Pins the one narrative both add (tryPopulateEntry) and refresh (refreshOneEntry) share via resolveAuthoredSection. 404/transient handling around it is in reconciler_notfound_test.go.
func TestResolveAuthoredSection_SharedNarrative(t *testing.T) {
	flat := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "flat", Namespace: "default"},
		Spec:       v1beta1.ContainerProfileSpec{Capabilities: []string{"SYS_ADMIN"}},
	}
	grouped := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "grouped", Namespace: "default"},
		Spec: v1beta1.ContainerProfileSpec{
			Containers: []v1beta1.ContainerProfileContainer{{Name: "app", Capabilities: []string{"NET_ADMIN"}}},
		},
	}
	learned := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "learned", Namespace: "default",
			Annotations: map[string]string{helpersv1.StatusMetadataKey: helpersv1.Completed},
		},
		Spec: v1beta1.ContainerProfileSpec{Capabilities: []string{"SYS_ADMIN"}},
	}

	t.Run("nil-in-nil-out", func(t *testing.T) {
		assert.Nil(t, resolveAuthoredSection(nil, "app", "n", "id", "default"))
	})
	t.Run("flat-passes-through", func(t *testing.T) {
		assert.Same(t, flat, resolveAuthoredSection(flat, "app", "flat", "id", "default"),
			"a flat authored document is the container's profile")
	})
	t.Run("grouped-covered-selects-section", func(t *testing.T) {
		got := resolveAuthoredSection(grouped, "app", "grouped", "id", "default")
		assert.NotNil(t, got)
		assert.Equal(t, []string{"NET_ADMIN"}, got.Spec.Capabilities)
	})
	t.Run("grouped-not-covered-is-nil", func(t *testing.T) {
		assert.Nil(t, resolveAuthoredSection(grouped, "sidecar", "grouped", "id", "default"),
			"a grouped document that does not name this container must resolve to nil, never a sibling's profile")
	})
	t.Run("learned-annotation-rejected", func(t *testing.T) {
		assert.Nil(t, resolveAuthoredSection(learned, "app", "learned", "id", "default"),
			"a label that resolves to a learned CP must be ignored")
	})
}
