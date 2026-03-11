package profiles

import (
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNetworkNeighborhoodAdapter(t *testing.T) {
	nn := &v1beta1.NetworkNeighborhood{
		TypeMeta: metav1.TypeMeta{
			Kind:       "NetworkNeighborhood",
			APIVersion: "spdx.softwarecomposition.kubescape.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-nn",
			Namespace: "test-ns",
			UID:       "test-uid",
			Annotations: map[string]string{
				"existing": "annotation",
			},
		},
		Spec: v1beta1.NetworkNeighborhoodSpec{
			Containers: []v1beta1.NetworkNeighborhoodContainer{
				{
					Name: "test-container",
					Ingress: []v1beta1.NetworkNeighbor{
						{
							Identifier: "test-neighbor",
						},
					},
				},
			},
		},
	}

	adapter := NewNetworkNeighborhoodAdapter(nn)

	assert.Equal(t, "test-nn", adapter.GetName())
	assert.Equal(t, "test-ns", adapter.GetNamespace())
	assert.Equal(t, "test-uid", adapter.GetUID())

	annotations := adapter.GetAnnotations()
	assert.Equal(t, "annotation", annotations["existing"])

	newAnnotations := map[string]string{"new": "annotation"}
	adapter.SetAnnotations(newAnnotations)
	assert.Equal(t, newAnnotations, nn.Annotations)

	content := adapter.GetContent().(map[string]interface{})
	assert.Equal(t, "NetworkNeighborhood", content["kind"])
	assert.Equal(t, "spdx.softwarecomposition.kubescape.io/v1beta1", content["apiVersion"])

	metadata := content["metadata"].(map[string]interface{})
	assert.Equal(t, "test-nn", metadata["name"])
	assert.Equal(t, "test-ns", metadata["namespace"])

	spec := content["spec"].(v1beta1.NetworkNeighborhoodSpec)
	assert.Equal(t, 1, len(spec.Containers))
	assert.Equal(t, "test-container", spec.Containers[0].Name)

	assert.Equal(t, nn, adapter.GetUpdatedObject())
}

func TestNetworkNeighborhoodAdapter_EmptyTypeMeta(t *testing.T) {
	nn := &v1beta1.NetworkNeighborhood{
		TypeMeta: metav1.TypeMeta{
			Kind:       "",
			APIVersion: "",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-nn",
			Namespace: "test-ns",
		},
		Spec: v1beta1.NetworkNeighborhoodSpec{
			Containers: []v1beta1.NetworkNeighborhoodContainer{
				{
					Name: "test-container",
				},
			},
		},
	}

	adapter := NewNetworkNeighborhoodAdapter(nn)
	content := adapter.GetContent().(map[string]interface{})

	assert.Equal(t, "NetworkNeighborhood", content["kind"])
	assert.Equal(t, "spdx.softwarecomposition.kubescape.io/v1beta1", content["apiVersion"])

	metadata := content["metadata"].(map[string]interface{})
	assert.Equal(t, "test-nn", metadata["name"])
	assert.Equal(t, "test-ns", metadata["namespace"])

	spec := content["spec"].(v1beta1.NetworkNeighborhoodSpec)
	assert.Equal(t, 1, len(spec.Containers))
	assert.Equal(t, "test-container", spec.Containers[0].Name)
}
