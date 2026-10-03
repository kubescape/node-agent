package storage

import (
	"context"
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestStorageHttpClientMock_ListContainerProfiles(t *testing.T) {
	mock := &StorageHttpClientMock{
		ContainerProfiles: []*v1beta1.ContainerProfile{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cp-1",
					Namespace: "default",
					Labels: map[string]string{
						"app": "frontend",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cp-2",
					Namespace: "default",
					Labels: map[string]string{
						"app": "backend",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cp-3",
					Namespace: "other",
					Labels: map[string]string{
						"app": "frontend",
					},
				},
			},
		},
	}

	// 1. List all in default namespace
	list, err := mock.ListContainerProfiles(context.Background(), "default", metav1.ListOptions{})
	require.NoError(t, err)
	assert.Len(t, list.Items, 2)

	// 2. List with label selector in default namespace
	list, err = mock.ListContainerProfiles(context.Background(), "default", metav1.ListOptions{
		LabelSelector: "app=frontend",
	})
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	assert.Equal(t, "cp-1", list.Items[0].Name)

	// 3. List in other namespace
	list, err = mock.ListContainerProfiles(context.Background(), "other", metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	assert.Equal(t, "cp-3", list.Items[0].Name)

	// 4. List in non-existent namespace
	list, err = mock.ListContainerProfiles(context.Background(), "nonexistent", metav1.ListOptions{})
	require.NoError(t, err)
	assert.Empty(t, list.Items)

	// 5. List cluster-wide across all namespaces (metav1.NamespaceAll / "")
	list, err = mock.ListContainerProfiles(context.Background(), metav1.NamespaceAll, metav1.ListOptions{})
	require.NoError(t, err)
	assert.Len(t, list.Items, 3)

	// 6. List cluster-wide with label selector
	list, err = mock.ListContainerProfiles(context.Background(), metav1.NamespaceAll, metav1.ListOptions{
		LabelSelector: "app=frontend",
	})
	require.NoError(t, err)
	assert.Len(t, list.Items, 2)

	// 7. Invalid label selector returns error
	_, err = mock.ListContainerProfiles(context.Background(), "default", metav1.ListOptions{
		LabelSelector: "invalid===selector",
	})
	require.Error(t, err)
}
