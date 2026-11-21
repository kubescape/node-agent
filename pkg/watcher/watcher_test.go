package watcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
)

func TestMakeEventKey(t *testing.T) {
	pod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kubescape",
			Name:      "node-agent-abc",
		},
	}

	gotPodKey := MakeEventKey(watch.Event{
		Type:   watch.Added,
		Object: pod,
	})
	assert.Equal(t, "/v1/Pod/kubescape/node-agent-abc", gotPodKey)

	deploy := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "web",
		},
	}

	gotDeployKey := MakeEventKey(watch.Event{
		Type:   watch.Modified,
		Object: deploy,
	})
	assert.Equal(t, "apps/v1/Deployment/default/web", gotDeployKey)
}

func TestWatchResourceImpl(t *testing.T) {
	gvr := schema.GroupVersionResource{
		Group:    "spdx.softwarecomposition.kubescape.io",
		Version:  "v1beta1",
		Resource: "applicationprofiles",
	}
	opts := metav1.ListOptions{
		LabelSelector: "app=demo",
		FieldSelector: "metadata.namespace=default",
	}

	wr := NewWatchResource(gvr, opts)
	require.NotNil(t, wr)
	assert.Equal(t, gvr, wr.GroupVersionResource())
	assert.Equal(t, opts, wr.ListOptions())
}

func TestWatchResourceMocks(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	opts := metav1.ListOptions{ResourceVersion: "42"}

	mockRes := &WatchResourceMock{
		Schema:  gvr,
		ListOpt: opts,
	}
	assert.Equal(t, gvr, mockRes.GroupVersionResource())
	assert.Equal(t, opts, mockRes.ListOptions())

	mockCollection := &WatchResourcesMock{}
	resources := mockCollection.WatchResources()
	require.Len(t, resources, 1)
	assert.Equal(t, schema.GroupVersionResource{}, resources[0].GroupVersionResource())
	assert.Equal(t, metav1.ListOptions{}, resources[0].ListOptions())
}
