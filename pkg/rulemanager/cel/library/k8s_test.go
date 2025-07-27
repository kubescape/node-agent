package library_test

import (
	"context"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/objectcache/k8scache"
	"github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/library"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestK8sLibrary(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "127.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "6443")

	mockK8sClient := k8sinterface.NewKubernetesApiMock()

	k8sObjCache, err := k8scache.NewK8sObjectCache("test", mockK8sClient)
	if err != nil {
		t.Fatalf("failed to create k8s object cache: %v", err)
	}

	// Create a proper Pod object and add it to the cache
	testPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "test-container",
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "config-volume",
							MountPath: "/etc/config",
						},
						{
							Name:      "data-volume",
							MountPath: "/var/data",
						},
					},
				},
				{
					Name: "test-container-2",
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "logs-volume",
							MountPath: "/var/logs",
						},
					},
				},
			},
		},
	}

	// Add the pod to the cache directly
	k8sObjCache.AddHandler(context.Background(), testPod)
	objectCache := objectcache.NewObjectCache(k8sObjCache, nil, nil, nil)
	env, err := cel.NewEnv(
		cel.Variable("event", cel.AnyType),
		library.K8s(objectCache.K8sObjectCache()),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	ast, issues := env.Compile("get_container_mount_paths('default', 'test-pod', 'test-container')")
	if issues != nil {
		t.Fatalf("failed to compile expression: %v", issues.Err())
	}

	program, err := env.Program(ast)
	if err != nil {
		t.Fatalf("failed to create program: %v", err)
	}

	result, _, err := program.Eval(map[string]interface{}{
		"event": map[string]interface{}{
			"namespace":     "default",
			"podName":       "test-pod",
			"containerName": "test-container",
		},
	})
	if err != nil {
		t.Fatalf("failed to eval program: %v", err)
	}

	// Assert the expected mount paths
	expectedMountPaths := []string{"/etc/config", "/var/data"}
	actualMountPaths := result.Value().([]string)

	assert.Equal(t, expectedMountPaths, actualMountPaths, "mount paths should match expected values")
}
