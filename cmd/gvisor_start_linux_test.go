//go:build linux

package main

import (
	"context"
	"testing"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/gvisor"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGVisorPodIdentityAndNamespacePolicy(t *testing.T) {
	identity := gvisor.Identity{Namespace: "apps", PodName: "sandbox", PodUID: "uid", ContainerName: "app"}
	for _, tc := range []string{"verified", "wrong_uid", "wrong_node", "wrong_namespace", "missing_container", "excluded_namespace", "excluded_label"} {
		t.Run(tc, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "sandbox", UID: "uid", Labels: map[string]string{"ignore": "yes"}}, Spec: corev1.PodSpec{NodeName: "node", Containers: []corev1.Container{{Name: "app"}}}}
			cfg := config.Config{NodeName: "node"}
			switch tc {
			case "wrong_uid":
				pod.UID = "new-uid"
			case "wrong_node":
				pod.Spec.NodeName = "other-node"
			case "wrong_namespace":
				pod.Namespace = "other"
			case "missing_container":
				pod.Spec.Containers = nil
			case "excluded_namespace":
				cfg.ExcludeNamespaces = []string{"apps"}
			case "excluded_label":
				cfg.ExcludeLabels = map[string][]string{"ignore": {"yes"}}
			}
			if got := gVisorPodMatches(identity, pod, cfg); got != (tc == "verified") {
				t.Fatalf("identity/policy accepted=%v", got)
			}
		})
	}
}

func TestGVisorDisabledStartupDoesNoIO(t *testing.T) {
	stop, err := startGVisorCollection(context.Background(), config.Config{}, "", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	stop()
}

func TestGVisorRequiresLogExport(t *testing.T) {
	cfg := config.Config{GVisorStart: gvisor.IntegrationConfig{Enabled: true, SocketPath: "/run/kubescape/starts.sock"}}
	if _, err := startGVisorCollection(context.Background(), cfg, "", nil, false); err == nil {
		t.Fatal("enabled source silently used a no-op exporter")
	}
}
