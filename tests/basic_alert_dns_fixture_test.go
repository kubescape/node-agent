//go:build component

package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
)

// installBasicAlertDNSFixture runs before the learning workload is created so
// DNS setup cannot consume its learning window. Each name has a different IP:
// sharing an IP could cause the DNS cache to mix the two learned destinations.
// Docker endpoints deliberately sit outside Kubernetes inventory: Pod/Service
// neighbors do not retain the DNSNames this test verifies.
func installBasicAlertDNSFixture(t *testing.T, namespace string) {
	t.Helper()
	client := k8sinterface.NewKubernetesApi().KubernetesClient
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	runDocker := func(ctx context.Context, args ...string) (string, error) {
		command := exec.CommandContext(ctx, "docker", args...)
		var stderr bytes.Buffer
		command.Stderr = &stderr
		stdout, err := command.Output()
		if err != nil {
			return "", fmt.Errorf("docker %v: %w; stdout=%q stderr=%q", args, err, stdout, stderr.String())
		}
		return strings.TrimSpace(string(stdout)), nil
	}
	transport := &http.Transport{}
	httpClient := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	defer transport.CloseIdleConnections()

	var hosts string
	seenIPs := make(map[string]bool)
	for _, name := range []string{"nginx", "server"} {
		id, err := runDocker(ctx, "create", "--network", "kind", "--label", "component-test="+namespace, "nginx:1.25.5")
		require.NoError(t, err, "create %s DNS fixture endpoint", name)
		require.Regexp(t, `^[a-f0-9]{64}$`, id, "Docker must return an exact container ID")
		t.Cleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			if t.Failed() {
				logCtx, logCancel := context.WithTimeout(cleanupCtx, 5*time.Second)
				logs, err := exec.CommandContext(logCtx, "docker", "logs", "--tail", "50", id).CombinedOutput()
				logCancel()
				t.Logf("DNS fixture %s logs: %s (error=%v)", name, logs, err)
			}
			_, err := runDocker(cleanupCtx, "rm", "--force", id)
			assert.NoError(t, err, "delete DNS fixture endpoint %s", id)
		})
		_, err = runDocker(ctx, "start", id)
		require.NoError(t, err, "start %s DNS fixture endpoint", name)
		ip, err := runDocker(ctx, "inspect", "--format", `{{with index .NetworkSettings.Networks "kind"}}{{.IPAddress}}{{end}}`, id)
		require.NoError(t, err, "inspect %s DNS fixture endpoint", name)
		require.NotNil(t, net.ParseIP(ip).To4(), "fixture requires a routable IPv4 address: %q", ip)
		require.False(t, seenIPs[ip], "DNS fixture endpoints must have distinct IPs")
		seenIPs[ip] = true
		var lastErr error
		err = wait.PollUntilContextCancel(ctx, time.Second, true, func(ctx context.Context) (bool, error) {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+ip, nil)
			if err != nil {
				return false, err
			}
			response, err := httpClient.Do(request)
			lastErr = err
			if err != nil {
				return false, nil
			}
			response.Body.Close()
			if response.StatusCode != http.StatusOK {
				lastErr = fmt.Errorf("HTTP status %s", response.Status)
				return false, nil
			}
			return true, nil
		})
		require.NoError(t, err, "wait for %s HTTP fixture (last error: %v)", name, lastErr)
		hosts += fmt.Sprintf("        %s %s.component.test\n", ip, name)
	}

	configMaps := client.CoreV1().ConfigMaps("kube-system")
	cm, err := configMaps.Get(ctx, "coredns", metav1.GetOptions{})
	require.NoError(t, err, "get CoreDNS config")
	original, ok := cm.Data["Corefile"]
	require.True(t, ok, "CoreDNS config must contain Corefile")

	restart := func(ctx context.Context) error {
		patch, err := json.Marshal(map[string]any{"spec": map[string]any{
			"template": map[string]any{"metadata": map[string]any{
				"annotations": map[string]string{"kubectl.kubernetes.io/restartedAt": time.Now().Format(time.RFC3339Nano)},
			}},
		}})
		if err != nil {
			return err
		}
		deployments := client.AppsV1().Deployments("kube-system")
		deployment, err := deployments.Patch(ctx, "coredns", types.MergePatchType, patch, metav1.PatchOptions{})
		if err != nil {
			return err
		}
		return wait.PollUntilContextCancel(ctx, time.Second, true, func(ctx context.Context) (bool, error) {
			current, err := deployments.Get(ctx, "coredns", metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			if current.Spec.Replicas == nil {
				return false, fmt.Errorf("CoreDNS deployment has no replica count")
			}
			replicas := *current.Spec.Replicas
			return replicas > 0 &&
				current.Status.ObservedGeneration >= deployment.Generation &&
				current.Status.UpdatedReplicas == replicas &&
				current.Status.Replicas == replicas &&
				current.Status.AvailableReplicas == replicas &&
				current.Status.ReadyReplicas == replicas, nil
		})
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanupCancel()
		current, err := configMaps.Get(cleanupCtx, "coredns", metav1.GetOptions{})
		if !assert.NoError(t, err, "get CoreDNS config for restoration") {
			return
		}
		current.Data["Corefile"] = original
		_, err = configMaps.Update(cleanupCtx, current, metav1.UpdateOptions{})
		if assert.NoError(t, err, "restore CoreDNS config") {
			assert.NoError(t, restart(cleanupCtx), "wait for restored CoreDNS")
		}
	})

	// A dedicated authoritative zone avoids public DNS and handles both A and
	// AAAA queries without forwarding fixture names outside the cluster.
	cm.Data["Corefile"] = original + "\ncomponent.test:53 {\n    errors\n    hosts {\n" + hosts + "        ttl 1\n    }\n}\n"
	_, err = configMaps.Update(ctx, cm, metav1.UpdateOptions{})
	require.NoError(t, err, "install DNS fixture")
	require.NoError(t, restart(ctx), "wait for CoreDNS fixture rollout")
}
