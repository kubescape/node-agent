package dynamicwatcher

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/cooldownqueue"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// A subprocess keeps the regression safe even when watchRetry calls os.Exit.
// Stop is deterministic: it precedes delivery of the next watch event/closure.
func TestStoppedQueueDoesNotExitProcess(t *testing.T) {
	if mode := os.Getenv("NODE_AGENT_WATCH_STOP_TEST"); mode != "" {
		q := cooldownqueue.NewCooldownQueue[watch.Event](time.Hour, time.Hour)
		defer q.Stop()
		w := watch.NewRaceFreeFake()
		client := fake.NewClientset()
		calls := 0
		client.PrependWatchReactor("pods", func(ktesting.Action) (bool, watch.Interface, error) {
			calls++
			if mode == "retry-then-stop" && calls == 1 {
				closed := watch.NewRaceFreeFake()
				closed.Stop()
				return true, closed, nil // Unexpected stream closure must still retry.
			}
			q.Stop()
			if mode == "late-event" {
				w.Add(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "late", ResourceVersion: "42"}})
			} else {
				w.Stop()
			}
			return true, w, nil
		})
		wh := NewWatchHandler(&k8sinterface.KubernetesApi{KubernetesClient: client}, nil, func(string) bool { return false })
		defer fmt.Println("normal shutdown cleanup ran")
		wh.watchRetry(context.Background(), resourcePod, metav1.ListOptions{}, q)
		wantCalls := 1
		if mode == "retry-then-stop" {
			wantCalls = 2
		}
		if calls != wantCalls || !w.IsStopped() {
			t.Fatalf("stopped queue retried or left watch running: calls=%d stopped=%t", calls, w.IsStopped())
		}
		return
	}
	for _, mode := range []string{"late-event", "closed-stream", "retry-then-stop"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStoppedQueueDoesNotExitProcess$", "-test.count=1")
			cmd.Env = append(os.Environ(), "NODE_AGENT_WATCH_STOP_TEST="+mode)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("normal queue shutdown terminated process: %v\n%s", err, output)
			}
			if !strings.Contains(string(output), "normal shutdown cleanup ran") {
				t.Fatalf("shutdown skipped deferred cleanup: %s", output)
			}
		})
	}
}
