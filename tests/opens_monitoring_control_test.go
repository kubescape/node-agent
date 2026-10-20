//go:build component

package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kubescape/node-agent/tests/testutils"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/wait"
)

// waitForOpensMonitoring proves the container and its profile are active before
// a file-access assertion can interpret silence as success. The callers exclude
// uname from their exec baseline and filter file-access alerts to comm=cat.
func waitForOpensMonitoring(t *testing.T, wl *testutils.TestWorkload, container string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	var lastFetchErr error
	err := wait.PollUntilContextCancel(ctx, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		stdout, stderr, err := wl.ExecIntoPodNoTTYWithContext(ctx, []string{"uname"}, container)
		if err != nil {
			return false, fmt.Errorf("uname monitoring control in %s: %w; stdout=%q stderr=%q", container, err, stdout, stderr)
		}
		alerts, err := testutils.GetAlertsWithContext(ctx, wl.Namespace)
		lastFetchErr = err
		if err != nil {
			return false, nil
		}
		for _, alert := range alerts {
			if alert.Labels["rule_id"] == "R0001" &&
				alert.Labels["comm"] == "uname" &&
				alert.Labels["container_name"] == container &&
				alert.Labels["fail_on_profile"] == "true" {
				return true, nil
			}
		}
		return false, nil
	})
	require.NoError(t, err,
		"monitoring control must produce a profile-backed R0001 uname alert for %s/%s before file-access assertions (last alert fetch error: %v)",
		wl.Namespace, container, lastFetchErr)
}
