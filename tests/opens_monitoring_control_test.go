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

// waitForProfileMonitoring proves the container and its profile are active before
// an assertion can interpret silence or count alerts. Callers exclude uname
// from their exec arguments and count only the command under test. BusyBox
// applets may share an allowed executable, so either an unexpected executable
// or unexpected arguments must demonstrate live profile enforcement.
func waitForProfileMonitoring(t *testing.T, wl *testutils.TestWorkload, container string) {
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
			if (alert.Labels["rule_id"] == "R0001" || alert.Labels["rule_id"] == "R0040") &&
				alert.Labels["comm"] == "uname" &&
				alert.Labels["container_name"] == container &&
				alert.Labels["fail_on_profile"] == "true" {
				return true, nil
			}
		}
		return false, nil
	})
	require.NoError(t, err,
		"monitoring control must produce a profile-backed exec or argument uname alert (R0001/R0040) for %s/%s before profile assertions (last alert fetch error: %v)",
		wl.Namespace, container, lastFetchErr)
}
