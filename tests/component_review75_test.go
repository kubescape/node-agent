//go:build component

package tests

import (
	"context"
	"encoding/json"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/node-agent/tests/testutils"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func countRuleAlerts(t *testing.T, ns, ruleID, container, comm string) int {
	t.Helper()
	alerts, _ := testutils.GetAlerts(ns)
	n := 0
	for _, a := range alerts {
		if a.Labels["rule_id"] == ruleID &&
			(container == "" || a.Labels["container_name"] == container) &&
			(comm == "" || a.Labels["comm"] == comm) {
			n++
		}
	}
	return n
}

// withNodeAgentConfig mutates the node-agent config.json ConfigMap, restarts the
// DaemonSet, and returns a restore func that reverts the change and restarts again.
func withNodeAgentConfig(t *testing.T, mutate func(cfg map[string]any)) func() {
	t.Helper()
	const nsKS, cmName = "kubescape", "node-agent"
	k8s := k8sinterface.NewKubernetesApi()
	cm, err := k8s.KubernetesClient.CoreV1().ConfigMaps(nsKS).Get(context.Background(), cmName, metav1.GetOptions{})
	require.NoError(t, err, "get node-agent ConfigMap")
	original := cm.Data["config.json"]

	var cfg map[string]any
	require.NoError(t, json.Unmarshal([]byte(original), &cfg), "parse config.json")
	mutate(cfg)
	updated, err := json.MarshalIndent(cfg, "", "  ")
	require.NoError(t, err, "marshal config.json")

	apply := func(body string) {
		c, e := k8s.KubernetesClient.CoreV1().ConfigMaps(nsKS).Get(context.Background(), cmName, metav1.GetOptions{})
		require.NoError(t, e)
		c.Data["config.json"] = body
		_, e = k8s.KubernetesClient.CoreV1().ConfigMaps(nsKS).Update(context.Background(), c, metav1.UpdateOptions{})
		require.NoError(t, e, "update node-agent ConfigMap")
		require.NoError(t, testutils.RestartDaemonSet(nsKS, cmName), "restart node-agent")
		time.Sleep(45 * time.Second)
	}
	apply(string(updated))
	return func() { apply(original) }
}

// Test_12_AuthoredMultiSubtypeProfile pins the reintroduced authored multi-container
// document: one ContainerProfile with containers[]/initContainers[]/ephemeralContainers[]
// subtype sections keyed by name, each enforced only against its own container.
func Test_12_AuthoredMultiSubtypeProfile(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()
	_ = applyUserDefinedContainerProfile(t, ns.Name, "resources/mc37-cp.yaml")

	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/mc37-multi-subtype-userdefined-deployment.yaml"))
	require.NoError(t, err, "create mc37 workload")
	require.NoError(t, wl.WaitForReady(120), "workload ready")
	time.Sleep(30 * time.Second)

	// app section resolved: a command IN the app section is quiet, one NOT in it alerts.
	require.Eventually(t, func() bool {
		_, _, _ = wl.ExecIntoPod([]string{"/usr/bin/id"}, "app")
		return countRuleAlerts(t, ns.Name, "R0001", "app", "id") > 0
	}, 2*time.Minute, 10*time.Second, "id is not in the app subtype — must fire R0001 in app")

	require.Eventually(t, func() bool {
		_, _, _ = wl.ExecIntoPod([]string{"/usr/bin/cat", "/etc/hostname"}, "app")
		time.Sleep(8 * time.Second)
		return countRuleAlerts(t, ns.Name, "R0001", "app", "cat") == 0
	}, 2*time.Minute, 12*time.Second, "cat IS in the app subtype — must NOT fire R0001 (empty/whole-doc resolution would alert)")

	// initContainers section resolved: the init container's own id (in its section) does not alert.
	require.Equal(t, 0, countRuleAlerts(t, ns.Name, "R0001", "setup", "id"),
		"id IS in the initContainers[setup] subtype — the init container's id must not alert")
}

// Test_13_NaturalLearningLifecycle restores the learn -> interrupt(restart) -> re-learn
// -> enforce cycle: a command absent from the learned profile alerts; the same command,
// executed during a fresh learning window after a deployment restart, is learned and
// then no longer alerts. Uses a non-busybox image so the alert is R0001, not R0040.
func Test_13_NaturalLearningLifecycle(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/review75-learn-deployment.yaml"))
	require.NoError(t, err, "create learner workload")
	require.NoError(t, wl.WaitForReady(80), "workload ready")
	require.NoError(t, wl.WaitForContainerProfileCompletion(30), "initial profile completion")
	time.Sleep(20 * time.Second)

	stale, err := wl.GetContainerProfiles()
	require.NoError(t, err, "list initial profiles")
	staleNames := make([]string, 0, len(stale))
	for i := range stale {
		staleNames = append(staleNames, stale[i].Name)
	}

	require.Eventually(t, func() bool {
		_, _, _ = wl.ExecIntoPod([]string{"/usr/bin/id"}, "app")
		return countRuleAlerts(t, ns.Name, "R0001", "app", "id") > 0
	}, 2*time.Minute, 10*time.Second, "id absent from the learned profile must fire R0001")

	require.NoError(t, testutils.RestartDeployment(ns.Name, "r75learn"), "restart to reset learning")
	require.NoError(t, wl.WaitForReady(80), "workload ready after restart")
	for i := 0; i < 8; i++ {
		_, _, _ = wl.ExecIntoPod([]string{"/usr/bin/id"}, "app")
		time.Sleep(8 * time.Second)
	}
	require.NoError(t, wl.WaitForContainerProfileCompletionWithBlacklist(30, staleNames), "re-learned profile completion")
	time.Sleep(20 * time.Second)

	before := countRuleAlerts(t, ns.Name, "R0001", "app", "id")
	for i := 0; i < 4; i++ {
		_, _, _ = wl.ExecIntoPod([]string{"/usr/bin/id"}, "app")
		time.Sleep(3 * time.Second)
	}
	time.Sleep(20 * time.Second)
	require.Equal(t, before, countRuleAlerts(t, ns.Name, "R0001", "app", "id"),
		"id executed during the learning window must be in the re-learned profile — no new R0001")
}

// Test_25_RuleCooldownExactThreshold isolates the cooldown from any profile reload by
// binding a static authored profile (never re-learns): 20 identical unlisted execs yield
// exactly ruleCooldownAfterCount (10) alerts, and further execs add none.
func Test_25_RuleCooldownExactThreshold(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()
	_ = applyUserDefinedContainerProfile(t, ns.Name, "resources/review75-static-cp.yaml")
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/review75-static-deployment.yaml"))
	require.NoError(t, err, "create static workload")
	require.NoError(t, wl.WaitForReady(80), "workload ready")
	time.Sleep(40 * time.Second)

	for i := 0; i < 20; i++ {
		_, _, _ = wl.ExecIntoPod([]string{"/usr/bin/id"}, "app")
		time.Sleep(1 * time.Second)
	}
	time.Sleep(30 * time.Second)
	require.Equal(t, 10, countRuleAlerts(t, ns.Name, "R0001", "app", "id"),
		"cooldown must cap identical alerts at ruleCooldownAfterCount (10) despite 20 execs")

	for i := 0; i < 10; i++ {
		_, _, _ = wl.ExecIntoPod([]string{"/usr/bin/id"}, "app")
		time.Sleep(1 * time.Second)
	}
	time.Sleep(30 * time.Second)
	require.Equal(t, 10, countRuleAlerts(t, ns.Name, "R0001", "app", "id"),
		"once cooled down, further identical execs add no alerts (suppression holds for ruleCooldownDuration)")
}

// Test_30_IgnoreExcludeAndLearningDuration pins that the exclude flags actually drop a
// container (no profile, no monitoring) and that the learning duration is governed by
// maxSniffingTimePerContainer.
func Test_30_IgnoreExcludeAndLearningDuration(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	t.Run("ExcludeFlagsDropContainer", func(t *testing.T) {
		excluded := testutils.NewRandomNamespace()
		control := testutils.NewRandomNamespace()
		restore := withNodeAgentConfig(t, func(cfg map[string]any) {
			cfg["excludeNamespaces"] = []string{excluded.Name}
			cfg["excludeLabels"] = map[string][]string{"r75-skip": {"true"}}
		})
		defer restore()

		exNS, err := testutils.NewTestWorkload(excluded.Name, path.Join(utils.CurrentDir(), "resources/review75-learn-deployment.yaml"))
		require.NoError(t, err, "excluded-namespace workload")
		require.NoError(t, exNS.WaitForReady(80))
		ctl, err := testutils.NewTestWorkload(control.Name, path.Join(utils.CurrentDir(), "resources/review75-learn-deployment.yaml"))
		require.NoError(t, err, "control workload")
		require.NoError(t, ctl.WaitForReady(80))

		time.Sleep(90 * time.Second)

		exCPs, _ := exNS.GetContainerProfiles()
		require.Empty(t, exCPs, "an excluded-namespace workload must produce NO ContainerProfile")
		ctlCPs, _ := ctl.GetContainerProfiles()
		require.NotEmpty(t, ctlCPs, "a non-excluded workload must still be profiled (exclusion must be selective)")

		for i := 0; i < 5; i++ {
			_, _, _ = exNS.ExecIntoPod([]string{"/usr/bin/id"}, "app")
			time.Sleep(2 * time.Second)
		}
		time.Sleep(20 * time.Second)
		require.Equal(t, 0, countRuleAlerts(t, excluded.Name, "R0001", "app", "id"),
			"an excluded container must generate no alerts")
	})

	t.Run("LearningDurationOverride", func(t *testing.T) {
		restore := withNodeAgentConfig(t, func(cfg map[string]any) {
			cfg["maxSniffingTimePerContainer"] = "45s"
			cfg["initialDelay"] = "10s"
		})
		defer restore()

		ns := testutils.NewRandomNamespace()
		wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/review75-learn-deployment.yaml"))
		require.NoError(t, err, "workload")
		require.NoError(t, wl.WaitForReady(80))

		deadline := time.Now().Add(90 * time.Second)
		require.NoError(t, wl.WaitForContainerProfileCompletion(90), "profile must complete within the shortened window")
		require.True(t, time.Now().Before(deadline),
			"completion must track the configured maxSniffingTimePerContainer, not a longer default")
	})
}

// Test_49_EphemeralContainerFullTreatment pins that an ephemeral container is
// learned, detected, and alerted on exactly like a regular container: a
// ContainerProfile is generated for it, and an exec not seen during learning
// fires R0001.
func Test_49_EphemeralContainerFullTreatment(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/review75-learn-deployment.yaml"))
	require.NoError(t, err, "create workload")
	require.NoError(t, wl.WaitForReady(80), "workload ready")

	require.NoError(t, wl.AddEphemeralContainer("ephcon", "debian:12-slim", []string{"/usr/bin/sleep", "infinity"}, 120),
		"attach ephemeral container")

	require.Eventually(t, func() bool {
		cps, e := wl.GetContainerProfiles()
		if e != nil {
			return false
		}
		for i := range cps {
			if strings.Contains(cps[i].Name, "ephcon") && cps[i].Annotations["kubescape.io/status"] == "completed" {
				return true
			}
		}
		return false
	}, 4*time.Minute, 10*time.Second, "an ephemeral container must be LEARNED — a completed ContainerProfile must exist for it (full treatment)")

	require.Eventually(t, func() bool {
		_, _, _ = wl.ExecIntoPod([]string{"/usr/bin/id"}, "ephcon")
		return countRuleAlerts(t, ns.Name, "R0001", "ephcon", "id") > 0
	}, 2*time.Minute, 10*time.Second, "id was not in the ephemeral container's learned profile — it must fire R0001 (detected + alerted like any other container)")
}
