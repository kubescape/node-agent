//go:build component
// +build component

package tests

import (
	"node-agent/pkg/utils"
	"node-agent/tests/testutils"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func tearDownTest(t *testing.T, startTime time.Time) {
	end := time.Now()

	t.Log("Waiting 60 seconds for Prometheus to scrape the data")
	time.Sleep(1 * time.Minute)

	err := testutils.PlotNodeAgentPrometheusCPUUsage(t.Name(), startTime, end)
	if err != nil {
		t.Errorf("Error plotting CPU usage: %v", err)
	}

	_, err = testutils.PlotNodeAgentPrometheusMemoryUsage(t.Name(), startTime, end)
	if err != nil {
		t.Errorf("Error plotting memory usage: %v", err)
	}
}

func Test_01_BasicAlertTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := testutils.NewRandomNamespace()
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}
	err = wl.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	err = wl.WaitForApplicationProfileCompletion(80)
	if err != nil {
		t.Errorf("Error waiting for application profile to be completed: %v", err)
	}

	time.Sleep(10 * time.Second)

	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"})
	if err != nil {
		t.Errorf("Error executing remote command: %v", err)
	}

	// Wait for the alert to be signaled
	time.Sleep(5 * time.Second)

	alerts, err := testutils.GetAlerts(wl.Namespace)
	if err != nil {
		t.Errorf("Error getting alerts: %v", err)
	}
	expectedRuleName := "Unexpected process launched"

	for _, alert := range alerts {
		ruleName, ruleOk := alert.Labels["rule_name"]
		if ruleOk && ruleName == expectedRuleName {
			return
		}
	}

	/*

		// FIXME: Something this is not working
		expectedRuleName := "Unexpected process launched"
		expectedCommand := "ls"

		for _, alert := range alerts {
			ruleName, ruleOk := alert.Labels["rule_name"]
			command, cmdOk := alert.Labels["comm"]

			if ruleOk && cmdOk && ruleName == expectedRuleName && command == expectedCommand {
				return
			}
		}
	*/

	t.Errorf("Expected alert not found")
}

func Test_02_AllAlertsFromMaliciousApp(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// Create a random namespace
	ns := testutils.NewRandomNamespace()

	// Create a workload
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/malicious-job.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}

	// Wait for the workload to be ready
	err = wl.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	// Malicious activity will be detected in 3 minutes + X seconds to wait for the alerts to be generated
	maliciousAppWaitBeforeStart := time.Minute * 3
	waitBeforeLookingForAlerts := time.Minute * 2
	timer := time.NewTimer(maliciousAppWaitBeforeStart + waitBeforeLookingForAlerts)

	// Wait for the application profile to be created and completed
	err = wl.WaitForApplicationProfileCompletion(80)
	if err != nil {
		t.Errorf("Error waiting for application profile to be completed: %v", err)
	}

	// Wait for the alerts to be generated
	<-timer.C

	// Get all the alerts for the namespace
	alerts, err := testutils.GetAlerts(wl.Namespace)
	if err != nil {
		t.Errorf("Error getting alerts: %v", err)
	}

	// Validate that all alerts are signaled
	expectedAlerts := map[string]bool{
		"Unexpected process launched":              false,
		"Unexpected file access":                   false,
		"Unexpected system call":                   false,
		"Unexpected capability used":               false,
		"Kubernetes Client Executed":               false,
		"Exec from malicious source":               false,
		"Kernel Module Load":                       false,
		"Exec Binary Not In Base Image":            false,
		"Exec from mount":                          false,
		"Unexpected Service Account Token Access":  false,
		"Unexpected domain request":                false,
		"Crypto Mining Related Port Communication": false,
		"Crypto Mining Domain Communication":       false,
	}

	for _, alert := range alerts {
		ruleName, ruleOk := alert.Labels["rule_name"]
		if ruleOk {
			if _, exists := expectedAlerts[ruleName]; exists {
				expectedAlerts[ruleName] = true
			}
		}
	}

	for ruleName, signaled := range expectedAlerts {
		if !signaled {
			t.Errorf("Expected alert '%s' was not signaled", ruleName)
		}
	}
}

func Test_03_BasicLoadActivities(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// Create a random namespace
	ns := testutils.NewRandomNamespace()

	// Create a workload
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}

	// Wait for the workload to be ready
	err = wl.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	// Wait for the application profile to be created and completed
	err = wl.WaitForApplicationProfileCompletion(80)
	if err != nil {
		t.Errorf("Error waiting for application profile to be completed: %v", err)
	}

	// Create loader
	loader, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/locust-deployment.yaml"))
	err = loader.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	loadStart := time.Now()

	// Create a load of 5 minutes
	time.Sleep(5 * time.Minute)

	loadEnd := time.Now()

	// Get CPU usage of Node Agent pods
	podToCpuUsage, err := testutils.GetNodeAgentAverageCPUUsage(loadStart, loadEnd)
	if err != nil {
		t.Errorf("Error getting CPU usage: %v", err)
	}

	if len(podToCpuUsage) == 0 {
		t.Errorf("No CPU usage data found")
	}

	for pod, cpuUsage := range podToCpuUsage {
		assert.LessOrEqual(t, cpuUsage, 0.4, "CPU usage of Node Agent is too high. CPU usage is %f, Pod: %s", cpuUsage, pod)
	}
}

func Test_04_MemoryLeak(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// Create a random namespace
	ns := testutils.NewRandomNamespace()

	// Create 2 workloads
	wlPaths := []string{
		"resources/locust-deployment.yaml",
		"resources/nginx-deployment.yaml",
	}
	workloads := []testutils.TestWorkload{}
	for _, p := range wlPaths {
		wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), p))
		if err != nil {
			t.Errorf("Error creating deployment: %v", err)
		}
		workloads = append(workloads, *wl)
	}
	for _, wl := range workloads {
		err := wl.WaitForReady(80)
		if err != nil {
			t.Errorf("Error waiting for workload to be ready: %v", err)
		}
		err = wl.WaitForApplicationProfileCompletion(80)
		if err != nil {
			t.Errorf("Error waiting for application profile to be completed: %v", err)
		}
	}

	// Wait for 60 seconds for the GC to run, so the memory leak can be detected
	time.Sleep(60 * time.Second)

	metrics, err := testutils.PlotNodeAgentPrometheusMemoryUsage("memleak_basic", start, time.Now())
	if err != nil {
		t.Errorf("Error plotting memory usage: %v", err)
	}

	if len(metrics) == 0 {
		t.Errorf("No memory usage data found")
	}

	for _, metric := range metrics {
		podName := metric.Name
		firstValue := metric.Values[0]
		lastValue := metric.Values[len(metric.Values)-1]

		// Validate that there is no memory leak, but tolerate 50Mb memory leak
		tolerateMb := 50
		assert.LessOrEqual(t, lastValue, firstValue+float64(tolerateMb*1024*1024), "Memory leak detected in node-agent pod (%s). Memory usage at the end of the test is %f and at the beginning of the test is %f", podName, lastValue, firstValue)
	}
}

func Test_05_MemoryLeak_10K_Alerts(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// Create a random namespace
	ns := testutils.NewRandomNamespace()

	// Create nginx workload
	nginx, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}
	err = nginx.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	err = nginx.WaitForApplicationProfileCompletion(80)
	if err != nil {
		t.Errorf("Error waiting for application profile to be completed: %v", err)
	}

	// wait for 300 seconds for the GC to run, so the memory leak can be detected
	t.Log("Waiting 300 seconds to have a baseline memory usage")
	time.Sleep(300 * time.Second)

	//Exec into the nginx pod and create a file in the /tmp directory in a loop
	startLoad := time.Now()
	for i := 0; i < 100; i++ {
		_, _, err := nginx.ExecIntoPod([]string{"bash", "-c", "for i in {1..100}; do touch /tmp/nginx-test-$i; done"})
		if err != nil {
			t.Errorf("Error executing remote command: %v", err)
		}
		if i%5 == 0 {
			t.Logf("Created file %d times", (i+1)*100)
		}
	}

	// wait for 300 seconds for the GC to run, so the memory leak can be detected
	t.Log("Waiting 300 seconds to GC to run")
	time.Sleep(300 * time.Second)

	metrics, err := testutils.PlotNodeAgentPrometheusMemoryUsage("memleak_10k_alerts", startLoad, time.Now())
	if err != nil {
		t.Errorf("Error plotting memory usage: %v", err)
	}

	if len(metrics) == 0 {
		t.Errorf("No memory usage data found")
	}

	for _, metric := range metrics {
		podName := metric.Name
		firstValue := metric.Values[0]
		lastValue := metric.Values[len(metric.Values)-1]

		// Validate that there is no memory leak, but tolerate 40mb memory leak
		tolerateMb := 40
		assert.LessOrEqual(t, lastValue, firstValue+float64(tolerateMb*1024*1024), "Memory leak detected in node-agent pod (%s). Memory usage at the end of the test is %f and at the beginning of the test is %f", podName, lastValue, firstValue)
	}
}

func Test_06_KillProcessInTheMiddle(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// Create a random namespace
	ns := testutils.NewRandomNamespace()
	// Create nginx deployment
	nginx, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/nginx-deployment.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}
	err = nginx.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	// Wait for the application profile to be created and 'ready' (not 'completed')
	err = nginx.WaitForApplicationProfile(80, "ready")
	if err != nil {
		t.Errorf("Error waiting for application profile to be 'ready': %v", err)
	}

	// Exec into the nginx pod and kill the process
	_, _, err = nginx.ExecIntoPod([]string{"bash", "-c", "kill -9 1"})
	if err != nil {
		t.Errorf("Error executing remote command: %v", err)
	}

	// Wait for the application profile to be 'completed'
	err = nginx.WaitForApplicationProfileCompletion(20)
	if err != nil {
		t.Errorf("Error waiting for application profile to be completed: %v", err)
	}
}

func Test_07_RuleBindingApplyTest(t *testing.T) {
	ruleBindingPath := func(name string) string {
		return path.Join(utils.CurrentDir(), "resources/rulebindings", name)
	}

	// valid
	exitCode := testutils.RunCommand("kubectl", "apply", "-f", ruleBindingPath("all-valid.yaml"))
	assert.Equal(t, 0, exitCode, "Error applying valid rule binding")
	_ = testutils.RunCommand("kubectl", "delete", "-f", ruleBindingPath("all-valid.yaml"))

	// invalid fields
	file := ruleBindingPath("invalid-name.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "-f", file)
	assert.NotEqualf(t, 0, exitCode, "Expected error when applying rule binding '%s'", file)

	file = ruleBindingPath("invalid-id.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "-f", file)
	assert.NotEqualf(t, 0, exitCode, "Expected error when applying rule binding '%s'", file)

	file = ruleBindingPath("invalid-tag.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "-f", file)
	assert.NotEqualf(t, 0, exitCode, "Expected error when applying rule binding '%s'", file)

	// duplicate fields
	file = ruleBindingPath("dup-fields-name-tag.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "-f", file)
	assert.NotEqualf(t, 0, exitCode, "Expected error when applying rule binding '%s'", file)

	file = ruleBindingPath("dup-fields-name-id.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "-f", file)
	assert.NotEqualf(t, 0, exitCode, "Expected error when applying rule binding '%s'", file)

	file = ruleBindingPath("dup-fields-id-tag.yaml")
	exitCode = testutils.RunCommand("kubectl", "apply", "-f", file)
	assert.NotEqualf(t, 0, exitCode, "Expected error when applying rule binding '%s'", file)
}

// TODO: create a test with an existing app profile and check if the alerts are generated
//func Test_08_BasicAlertTestExistingProfile(t *testing.T) {
//
//}
