//go:build integration
// +build integration

package tests

import (
	utilspkg "node-agent/pkg/utils"
	"node-agent/tests/utils"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	kubescapeNamespace = "kubescape"
	namespace          = "default"
	name               = "test"
)

func tearDownTest(t *testing.T, startTime time.Time) {
	end := time.Now()

	t.Log("Waiting 60 seconds for Prometheus to scrape the data")
	time.Sleep(1 * time.Minute)

	err := utils.PlotNodeAgentPrometheusCPUUsage(t.Name(), startTime, end)
	if err != nil {
		t.Errorf("Error plotting CPU usage: %v", err)
	}

	_, err = utils.PlotNodeAgentPrometheusMemoryUsage(t.Name(), startTime, end)
	if err != nil {
		t.Errorf("Error plotting memory usage: %v", err)
	}
}

func TestBasicAlertTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := utils.NewRandomNamespace()
	wl, err := utils.NewTestWorkload(ns.Name, path.Join(utilspkg.CurrentDir(), "component-tests/resources/nginx-deployment.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}
	err = wl.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	err = wl.WaitForApplicationProfile(80)
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

	alerts, err := utils.GetAlerts(wl.Namespace)
	if err != nil {
		t.Errorf("Error getting alerts: %v", err)
	}
	expectedRuleName := "Unexpected process launched"
	expectedCommand := "ls"

	for _, alert := range alerts {
		ruleName, ruleOk := alert.Labels["rule_name"]
		command, cmdOk := alert.Labels["comm"]

		if ruleOk && cmdOk && ruleName == expectedRuleName && command == expectedCommand {
			return
		}
	}

	t.Errorf("Expected alert not found")
}

func TestAllAlertsFromMaliciousApp(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// Create a random namespace
	ns := utils.NewRandomNamespace()

	// Create a workload
	wl, err := utils.NewTestWorkload(ns.Name, path.Join(utilspkg.CurrentDir(), "component-tests/resources/malicious-job.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}

	// Wait for the workload to be ready
	err = wl.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	// Malicious activity will be detected in 3 minutes + 40 seconds to wait for the alerts to be generated
	timer := time.NewTimer(time.Second * 220)

	// Wait for the application profile to be created and completed
	err = wl.WaitForApplicationProfile(80)
	if err != nil {
		t.Errorf("Error waiting for application profile to be completed: %v", err)
	}

	// Wait for the alerts to be generated
	<-timer.C

	// Get all the alerts for the namespace
	alerts, err := utils.GetAlerts(wl.Namespace)
	if err != nil {
		t.Errorf("Error getting alerts: %v", err)
	}

	// Validate that all alerts are signaled
	expectedAlerts := map[string]bool{
		"Unexpected process launched":             false,
		"Unexpected file access":                  false,
		"Unexpected system call":                  false,
		"Unexpected capability used":              false,
		"Unexpected domain request":               false,
		"Unexpected Service Account Token Access": false,
		"Kubernetes Client Executed":              false,
		"Exec from malicious source":              false,
		"Kernel Module Load":                      false,
		"Exec Binary Not In Base Image":           false,
		// "Malicious SSH Connection", (This rule needs to be updated to be more reliable).
		"Exec from mount":                          false,
		"Crypto Mining Related Port Communication": false,
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
			t.Errorf("Expected alert %s was not signaled", ruleName)
		}
	}
}

func TestBasicLoadActivities(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// Create a random namespace
	ns := utils.NewRandomNamespace()

	// Create a workload
	wl, err := utils.NewTestWorkload(ns.Name, path.Join(utilspkg.CurrentDir(), "component-tests/resources/nginx-deployment.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}

	// Wait for the workload to be ready
	err = wl.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	// Wait for the application profile to be created and completed
	err = wl.WaitForApplicationProfile(80)
	if err != nil {
		t.Errorf("Error waiting for application profile to be completed: %v", err)
	}

	// Create loader
	loader, err := utils.NewTestWorkload(ns.Name, path.Join(utilspkg.CurrentDir(), "component-tests/resources/locust-deployment.yaml"))
	err = loader.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	loadStart := time.Now()

	// Create a load of 5 minutes
	time.Sleep(5 * time.Minute)

	loadEnd := time.Now()

	// Get CPU usage of Node Agent pods
	podToCpuUsage, err := utils.GetNodeAgentAverageCPUUsage(loadStart, loadEnd)
	if err != nil {
		t.Errorf("Error getting CPU usage: %v", err)
	}

	if len(podToCpuUsage) == 0 {
		t.Errorf("No CPU usage data found")
	}

	for pod, cpuUsage := range podToCpuUsage {
		assert.LessOrEqual(t, cpuUsage, 0.1, "CPU usage of Node Agent is too high. CPU usage is %f, Pod: %s", cpuUsage, pod)
	}
}

func TestMemoryLeak(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// Create a random namespace
	ns := utils.NewRandomNamespace()

	// Create 2 workloads
	wlPaths := []string{
		"component-tests/resources/locust-deployment.yaml",
		"component-tests/resources/nginx-deployment.yaml",
	}
	workloads := []utils.TestWorkload{}
	for _, p := range wlPaths {
		wl, err := utils.NewTestWorkload(ns.Name, path.Join(utilspkg.CurrentDir(), p))
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
		err = wl.WaitForApplicationProfile(80)
		if err != nil {
			t.Errorf("Error waiting for application profile to be completed: %v", err)
		}
	}

	// Wait for 60 seconds for the GC to run, so the memory leak can be detected
	time.Sleep(60 * time.Second)

	metrics, err := utils.PlotNodeAgentPrometheusMemoryUsage("memleak_basic", start, time.Now())
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

		// Validate that there is no memory leak, but tolerate 35mb memory leak
		assert.LessOrEqual(t, lastValue, firstValue+35000000, "Memory leak detected in node-agent pod (%s). Memory usage at the end of the test is %f and at the beginning of the test is %f", podName, lastValue, firstValue)
	}
}

func TestMemoryLeak_10K_Alerts(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	// Create a random namespace
	ns := utils.NewRandomNamespace()

	// Create nginx workload
	nginx, err := utils.NewTestWorkload(ns.Name, path.Join(utilspkg.CurrentDir(), "component-tests/resources/nginx-deployment.yaml"))
	if err != nil {
		t.Errorf("Error creating workload: %v", err)
	}
	err = nginx.WaitForReady(80)
	if err != nil {
		t.Errorf("Error waiting for workload to be ready: %v", err)
	}

	err = nginx.WaitForApplicationProfile(80)
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

	metrics, err := utils.PlotNodeAgentPrometheusMemoryUsage("memleak_10k_alerts", startLoad, time.Now())
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

		// Validate that there is no memory leak, but tolerate 6mb memory leak
		assert.LessOrEqual(t, lastValue, firstValue+6000000, "Memory leak detected in node-agent pod (%s). Memory usage at the end of the test is %f and at the beginning of the test is %f", podName, lastValue, firstValue)
	}
}
