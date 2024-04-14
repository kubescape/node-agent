//go:build integration
// +build integration

package tests

import (
	"node-agent/tests/utils"
	"testing"
	"time"
)

const (
	kubescapeNamespace = "kubescape"
	namespace          = "default"
	name               = "test"
)

func tearDownTest(t *testing.T, startTime time.Time) {
	end := time.Now()

	t.Log("Waiting 60 seconds for Prometheus to scrape the data")
	time.Sleep(60)

	err := utils.PlotPrometheusCPUUsage(t.Name(), startTime, end)
	if err != nil {
		t.Errorf("Error plotting CPU usage: %v", err)
	}

	err = utils.PlotPrometheusMemoryUsage(t.Name(), startTime, end)
	if err != nil {
		t.Errorf("Error plotting memory usage: %v", err)
	}
}

func TestBasicAlertTest(t *testing.T) {
	start := time.Now()
	defer tearDownTest(t, start)

	ns := utils.NewRandomNamespace()
	wl, err := utils.NewTestWorkload(ns.Name, "component-tests/resources/nginx-deployment.yaml")
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

	time.Sleep(10)

	_, _, err = wl.ExecIntoPod([]string{"ls", "-l"})
	if err != nil {
		t.Errorf("Error executing remote command: %v", err)
	}

	// Wait for the alert to be signaled
	time.Sleep(5)

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
	print("b")
}
