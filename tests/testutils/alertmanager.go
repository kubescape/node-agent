package testutils

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"testing"

	"github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
)

const (
	alertManagerURL = "http://localhost:9093"
)

// Alert structure based on the expected JSON format from Alertmanager
type Alert struct {
	Labels map[string]string `json:"labels"`
}

// GetAlerts retrieves and filters alerts from Alertmanager
func GetAlerts(namespace string) ([]Alert, error) {
	url := alertManagerURL
	if envURL, exists := os.LookupEnv("ALERTMANAGER_URL"); exists {
		url = envURL
	}

	alerts, err := getActiveAlerts(url)
	if err != nil {
		return nil, fmt.Errorf("could not get alerts: %v", err)
	}

	alerts = filterAlertsByLabel(alerts, "alertname", "KubescapeRuleViolated")
	alerts = filterAlertsByLabel(alerts, "namespace", namespace)

	return alerts, nil
}

func GetMalwareAlerts(namespace string) ([]Alert, error) {
	url := alertManagerURL
	if envURL, exists := os.LookupEnv("ALERTMANAGER_URL"); exists {
		url = envURL
	}

	alerts, err := getActiveAlerts(url)
	if err != nil {
		return nil, fmt.Errorf("could not get alerts: %v", err)
	}

	alerts = filterAlertsByLabel(alerts, "alertname", "KubescapeMalwareDetected")
	alerts = filterAlertsByLabel(alerts, "namespace", namespace)

	return alerts, nil
}

// getActiveAlerts fetches the active alerts from Alertmanager
func getActiveAlerts(alertManagerURL string) ([]Alert, error) {
	endpoint := fmt.Sprintf("%s/api/v2/alerts?active=true", alertManagerURL)
	response, err := http.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("error connecting: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http error: %s", response.Status)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read error: %v", err)
	}

	var alerts []Alert
	err = json.Unmarshal(body, &alerts)
	if err != nil {
		return nil, fmt.Errorf("json parsing error: %v", err)
	}

	return alerts, nil
}

// filterAlertsByLabel filters alerts by a specific label
func filterAlertsByLabel(alerts []Alert, labelKey, labelValue string) []Alert {
	var filteredAlerts []Alert
	for i := range alerts {
		if value, ok := alerts[i].Labels[labelKey]; ok && value == labelValue {
			filteredAlerts = append(filteredAlerts, alerts[i])
		}
	}
	return filteredAlerts
}

func AssertContains(t *testing.T, alerts []Alert, expectedRuleName string, expectedCommand string, expectedContainerName string, expectedFailOnProfile []bool) {
	expectedProfileStatus := helpers.Completed
	for _, alert := range alerts {
		ruleName, ruleOk := alert.Labels["rule_name"]
		command, cmdOk := alert.Labels["comm"]
		containerName, containerOk := alert.Labels["container_name"]
		failOnProfile, failOnProfileOk := alert.Labels["fail_on_profile"]
		profileStatus, profileStatusOk := alert.Labels["profile_status"]
		failOnProfileBool, err := strconv.ParseBool(failOnProfile)
		if err != nil {
			t.Errorf("error parsing fail_on_profile: %v", err)
		}

		if ruleOk && cmdOk && containerOk && ruleName == expectedRuleName && command == expectedCommand && containerName == expectedContainerName &&
			failOnProfileOk && slices.Contains(expectedFailOnProfile, failOnProfileBool) {
			// if fail on profile is true, we expect the profile to be completed
			// else return if the profile is not completed
			if failOnProfileBool {
				if profileStatusOk && profileStatus == expectedProfileStatus {
					return
				}
			} else {
				return
			}

		}
	}

	t.Error("expected alert with rule name: ", expectedRuleName, " command: ", expectedCommand, " container name: ", expectedContainerName, " not found")
	t.Logf("All alerts: %v", alerts)
}

func AssertNotContains(t *testing.T, alerts []Alert, notExpectedRuleName string, notExpectedCommand string, notExpectedContainerName string, notExpectedFailOnProfile []bool) {
	for _, alert := range alerts {
		ruleName, ruleOk := alert.Labels["rule_name"]
		command, cmdOk := alert.Labels["comm"]
		containerName, containerOk := alert.Labels["container_name"]
		failOnProfile, failOnProfileOk := alert.Labels["fail_on_profile"]
		failOnProfileBool, err := strconv.ParseBool(failOnProfile)
		if err != nil {
			t.Errorf("error parsing fail_on_profile: %v", err)
		}
		if ruleOk && cmdOk && containerOk && ruleName == notExpectedRuleName && command == notExpectedCommand && containerName == notExpectedContainerName &&
			failOnProfileOk && slices.Contains(notExpectedFailOnProfile, failOnProfileBool) {
			t.Error("did not expect an alert with rule name: ", notExpectedRuleName, " command: ", notExpectedCommand, " container name: ", notExpectedContainerName, " not found")
			t.Logf("All alerts: %v", alerts)
		}
	}
}

// AssertUIDFieldsPopulated verifies that pod_uid and workload_uid fields are populated in alerts
func AssertUIDFieldsPopulated(t *testing.T, alerts []Alert, namespace string) {
	if len(alerts) == 0 {
		t.Error("no alerts found to verify UID fields")
		return
	}

	alertsWithoutPodUID := 0
	alertsWithoutWorkloadUID := 0
	totalAlerts := len(alerts)

	for _, alert := range alerts {
		podUID, podUIDExists := alert.Labels["pod_uid"]
		workloadUID, workloadUIDExists := alert.Labels["workload_uid"]

		// Check if pod_uid exists and is not empty
		if !podUIDExists || podUID == "" {
			alertsWithoutPodUID++
			t.Logf("Alert missing pod_uid: rule=%s, container=%s, pod=%s",
				alert.Labels["rule_name"],
				alert.Labels["container_name"],
				alert.Labels["pod_name"])
		}

		// Check if workload_uid exists and is not empty
		if !workloadUIDExists || workloadUID == "" {
			alertsWithoutWorkloadUID++
			t.Logf("Alert missing workload_uid: rule=%s, container=%s, pod=%s",
				alert.Labels["rule_name"],
				alert.Labels["container_name"],
				alert.Labels["pod_name"])
		}

		// Log successful UID population for debugging
		if podUIDExists && podUID != "" && workloadUIDExists && workloadUID != "" {
			t.Logf("✓ Alert has both UIDs: pod_uid=%s, workload_uid=%s, rule=%s",
				podUID, workloadUID, alert.Labels["rule_name"])
		}
	}

	// Report statistics
	t.Logf("UID Field Statistics for namespace %s:", namespace)
	t.Logf("  Total alerts: %d", totalAlerts)
	t.Logf("  Alerts with pod_uid: %d (%.1f%%)", totalAlerts-alertsWithoutPodUID, float64(totalAlerts-alertsWithoutPodUID)/float64(totalAlerts)*100)
	t.Logf("  Alerts with workload_uid: %d (%.1f%%)", totalAlerts-alertsWithoutWorkloadUID, float64(totalAlerts-alertsWithoutWorkloadUID)/float64(totalAlerts)*100)

	// Fail if more than 10% of alerts are missing UIDs (allowing for edge cases)
	if float64(alertsWithoutPodUID)/float64(totalAlerts) > 0.1 {
		t.Errorf("Too many alerts missing pod_uid: %d out of %d (%.1f%%)",
			alertsWithoutPodUID, totalAlerts, float64(alertsWithoutPodUID)/float64(totalAlerts)*100)
	}

	if float64(alertsWithoutWorkloadUID)/float64(totalAlerts) > 0.1 {
		t.Errorf("Too many alerts missing workload_uid: %d out of %d (%.1f%%)",
			alertsWithoutWorkloadUID, totalAlerts, float64(alertsWithoutWorkloadUID)/float64(totalAlerts)*100)
	}
}
