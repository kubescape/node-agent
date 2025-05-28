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
