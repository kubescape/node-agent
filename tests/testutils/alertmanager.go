package testutils

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
)

const (
	alertManagerURL = "http://localhost:9093"
)

// Alert structure based on the expected JSON format from Alertmanager
type Alert struct {
	Labels map[string]string `json:"labels"`
}

// getAlerts retrieves and filters alerts from Alertmanager
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

func AssertContains(t *testing.T, alerts []Alert, expectedRuleName string, expectedCommand string, expectedContainerName string) {
	for _, alert := range alerts {
		ruleName, ruleOk := alert.Labels["rule_name"]
		command, cmdOk := alert.Labels["comm"]
		containerName, containerOk := alert.Labels["container_name"]

		if ruleOk && cmdOk && containerOk && ruleName == expectedRuleName && command == expectedCommand && containerName == expectedContainerName {
			return
		}
	}

	t.Error("expected alert with rule name: ", expectedRuleName, " command: ", expectedCommand, " container name: ", expectedContainerName, " not found")
	t.Logf("All alerts: %v", alerts)
}

func AssertNotContains(t *testing.T, alerts []Alert, notExpectedRuleName string, notExpectedCommand string, notExpectedContainerName string) {
	for _, alert := range alerts {
		ruleName, ruleOk := alert.Labels["rule_name"]
		command, cmdOk := alert.Labels["comm"]
		containerName, containerOk := alert.Labels["container_name"]

		if ruleOk && cmdOk && containerOk && ruleName == notExpectedRuleName && command == notExpectedCommand && containerName == notExpectedContainerName {
			t.Error("did not expect an alert with rule name: ", notExpectedRuleName, " command: ", notExpectedCommand, " container name: ", notExpectedContainerName, " not found")
			t.Logf("All alerts: %v", alerts)
		}
	}
}
