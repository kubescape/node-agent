package exporters

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	mmtypes "github.com/kubescape/node-agent/pkg/malwaremanager/v1/types"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
)

func TestSendRuleAlert(t *testing.T) {
	bodyChan := make(chan []byte, 1)
	// Create a mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed to read request body: %v", err)
		}
		bodyChan <- body
	}))
	defer server.Close()

	// Create an HTTPExporter with the mock server URL
	exporter, err := NewHTTPExporter(HTTPExporterConfig{
		URL: server.URL,
	}, "", "", nil)
	assert.NoError(t, err)

	// Create a mock rule failure
	failedRule := &types.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName: "testrule",
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			ContainerID:   "testcontainerid",
			ContainerName: "testcontainer",
			Namespace:     "testnamespace",
			PodNamespace:  "testnamespace",
			PodName:       "testpodname",
		},
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: "Application profile is missing",
		},
	}

	// Call SendRuleAlert
	exporter.SendRuleAlert(failedRule)

	// Assert that the HTTP request was sent correctly
	alertsList := HTTPAlertsList{}
	select {
	case body := <-bodyChan:
		if err := json.Unmarshal(body, &alertsList); err != nil {
			t.Fatalf("Failed to unmarshal request body: %v", err)
		}

	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for request body")
	}
	assert.Equal(t, "RuntimeAlerts", alertsList.Kind)
	assert.Equal(t, "kubescape.io/v1", alertsList.APIVersion)
	assert.Equal(t, 1, len(alertsList.Spec.Alerts))
	alert := alertsList.Spec.Alerts[0]
	assert.Equal(t, "testrule", alert.AlertName)
	assert.Equal(t, "testcontainerid", alert.ContainerID)
	assert.Equal(t, "testcontainer", alert.ContainerName)
	assert.Equal(t, "testnamespace", alert.PodNamespace)
	assert.Equal(t, "testpodname", alert.PodName)
}

func TestSendRuleAlertRateReached(t *testing.T) {
	bodyChan := make(chan []byte, 1)
	// Create a mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed to read request body: %v", err)
		}
		bodyChan <- body
	}))
	defer server.Close()
	// Create an HTTPExporter with the mock server URL
	exporter, err := NewHTTPExporter(HTTPExporterConfig{
		URL:                server.URL,
		MaxAlertsPerMinute: 1,
	}, "", "", nil)
	assert.NoError(t, err)

	// Create a mock rule failure
	failedRule := &types.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName: "testrule",
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			ContainerID:   "testcontainerid",
			ContainerName: "testcontainer",
			Namespace:     "testnamespace",
			PodName:       "testpodname",
		},
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: "Application profile is missing",
		},
	}

	// Call SendRuleAlert multiple times
	exporter.SendRuleAlert(failedRule)
	exporter.SendRuleAlert(failedRule)
	alertsList := HTTPAlertsList{}
	select {
	case body := <-bodyChan:
		if err := json.Unmarshal(body, &alertsList); err != nil {
			t.Fatalf("Failed to unmarshal request body: %v", err)
		}

	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for request body")
	}
	// Assert that the second request was not sent
	alertsList = HTTPAlertsList{}
	select {
	case body := <-bodyChan:
		if err := json.Unmarshal(body, &alertsList); err != nil {
			t.Fatalf("Failed to unmarshal request body: %v", err)
		}

	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for request body")
	}
	// Assert that the HTTP request contains the alert limit reached alert
	alert := alertsList.Spec.Alerts[0]
	assert.Equal(t, "AlertLimitReached", alert.AlertName)
	assert.Equal(t, "Alert limit reached", alert.Message)

}

func TestSendMalwareAlertHTTPExporter(t *testing.T) {
	bodyChan := make(chan []byte, 1)
	// Create a mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed to read request body: %v", err)
		}
		bodyChan <- body
	}))
	defer server.Close()

	// Create an HTTPExporter with the mock server URL
	exporter, err := NewHTTPExporter(HTTPExporterConfig{
		URL: server.URL,
	}, "", "", nil)
	assert.NoError(t, err)

	// Create a mock malware description
	malwareDesc := &mmtypes.GenericMalwareResult{
		BasicRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:  "testmalware",
			Size:       "2MiB",
			MD5Hash:    "testmalwarehash",
			SHA1Hash:   "testmalwarehash",
			SHA256Hash: "testmalwarehash",
		},
		TriggerEvent: utils.StructEvent{},
		MalwareRuntimeAlert: apitypes.MalwareAlert{
			MalwareDescription: "testmalwaredescription",
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			ContainerID:   "testmalwarecontainerid",
			Namespace:     "testmalwarenamespace",
			PodName:       "testmalwarepodname",
			PodNamespace:  "testmalwarenamespace",
			ContainerName: "testmalwarecontainername",
		},
	}

	// Call SendMalwareAlert
	exporter.SendMalwareAlert(malwareDesc)

	// Assert that the HTTP request was sent correctly
	alertsList := HTTPAlertsList{}
	select {
	case body := <-bodyChan:
		if err := json.Unmarshal(body, &alertsList); err != nil {
			t.Fatalf("Failed to unmarshal request body: %v", err)
		}

	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for request body")
	}

	// Assert other expectations
	assert.Equal(t, "RuntimeAlerts", alertsList.Kind)
	assert.Equal(t, "kubescape.io/v1", alertsList.APIVersion)
	assert.Equal(t, 1, len(alertsList.Spec.Alerts))
	alert := alertsList.Spec.Alerts[0]
	assert.Equal(t, "testmalware", alert.AlertName)
	assert.Equal(t, "testmalwarecontainerid", alert.ContainerID)
	assert.Equal(t, "testmalwarecontainername", alert.ContainerName)
	assert.Equal(t, "testmalwarenamespace", alert.PodNamespace)
	assert.Equal(t, "testmalwarepodname", alert.PodName)
}

func TestValidateHTTPExporterConfig(t *testing.T) {
	// Test case: URL is empty
	_, err := NewHTTPExporter(HTTPExporterConfig{}, "", "", nil)
	assert.Error(t, err)

	// Test case: URL is not empty
	exp, err := NewHTTPExporter(HTTPExporterConfig{
		URL: "http://localhost:9093",
	}, "cluster", "node", nil)
	assert.NoError(t, err)
	assert.Equal(t, "POST", exp.config.Method)
	assert.Equal(t, 5, exp.config.TimeoutSeconds)
	assert.Equal(t, 100, exp.config.MaxAlertsPerMinute)
	assert.Equal(t, []HTTPKeyValues{}, exp.config.Headers)
	assert.Equal(t, "cluster", exp.clusterName)
	assert.Equal(t, "node", exp.nodeName)

	// Test case: Method is PUT
	exp, err = NewHTTPExporter(HTTPExporterConfig{
		URL:                "http://localhost:9093",
		Method:             "PUT",
		TimeoutSeconds:     2,
		MaxAlertsPerMinute: 20000,
		Headers: []HTTPKeyValues{
			{
				Key:   "Authorization",
				Value: "Bearer token",
			},
		},
	}, "", "", nil)
	assert.NoError(t, err)
	assert.Equal(t, "PUT", exp.config.Method)
	assert.Equal(t, 2, exp.config.TimeoutSeconds)
	assert.Equal(t, 20000, exp.config.MaxAlertsPerMinute)
	assert.Equal(t, []HTTPKeyValues{{Key: "Authorization", Value: "Bearer token"}}, exp.config.Headers)

	// Test case: Method is neither POST nor PUT
	_, err = NewHTTPExporter(HTTPExporterConfig{
		URL:    "http://localhost:9093",
		Method: "DELETE",
	}, "", "", nil)
	assert.Error(t, err)
}
