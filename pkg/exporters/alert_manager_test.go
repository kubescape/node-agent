package exporters

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	mmtypes "node-agent/pkg/malwaremanager/v1/types"
	"strings"
	"testing"

	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"

	"node-agent/pkg/ruleengine/v1"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
)

func TestSendAlert(t *testing.T) {
	// Set up a mock Alertmanager server
	recievedData := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		bodyData, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed to read request body: %v", err)
		}
		recievedData <- bodyData
	}))
	defer server.Close()

	// Create a new Alertmanager exporter
	exporter := InitAlertManagerExporter(strings.Replace(server.URL, "http://", "", 1))
	if exporter == nil {
		t.Fatalf("Failed to create new Alertmanager exporter")
	}
	// Call SendAlert

	exporter.SendRuleAlert(&ruleengine.GenericRuleFailure{
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
	})
	bytesData := <-recievedData

	// Assert the request body is correct
	alerts := []map[string]interface{}{}
	if err := json.Unmarshal(bytesData, &alerts); err != nil {
		t.Fatalf("Failed to unmarshal request body: %v", err)
	}
	assert.Equal(t, 1, len(alerts))
	alert := alerts[0]
	alertLabels := alert["labels"].(map[string]interface{})
	assert.Equal(t, "KubescapeRuleViolated", alertLabels["alertname"])
	assert.Equal(t, "testrule", alertLabels["rule_name"])
	assert.Equal(t, "testcontainerid", alertLabels["container_id"])
	assert.Equal(t, "testcontainer", alertLabels["container_name"])
	assert.Equal(t, "testnamespace", alertLabels["namespace"])
	assert.Equal(t, "testpodname", alertLabels["pod_name"])
	assert.Equal(t, "", alertLabels["node_name"])
	assert.Equal(t, "none", alertLabels["severity"])
	assert.Equal(t, "Rule 'testrule' in 'testpodname' namespace 'testnamespace' failed", alert["annotations"].(map[string]interface{})["summary"])
	assert.Equal(t, "Application profile is missing", alert["annotations"].(map[string]interface{})["message"])
	assert.Equal(t, strings.HasPrefix(fmt.Sprint(alert["generatorURL"]), "https://armosec.github.io/kubecop/alertviewer/"), true)
}

func TestSendMalwareAlert(t *testing.T) {
	// Set up a mock Alertmanager server
	recievedData := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		bodyData, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed to read request body: %v", err)
		}
		recievedData <- bodyData
	}))
	defer server.Close()
	// os.Setenv("ALERTMANAGER_URL", "localhost:9093")

	// Create a new Alertmanager exporter
	exporter := InitAlertManagerExporter(strings.Replace(server.URL, "http://", "", 1))
	if exporter == nil {
		t.Fatalf("Failed to create new Alertmanager exporter")
	}
	// Call SendAlert
	exporter.SendMalwareAlert(&mmtypes.GenericMalwareResult{
		BasicRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:  "testmalware",
			Size:       "2MiB",
			MD5Hash:    "testmalwarehash",
			SHA1Hash:   "testmalwarehash",
			SHA256Hash: "testmalwarehash",
		},
		TriggerEvent: igtypes.Event{
			CommonData: igtypes.CommonData{
				Runtime: igtypes.BasicRuntimeMetadata{
					ContainerID:          "testmalwarecontainerid",
					ContainerName:        "testmalwarecontainername",
					ContainerImageName:   "testmalwarecontainerimage",
					ContainerImageDigest: "testmalwarecontainerimagedigest",
				},
				K8s: igtypes.K8sMetadata{
					Node:        "testmalwarenode",
					HostNetwork: false,
					BasicK8sMetadata: igtypes.BasicK8sMetadata{
						Namespace:     "testmalwarenamespace",
						PodName:       "testmalwarepodname",
						ContainerName: "testmalwarecontainername",
					},
				},
			},
		},
		MalwareRuntimeAlert: apitypes.MalwareAlert{
			MalwareDescription: "testmalwaredescription",
		},
	})
	bytesData := <-recievedData

	// Assert the request body is correct
	alerts := []map[string]interface{}{}
	if err := json.Unmarshal(bytesData, &alerts); err != nil {
		t.Fatalf("Failed to unmarshal request body: %v", err)
	}
	assert.Equal(t, 1, len(alerts))
	alert := alerts[0]
	alertLabels := alert["labels"].(map[string]interface{})
	assert.Equal(t, "KubescapeMalwareDetected", alertLabels["alertname"])
	assert.Equal(t, "testmalwarecontainerid", alertLabels["container_id"])
	assert.Equal(t, "testmalwarecontainername", alertLabels["container_name"])
	assert.Equal(t, "testmalwarenamespace", alertLabels["namespace"])
	assert.Equal(t, "testmalwarepodname", alertLabels["pod_name"])
	assert.Equal(t, "", alertLabels["node_name"])
	assert.Equal(t, "critical", alertLabels["severity"])
	assert.Equal(t, strings.HasPrefix(fmt.Sprint(alert["generatorURL"]), "https://armosec.github.io/kubecop/alertviewer/"), true)
}
