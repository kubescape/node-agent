package exporters

import (
	"log"
	mmtypes "node-agent/pkg/malwaremanager/v1/types"
	ruleenginev1 "node-agent/pkg/ruleengine/v1"
	"os"
	"testing"
	"time"

	"gopkg.in/mcuadros/go-syslog.v2"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/stretchr/testify/assert"
)

func setupServer() *syslog.Server {
	channel := make(syslog.LogPartsChannel, 100)
	handler := syslog.NewChannelHandler(channel)

	server := syslog.NewServer()
	server.SetFormat(syslog.Automatic)
	server.SetHandler(handler)
	if err := server.ListenUDP("0.0.0.0:40000"); err != nil { // Due to permission issues, we can't listen on port 514 on the CI.
		log.Fatalf("failed to listen on UDP: %v", err)
	}

	if err := server.Boot(); err != nil {
		log.Fatalf("failed to boot the server: %v", err)
	}

	go func(channel syslog.LogPartsChannel) {
		for logParts := range channel {
			if assert.NotNil(nil, logParts) {
				if assert.NotNil(nil, logParts["content"]) {
					assert.NotEmpty(nil, logParts["content"].(string))
				}
			} else {
				os.Exit(1)
			}
		}
	}(channel)

	go server.Wait()

	return server
}

func TestSyslogExporter(t *testing.T) {
	// Set up a mock syslog server
	server := setupServer()
	defer server.Kill()

	// Set up environment variables for the exporter
	syslogHost := "127.0.0.1:40000"
	os.Setenv("SYSLOG_HOST", syslogHost)
	os.Setenv("SYSLOG_PROTOCOL", "udp")

	// Initialize the syslog exporter
	syslogExp := InitSyslogExporter("")
	if syslogExp == nil {
		t.Errorf("Expected syslogExp to not be nil")
	}

	// Send an alert
	syslogExp.SendRuleAlert(&ruleenginev1.GenericRuleFailure{
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

	syslogExp.SendRuleAlert(&ruleenginev1.GenericRuleFailure{
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

	syslogExp.SendMalwareAlert(&mmtypes.GenericMalwareResult{
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

	// Allow some time for the message to reach the mock syslog server
	time.Sleep(200 * time.Millisecond)
}
