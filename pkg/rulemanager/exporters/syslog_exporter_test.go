package exporters

import (
	"log"
	mmtypes "node-agent/pkg/malwaremanager/v1/types"
	"node-agent/pkg/utils"
	"os"
	"testing"
	"time"

	"gopkg.in/mcuadros/go-syslog.v2"

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
	syslogExp.SendRuleAlert(&GenericRuleFailure{
		RuleName: "testrule",
		Err:      "Application profile is missing",
		FailureEvent: &utils.GeneralEvent{
			ContainerName: "testcontainer", ContainerID: "testcontainerid", Namespace: "testnamespace", PodName: "testpodname"}},
	)

	syslogExp.SendRuleAlert(&GenericRuleFailure{
		RuleName: "testrule",
		Err:      "Application profile is missing",
		FailureEvent: &utils.GeneralEvent{
			ContainerName: "testcontainer", ContainerID: "testcontainerid", Namespace: "testnamespace", PodName: "testpodname"}},
	)

	syslogExp.SendMalwareAlert(&mmtypes.GenericMalwareResult{
		Name:                 "testmalware",
		MD5Hash:              "testhash",
		SHA256Hash:           "testhash",
		SHA1Hash:             "testhash",
		Description:          "testdescription",
		Path:                 "testpath",
		Size:                 "2MB",
		Namespace:            "testnamespace",
		PodName:              "testpodname",
		ContainerName:        "testcontainername",
		ContainerID:          "testcontainerid",
		ContainerImage:       "testcontainerimage",
		ContainerImageDigest: "testcontainerimagedigest",
	})

	// Allow some time for the message to reach the mock syslog server
	time.Sleep(200 * time.Millisecond)
}
