package exporters

import (
	"encoding/csv"
	"fmt"
	"os"

	"github.com/kubescape/node-agent/pkg/hostfimsensor"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"

	"github.com/sirupsen/logrus"
)

// TODO: Add missing fields.

// CsvExporter is an exporter that sends alerts to csv
type CsvExporter struct {
	CsvRulePath    string
	CsvMalwarePath string
}

// InitCsvExporter initializes a new CsvExporter
func InitCsvExporter(csvRulePath, csvMalwarePath string) *CsvExporter {
	if csvRulePath == "" {
		csvRulePath = os.Getenv("EXPORTER_CSV_RULE_PATH")
		if csvRulePath == "" {
			logrus.Debugf("csv rule path not provided, rule alerts will not be exported to csv")
			return nil
		}
	}

	if csvMalwarePath == "" {
		csvMalwarePath = os.Getenv("EXPORTER_CSV_MALWARE_PATH")
		if csvMalwarePath == "" {
			logrus.Debugf("csv malware path not provided, malware alerts will not be exported to csv")
		}
	}

	if _, err := os.Stat(csvRulePath); os.IsNotExist(err) {
		writeRuleHeaders(csvRulePath)
	}

	if _, err := os.Stat(csvMalwarePath); os.IsNotExist(err) && csvMalwarePath != "" {
		writeMalwareHeaders(csvMalwarePath)
	}

	return &CsvExporter{
		CsvRulePath:    csvRulePath,
		CsvMalwarePath: csvMalwarePath,
	}
}

// SendRuleAlert sends an alert to csv
func (ce *CsvExporter) SendRuleAlert(failedRule types.RuleFailure) {
	csvFile, err := os.OpenFile(ce.CsvRulePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		logrus.Errorf("failed to initialize csv exporter: %v", err)
		return
	}
	defer csvFile.Close()

	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()

	csvWriter.Write([]string{
		failedRule.GetBaseRuntimeAlert().AlertName,
		failedRule.GetRuleAlert().RuleDescription,
		failedRule.GetBaseRuntimeAlert().FixSuggestions,
		failedRule.GetRuntimeAlertK8sDetails().PodName,
		failedRule.GetRuntimeAlertK8sDetails().ContainerName,
		failedRule.GetRuntimeAlertK8sDetails().Namespace,
		failedRule.GetRuntimeAlertK8sDetails().ContainerID,
		fmt.Sprintf("%d", failedRule.GetRuntimeProcessDetails().ProcessTree.PID),
		failedRule.GetRuntimeProcessDetails().ProcessTree.Comm,
		fmt.Sprintf("%d", failedRule.GetRuntimeProcessDetails().ProcessTree.Uid),
		fmt.Sprintf("%d", failedRule.GetRuntimeProcessDetails().ProcessTree.Gid),
		fmt.Sprintf("%d", failedRule.GetRuntimeProcessDetails().ProcessTree.PPID),
		failedRule.GetBaseRuntimeAlert().Timestamp.String(),
	})
}

func writeRuleHeaders(csvPath string) {
	csvFile, err := os.OpenFile(csvPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logrus.Errorf("failed to initialize csv exporter: %v", err)
		return
	}
	defer csvFile.Close()

	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()
	csvWriter.Write([]string{
		"Rule Name",
		"Alert Message",
		"Fix Suggestion",
		"Pod Name",
		"Container Name",
		"Namespace",
		"Container ID",
		"PID",
		"Comm",
		"UID",
		"GID",
		"PPID",
		"Timestamp",
	})
}

func (ce *CsvExporter) SendMalwareAlert(malwareResult malwaremanager.MalwareResult) {
	csvFile, err := os.OpenFile(ce.CsvMalwarePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		logrus.Errorf("failed to initialize csv exporter: %v", err)
		return
	}
	defer csvFile.Close()

	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()
	csvWriter.Write([]string{
		malwareResult.GetBasicRuntimeAlert().AlertName,
		malwareResult.GetMalwareRuntimeAlert().MalwareDescription,
		malwareResult.GetRuntimeProcessDetails().ProcessTree.Cmdline,
		malwareResult.GetBasicRuntimeAlert().MD5Hash,
		malwareResult.GetBasicRuntimeAlert().SHA256Hash,
		malwareResult.GetBasicRuntimeAlert().SHA1Hash,
		malwareResult.GetBasicRuntimeAlert().Size,
		malwareResult.GetTriggerEvent().GetBaseEvent().GetNamespace(),
		malwareResult.GetTriggerEvent().GetBaseEvent().GetPod(),
		malwareResult.GetTriggerEvent().GetBaseEvent().GetContainer(),
		malwareResult.GetTriggerEvent().Runtime.ContainerID,
		malwareResult.GetTriggerEvent().Runtime.ContainerImageName,
		malwareResult.GetTriggerEvent().Runtime.ContainerImageDigest,
	})
}

// Write Malware Headers
func writeMalwareHeaders(csvPath string) {
	csvFile, err := os.OpenFile(csvPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logrus.Errorf("failed to initialize csv exporter: %v", err)
		return
	}
	defer csvFile.Close()

	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()
	csvWriter.Write([]string{
		"Malware Name",
		"Description",
		"Cmdline",
		"MD5 Hash",
		"SHA256 Hash",
		"SHA1 Hash",
		"Size",
		"Namespace",
		"Pod Name",
		"Container Name",
		"Container ID",
		"Container Image",
		"Container Image Digest",
	})
}

func (ce *CsvExporter) SendFimAlerts(fimEvents []hostfimsensor.FimEvent) {
	// TODO: Implement FIM alerts sending logic
}
