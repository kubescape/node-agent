package exporters

import (
	"encoding/csv"
	mmtypes "node-agent/pkg/malwaremanager/v1/types"
	"node-agent/pkg/utils"
	"os"
	"testing"
)

func TestCsvExporter(t *testing.T) {
	csvExporter := InitCsvExporter("/tmp/kubecop.csv", "/tmp/kubecop-malware.csv")
	if csvExporter == nil {
		t.Fatalf("Expected csvExporter to not be nil")
	}

	csvExporter.SendRuleAlert(&GenericRuleFailure{
		RuleName: "testrule",
		Err:      "Application profile is missing",
		FailureEvent: &utils.GeneralEvent{
			ContainerName: "testcontainer", ContainerID: "testcontainerid", Namespace: "testnamespace", PodName: "testpodname"}},
	)

	csvExporter.SendMalwareAlert(&mmtypes.GenericMalwareResult{
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

	// Check if the csv file exists and contains the expected content (2 rows - header and the alert)
	if _, err := os.Stat("/tmp/kubecop.csv"); os.IsNotExist(err) {
		t.Fatalf("Expected csv file to exist")
	}

	if _, err := os.Stat("/tmp/kubecop-malware.csv"); os.IsNotExist(err) {
		t.Fatalf("Expected csv malware file to exist")
	}

	csvRuleFile, err := os.Open("/tmp/kubecop.csv")
	if err != nil {
		t.Fatalf("Expected csv file to open")
	}

	csvMalwareFile, err := os.Open("/tmp/kubecop-malware.csv")
	if err != nil {
		t.Fatalf("Expected csv malware file to open")
	}

	csvReader := csv.NewReader(csvRuleFile)
	csvMalwareReader := csv.NewReader(csvMalwareFile)
	csvMalwareData, err := csvMalwareReader.ReadAll()
	if err != nil {
		t.Fatalf("Expected csv malware file to be readable")
	}

	csvData, err := csvReader.ReadAll()
	if err != nil {
		t.Fatalf("Expected csv file to be readable")
	}

	if len(csvMalwareData) != 2 {
		t.Fatalf("Expected csv malware file to contain 2 rows")
	}

	if csvMalwareData[0][0] != "Malware Name" {
		t.Fatalf("Expected csv malware file to contain the malware name header")
	}

	if len(csvData) != 2 {
		t.Fatalf("Expected csv file to contain 2 rows")
	}

	if csvData[0][0] != "Rule Name" {
		t.Fatalf("Expected csv file to contain the rule name header")
	}

	csvRuleFile.Close()
	csvMalwareFile.Close()

	err = os.Remove("/tmp/kubecop.csv")
	if err != nil {
		t.Fatalf("Expected csv file to be removed")
	}

	err = os.Remove("/tmp/kubecop-malware.csv")
	if err != nil {
		t.Fatalf("Expected csv malware file to be removed")
	}
}
