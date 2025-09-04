package exporters

import (
	"encoding/csv"
	"os"
	"testing"

	mmtypes "github.com/kubescape/node-agent/pkg/malwaremanager/v1/types"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestCsvExporter(t *testing.T) {
	csvExporter := InitCsvExporter("/tmp/kubecop.csv", "/tmp/kubecop-malware.csv")
	if csvExporter == nil {
		t.Fatalf("Expected csvExporter to not be nil")
	}

	csvExporter.SendRuleAlert(&types.GenericRuleFailure{
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
	csvExporter.SendMalwareAlert(&mmtypes.GenericMalwareResult{
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
