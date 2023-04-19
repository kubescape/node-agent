package sbom

import (
	"encoding/json"
	"os"
	"path"
	"sniffer/pkg/utils"
	"testing"

	instanceidhandlerV1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	instnaceIDMock = "apiVersion-v1/namespace-aaa/kind-deployment/name-redis/containerName-redis"
)

type notSPDXFormatSBOMData struct {
	Data int `json:"aaa"`
}

func TestStoreLabels(t *testing.T) {
	instanceID, err := instanceidhandlerV1.GenerateInstanceIDFromString(instnaceIDMock)
	if err != nil {
		t.Fatalf("fail to create instance ID, err: %v", err)
	}
	data := CreateSBOMDataSPDXVersionV040(instanceID)
	SBOMData := data.(*SBOMData)

	var SBOMDataMock spdxv1beta1.SBOMSPDXv2p3
	nginxSBOMPath := path.Join(utils.CurrentDir(), "..", "testdata", "nginx-spdx-format-mock.json")
	bytes, err := os.ReadFile(nginxSBOMPath)
	if err != nil {
		t.Fatalf("fail to read SBOM file, err: %v", err)
	}
	err = json.Unmarshal(bytes, &SBOMDataMock.Spec.SPDX)
	if err != nil {
		t.Fatalf("fail to unmarshal SBOM file, err: %v", err)
	}
	err = SBOMData.StoreSBOM(&SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to store SBOM file, err: %v", err)
	}
	err = SBOMData.FilterSBOM((map[string]bool{
		"/usr/share/adduser/adduser.conf": true,
	}))
	if err != nil {
		t.Fatalf("fail to filter SBOM, err: %v", err)
	}
	SBOMData.StoreMetadata("wlid://cluster-test/namespace-aaa/deplo#*?yment/redis", "e41ced4a64bd065a1a8b79dbc5832b744a3ad82e7fcbe9fb2ebdd1267f972775", instanceID)
	for i := range SBOMData.filteredSpdxData.Labels {
		switch i {
		case instanceidhandlerV1.NamespaceMetadataKey:
			if SBOMData.filteredSpdxData.Labels[i] != "aaa" {
				t.Fatalf("label key %s should be v1 not %s", i, SBOMData.filteredSpdxData.Labels[i])
			}
		case instanceidhandlerV1.NameMetadataKey:
			if SBOMData.filteredSpdxData.Labels[i] != "redis" {
				t.Fatalf("label key %s should be v1 not %s", i, SBOMData.filteredSpdxData.Labels[i])
			}
		case instanceidhandlerV1.ContainerNameMetadataKey:
			if SBOMData.filteredSpdxData.Labels[i] != "redis" {
				t.Fatalf("label key %s should be v1 not %s", i, SBOMData.filteredSpdxData.Labels[i])
			}
		}
	}
}

func TestGetSBOMData(t *testing.T) {
	instanceID, err := instanceidhandlerV1.GenerateInstanceIDFromString(instnaceIDMock)
	if err != nil {
		t.Fatalf("fail to create instance ID, err: %v", err)
	}
	data := CreateSBOMDataSPDXVersionV040(instanceID)
	SBOMData := data.(*SBOMData)

	var SBOMDataMock spdxv1beta1.SBOMSPDXv2p3
	nginxSBOMPath := path.Join(utils.CurrentDir(), "..", "testdata", "nginx-spdx-format-mock.json")
	bytes, err := os.ReadFile(nginxSBOMPath)
	if err != nil {
		t.Fatalf("fail to read SBOM file, err: %v", err)
	}
	err = json.Unmarshal(bytes, &SBOMDataMock.Spec.SPDX)
	if err != nil {
		t.Fatalf("fail to unmarshal SBOM file, err: %v", err)
	}
	err = SBOMData.StoreSBOM(&SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to store SBOM file, err: %v", err)
	}
	_, err = SBOMData.getSBOMDataSPDXFormat()
	if err != nil {
		t.Fatalf("fail to get SBOM, err: %v", err)
	}
	SBOMData.spdxDataPath = "123"
	err = SBOMData.FilterSBOM(map[string]bool{
		"/usr/share/adduser/adduser.conf": true,
	})
	if err == nil {
		t.Fatalf("FilterSBOM should failed")
	}

}

func TestSaveSBOM(t *testing.T) {
	instanceID, err := instanceidhandlerV1.GenerateInstanceIDFromString(instnaceIDMock)
	if err != nil {
		t.Fatalf("fail to create instance ID, err: %v", err)
	}
	data := CreateSBOMDataSPDXVersionV040(instanceID)
	SBOMData := data.(*SBOMData)

	var SBOMDataMock spdxv1beta1.SBOMSPDXv2p3
	nginxSBOMPath := path.Join(utils.CurrentDir(), "..", "testdata", "nginx-spdx-format-mock.json")
	bytes, err := os.ReadFile(nginxSBOMPath)
	if err != nil {
		t.Fatalf("fail to read SBOM file, err: %v", err)
	}
	err = json.Unmarshal(bytes, &SBOMDataMock.Spec.SPDX)
	if err != nil {
		t.Fatalf("fail to unmarshal SBOM file, err: %v", err)
	}
	err = SBOMData.saveSBOM(&SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to save SBOM file, err: %v", err)
	}
	SBOMData.spdxDataPath = "/proc/1/blabla"
	err = SBOMData.StoreSBOM(&SBOMDataMock)
	if err == nil {
		t.Fatalf("StoreSBOM should fail")
	}

}

func TestCreateSBOMDataSPDXVersionV040(t *testing.T) {
	instanceID, err := instanceidhandlerV1.GenerateInstanceIDFromString(instnaceIDMock)
	if err != nil {
		t.Fatalf("fail to create instance ID, err: %v", err)
	}
	data := CreateSBOMDataSPDXVersionV040(instanceID)
	SBOMData := data.(*SBOMData)

	expectedPath := utils.CurrentDir() + "/" + directorySBOM + "/" + instanceID.GetHashed()
	if SBOMData.spdxDataPath != expectedPath {
		t.Fatalf("fail to create SBOMData, expected path %s get path %s", expectedPath, SBOMData.spdxDataPath)
	}

}

func TestCreateSBOMDir(t *testing.T) {
	createSBOMDir()
	_, err := os.Stat(utils.CurrentDir() + "/" + directorySBOM)
	if os.IsNotExist(err) {
		t.Fatalf("fail to create SBOM directory with err %v", err)
	}
}

func TestGetFilterSBOMData(t *testing.T) {
	instanceID, err := instanceidhandlerV1.GenerateInstanceIDFromString(instnaceIDMock)
	if err != nil {
		t.Fatalf("fail to create instance ID, err: %v", err)
	}
	data := CreateSBOMDataSPDXVersionV040(instanceID)
	SBOMData := data.(*SBOMData)

	var SBOMDataMock spdxv1beta1.SBOMSPDXv2p3
	nginxSBOMPath := path.Join(utils.CurrentDir(), "..", "testdata", "nginx-spdx-format-mock.json")
	bytes, err := os.ReadFile(nginxSBOMPath)
	if err != nil {
		t.Fatalf("fail to read SBOM file, err: %v", err)
	}
	err = json.Unmarshal(bytes, &SBOMDataMock.Spec.SPDX)
	if err != nil {
		t.Fatalf("fail to unmarshal SBOM file, err: %v", err)
	}
	err = SBOMData.StoreSBOM(&SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to store SBOM file, err: %v", err)
	}
	if SBOMData.GetFilterSBOMData() != &SBOMData.filteredSpdxData {
		t.Fatalf("fail to get SBOM filtered data")
	}
}

func TestStoreSBOM(t *testing.T) {
	instanceID, err := instanceidhandlerV1.GenerateInstanceIDFromString(instnaceIDMock)
	if err != nil {
		t.Fatalf("fail to create instance ID, err: %v", err)
	}
	data := CreateSBOMDataSPDXVersionV040(instanceID)
	SBOMData := data.(*SBOMData)

	var SBOMDataMock spdxv1beta1.SBOMSPDXv2p3
	nginxSBOMPath := path.Join(utils.CurrentDir(), "..", "testdata", "nginx-spdx-format-mock.json")
	bytes, err := os.ReadFile(nginxSBOMPath)
	if err != nil {
		t.Fatalf("fail to read SBOM file, err: %v", err)
	}
	err = json.Unmarshal(bytes, &SBOMDataMock.Spec.SPDX)
	if err != nil {
		t.Fatalf("fail to unmarshal SBOM file, err: %v", err)
	}
	err = SBOMData.StoreSBOM(&SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to store SBOM file, err: %v", err)
	}

	var notSPDXFormatSBOMDataMock notSPDXFormatSBOMData
	nginxSBOMPath = path.Join(utils.CurrentDir(), "..", "testdata", "not-spdx-format.json")
	bytes, err = os.ReadFile(nginxSBOMPath)
	if err != nil {
		t.Fatalf("fail to read SBOM file, err: %v", err)
	}
	err = json.Unmarshal(bytes, &notSPDXFormatSBOMDataMock)
	if err != nil {
		t.Fatalf("fail to unmarshal SBOM file, err: %v", err)
	}
	err = SBOMData.StoreSBOM(&notSPDXFormatSBOMDataMock)
	if err == nil {
		t.Fatalf("StoreSBOM should fail")
	}
}

func TestFilterSBOM(t *testing.T) {
	instanceID, err := instanceidhandlerV1.GenerateInstanceIDFromString(instnaceIDMock)
	if err != nil {
		t.Fatalf("fail to create instance ID, err: %v", err)
	}
	data := CreateSBOMDataSPDXVersionV040(instanceID)
	SBOMData := data.(*SBOMData)

	var SBOMDataMock spdxv1beta1.SBOMSPDXv2p3
	nginxSBOMPath := path.Join(utils.CurrentDir(), "..", "testdata", "nginx-spdx-format-mock.json")
	bytes, err := os.ReadFile(nginxSBOMPath)
	if err != nil {
		t.Fatalf("fail to read SBOM file, err: %v", err)
	}
	err = json.Unmarshal(bytes, &SBOMDataMock.Spec.SPDX)
	if err != nil {
		t.Fatalf("fail to unmarshal SBOM file, err: %v", err)
	}
	err = SBOMData.StoreSBOM(&SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to store SBOM file, err: %v", err)
	}
	err = SBOMData.FilterSBOM((map[string]bool{
		"/usr/share/adduser/adduser.conf": true,
	}))
	if err != nil {
		t.Fatalf("fail to filter SBOM, err: %v", err)
	}

}

func TestIsNewRelevantSBOMDataExist(t *testing.T) {
	instanceID, err := instanceidhandlerV1.GenerateInstanceIDFromString(instnaceIDMock)
	if err != nil {
		t.Fatalf("fail to create instance ID, err: %v", err)
	}
	data := CreateSBOMDataSPDXVersionV040(instanceID)
	SBOMData := data.(*SBOMData)

	var SBOMDataMock spdxv1beta1.SBOMSPDXv2p3
	nginxSBOMPath := path.Join(utils.CurrentDir(), "..", "testdata", "nginx-spdx-format-mock.json")
	bytes, err := os.ReadFile(nginxSBOMPath)
	if err != nil {
		t.Fatalf("fail to read SBOM file, err: %v", err)
	}
	err = json.Unmarshal(bytes, &SBOMDataMock.Spec.SPDX)
	if err != nil {
		t.Fatalf("fail to unmarshal SBOM file, err: %v", err)
	}
	err = SBOMData.StoreSBOM(&SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to store SBOM file, err: %v", err)
	}
	err = SBOMData.FilterSBOM((map[string]bool{
		"/usr/share/adduser/adduser.conf": true,
	}))
	if err != nil {
		t.Fatalf("fail to filter SBOM, err: %v", err)
	}
	if SBOMData.IsNewRelevantSBOMDataExist() != true {
		t.Fatalf("IsNewRelevantSBOMDataExist should return true, not false")
	}
}

func TestIsSBOMAlreadyExist(t *testing.T) {
	instanceID, err := instanceidhandlerV1.GenerateInstanceIDFromString(instnaceIDMock)
	if err != nil {
		t.Fatalf("fail to create instance ID, err: %v", err)
	}
	data := CreateSBOMDataSPDXVersionV040(instanceID)
	SBOMData := data.(*SBOMData)

	var SBOMDataMock spdxv1beta1.SBOMSPDXv2p3
	nginxSBOMPath := path.Join(utils.CurrentDir(), "..", "testdata", "nginx-spdx-format-mock.json")
	bytes, err := os.ReadFile(nginxSBOMPath)
	if err != nil {
		t.Fatalf("fail to read SBOM file, err: %v", err)
	}
	err = json.Unmarshal(bytes, &SBOMDataMock.Spec.SPDX)
	if err != nil {
		t.Fatalf("fail to unmarshal SBOM file, err: %v", err)
	}
	err = SBOMData.StoreSBOM(&SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to store SBOM file, err: %v", err)
	}
	err = SBOMData.FilterSBOM((map[string]bool{
		"/usr/share/adduser/adduser.conf": true,
	}))
	if err != nil {
		t.Fatalf("fail to filter SBOM, err: %v", err)
	}
	if SBOMData.IsSBOMAlreadyExist() != true {
		t.Fatalf("IsSBOMAlreadyExist should return true, not false")
	}
}

func TestAddResourceVersionIfNeeded(t *testing.T) {
	instanceID, err := instanceidhandlerV1.GenerateInstanceIDFromString(instnaceIDMock)
	if err != nil {
		t.Fatalf("fail to create instance ID, err: %v", err)
	}
	data := CreateSBOMDataSPDXVersionV040(instanceID)
	SBOMData := data.(*SBOMData)

	var SBOMDataMock spdxv1beta1.SBOMSPDXv2p3
	nginxSBOMPath := path.Join(utils.CurrentDir(), "..", "testdata", "nginx-spdx-format-mock.json")
	bytes, err := os.ReadFile(nginxSBOMPath)
	if err != nil {
		t.Fatalf("fail to read SBOM file, err: %v", err)
	}
	err = json.Unmarshal(bytes, &SBOMDataMock.Spec.SPDX)
	if err != nil {
		t.Fatalf("fail to unmarshal SBOM file, err: %v", err)
	}
	err = SBOMData.StoreSBOM(&SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to store SBOM file, err: %v", err)
	}
	err = SBOMData.FilterSBOM((map[string]bool{
		"/usr/share/adduser/adduser.conf": true,
	}))
	if err != nil {
		t.Fatalf("fail to filter SBOM, err: %v", err)
	}
}

func TestStoreFilteredSBOMName(t *testing.T) {
	instanceID, err := instanceidhandlerV1.GenerateInstanceIDFromString(instnaceIDMock)
	if err != nil {
		t.Fatalf("fail to create instance ID, err: %v", err)
	}
	data := CreateSBOMDataSPDXVersionV040(instanceID)
	SBOMData := data.(*SBOMData)

	var SBOMDataMock spdxv1beta1.SBOMSPDXv2p3
	nginxSBOMPath := path.Join(utils.CurrentDir(), "..", "testdata", "nginx-spdx-format-mock.json")
	bytes, err := os.ReadFile(nginxSBOMPath)
	if err != nil {
		t.Fatalf("fail to read SBOM file, err: %v", err)
	}
	err = json.Unmarshal(bytes, &SBOMDataMock.Spec.SPDX)
	if err != nil {
		t.Fatalf("fail to unmarshal SBOM file, err: %v", err)
	}
	err = SBOMData.StoreSBOM(&SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to store SBOM file, err: %v", err)
	}
	err = SBOMData.FilterSBOM((map[string]bool{
		"/usr/share/adduser/adduser.conf": true,
	}))
	if err != nil {
		t.Fatalf("fail to filter SBOM, err: %v", err)
	}
	SBOMData.StoreFilteredSBOMName(instanceID.GetHashed())
	if SBOMData.filteredSpdxData.GetName() != instanceID.GetHashed() {
		t.Fatalf("filteredSpdxData name should be %s not %s", instanceID.GetHashed(), SBOMData.filteredSpdxData.GetName())
	}

}

func TestStoreMetadata(t *testing.T) {
	instanceID, err := instanceidhandlerV1.GenerateInstanceIDFromString(instnaceIDMock)
	if err != nil {
		t.Fatalf("fail to create instance ID, err: %v", err)
	}
	data := CreateSBOMDataSPDXVersionV040(instanceID)
	SBOMData := data.(*SBOMData)

	var SBOMDataMock spdxv1beta1.SBOMSPDXv2p3
	nginxSBOMPath := path.Join(utils.CurrentDir(), "..", "testdata", "nginx-spdx-format-mock.json")
	bytes, err := os.ReadFile(nginxSBOMPath)
	if err != nil {
		t.Fatalf("fail to read SBOM file, err: %v", err)
	}
	err = json.Unmarshal(bytes, &SBOMDataMock.Spec.SPDX)
	if err != nil {
		t.Fatalf("fail to unmarshal SBOM file, err: %v", err)
	}
	err = SBOMData.StoreSBOM(&SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to store SBOM file, err: %v", err)
	}
	err = SBOMData.FilterSBOM((map[string]bool{
		"/usr/share/adduser/adduser.conf":  true,
		"/usr/share/doc/adduser/copyright": true,
	}))
	if err != nil {
		t.Fatalf("fail to filter SBOM, err: %v", err)
	}
	SBOMData.StoreMetadata("wlid://cluster-test/namespace-aaa/deployment/redis", "e41ced4a64bd065a1a8b79dbc5832b744a3ad82e7fcbe9fb2ebdd1267f972775", instanceID)
	for i := range SBOMData.filteredSpdxData.Labels {
		switch i {
		case instanceidhandlerV1.NamespaceMetadataKey:
			if SBOMData.filteredSpdxData.Labels[i] != "aaa" {
				t.Fatalf("label key %s should be v1 not %s", i, SBOMData.filteredSpdxData.Labels[i])
			}
		case instanceidhandlerV1.KindMetadataKey:
			if SBOMData.filteredSpdxData.Labels[i] != "Deployment" {
				t.Fatalf("label key %s should be Deployment not %s", i, SBOMData.filteredSpdxData.Labels[i])
			}
		case instanceidhandlerV1.NameMetadataKey:
			if SBOMData.filteredSpdxData.Labels[i] != "redis" {
				t.Fatalf("label key %s should be v1 not %s", i, SBOMData.filteredSpdxData.Labels[i])
			}
		case instanceidhandlerV1.ContainerNameMetadataKey:
			if SBOMData.filteredSpdxData.Labels[i] != "redis" {
				t.Fatalf("label key %s should be v1 not %s", i, SBOMData.filteredSpdxData.Labels[i])
			}
		}
	}
}

func TestCleanResources(t *testing.T) {
	instanceID, err := instanceidhandlerV1.GenerateInstanceIDFromString(instnaceIDMock)
	if err != nil {
		t.Fatalf("fail to create instance ID, err: %v", err)
	}
	data := CreateSBOMDataSPDXVersionV040(instanceID)
	SBOMData := data.(*SBOMData)

	var SBOMDataMock spdxv1beta1.SBOMSPDXv2p3
	nginxSBOMPath := path.Join(utils.CurrentDir(), "..", "testdata", "nginx-spdx-format-mock.json")
	bytes, err := os.ReadFile(nginxSBOMPath)
	if err != nil {
		t.Fatalf("fail to read SBOM file, err: %v", err)
	}
	err = json.Unmarshal(bytes, &SBOMDataMock.Spec.SPDX)
	if err != nil {
		t.Fatalf("fail to unmarshal SBOM file, err: %v", err)
	}
	err = SBOMData.StoreSBOM(&SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to store SBOM file, err: %v", err)
	}
	SBOMData.CleanResources()
	_, err = os.Stat(utils.CurrentDir() + "/" + directorySBOM + "/" + instanceID.GetHashed())
	if !os.IsNotExist(err) {
		t.Fatalf("SBOM file of %s should be deleted", instanceID.GetHashed())
	}
	SBOMData.CleanResources()
}

/*
example:    "sourceInfo": "acquired package info from installed python package manifest file: /usr/local/lib/python3.10/site-packages/Deprecated-1.2.13.dist-info/METADATA, /usr/local/lib/python3.10/site-packages/Deprecated-1.2.13.dist-info/RECORD, /usr/local/lib/python3.10/site-packages/Deprecated-1.2.13.dist-info/top_level.txt"
*/
func TestParsedFilesBySourceInfo(t *testing.T) {
	sourceInfo := "acquired package info from installed python package manifest file: /usr/local/lib/python3.10/site-packages/Deprecated-1.2.13.dist-info/METADATA, /usr/local/lib/python3.10/site-packages/Deprecated-1.2.13.dist-info/RECORD, /usr/local/lib/python3.10/site-packages/Deprecated-1.2.13.dist-info/top_level.txt"
	list := parsedFilesBySourceInfo(sourceInfo)
	if list[0] != "/usr/local/lib/python3.10/site-packages/Deprecated-1.2.13.dist-info/METADATA" {
		t.Fatalf("list[0] should be %s, not %s", "/usr/local/lib/python3.10/site-packages/Deprecated-1.2.13.dist-info/METADATA", list[0])
	}
	if list[1] != "/usr/local/lib/python3.10/site-packages/Deprecated-1.2.13.dist-info/RECORD" {
		t.Fatalf("list[1] should be %s, not %s", "/usr/local/lib/python3.10/site-packages/Deprecated-1.2.13.dist-info/RECORD", list[1])
	}
	if list[2] != "/usr/local/lib/python3.10/site-packages/Deprecated-1.2.13.dist-info/top_level.txt" {
		t.Fatalf("list[2] should be %s, not %s", "/usr/local/lib/python3.10/site-packages/Deprecated-1.2.13.dist-info/top_level.txt", list[2])
	}
}
