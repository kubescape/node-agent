package sbom

import (
	"context"
	"encoding/json"
	"node-agent/pkg/utils"
	"os"
	"path"
	"testing"

	instanceidhandlerV1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/spf13/afero"
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
	data := CreateSBOMDataSPDXVersionV040(instanceID, afero.NewMemMapFs())
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
	err = SBOMData.StoreSBOM(context.TODO(), &SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to store SBOM file, err: %v", err)
	}
	err = SBOMData.FilterSBOM(context.TODO(), map[string]bool{
		"/usr/share/adduser/adduser.conf": true,
	})
	if err != nil {
		t.Fatalf("fail to filter SBOM, err: %v", err)
	}
	SBOMData.StoreMetadata(context.TODO(), "wlid://cluster-test/namespace-aaa/deplo#*?yment/redis", "e41ced4a64bd065a1a8b79dbc5832b744a3ad82e7fcbe9fb2ebdd1267f972775", instanceID)
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
	data := CreateSBOMDataSPDXVersionV040(instanceID, afero.NewMemMapFs())
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
	err = SBOMData.StoreSBOM(context.TODO(), &SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to store SBOM file, err: %v", err)
	}
	_, err = SBOMData.getSBOMDataSPDXFormat(context.TODO())
	if err != nil {
		t.Fatalf("fail to get SBOM, err: %v", err)
	}
	SBOMData.spdxDataPath = "123"
	err = SBOMData.FilterSBOM(context.TODO(), map[string]bool{
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
	data := CreateSBOMDataSPDXVersionV040(instanceID, afero.NewMemMapFs())
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
	err = SBOMData.saveSBOM(context.TODO(), &SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to save SBOM file, err: %v", err)
	}
}

func TestCreateSBOMDataSPDXVersionV040(t *testing.T) {
	instanceID, err := instanceidhandlerV1.GenerateInstanceIDFromString(instnaceIDMock)
	if err != nil {
		t.Fatalf("fail to create instance ID, err: %v", err)
	}
	data := CreateSBOMDataSPDXVersionV040(instanceID, afero.NewMemMapFs())
	SBOMData := data.(*SBOMData)

	expectedPath := spdxDataDirPath + "/" + instanceID.GetHashed()
	if SBOMData.spdxDataPath != expectedPath {
		t.Fatalf("fail to create SBOMData, expected path %s get path %s", expectedPath, SBOMData.spdxDataPath)
	}

}

func TestGetFilterSBOMData(t *testing.T) {
	instanceID, err := instanceidhandlerV1.GenerateInstanceIDFromString(instnaceIDMock)
	if err != nil {
		t.Fatalf("fail to create instance ID, err: %v", err)
	}
	data := CreateSBOMDataSPDXVersionV040(instanceID, afero.NewMemMapFs())
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
	err = SBOMData.StoreSBOM(context.TODO(), &SBOMDataMock)
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
	data := CreateSBOMDataSPDXVersionV040(instanceID, afero.NewMemMapFs())
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
	err = SBOMData.StoreSBOM(context.TODO(), &SBOMDataMock)
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
	err = SBOMData.StoreSBOM(context.TODO(), &notSPDXFormatSBOMDataMock)
	if err == nil {
		t.Fatalf("StoreSBOM should fail")
	}
}

func TestFilterSBOM(t *testing.T) {
	instanceID, err := instanceidhandlerV1.GenerateInstanceIDFromString(instnaceIDMock)
	if err != nil {
		t.Fatalf("fail to create instance ID, err: %v", err)
	}
	data := CreateSBOMDataSPDXVersionV040(instanceID, afero.NewMemMapFs())
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
	err = SBOMData.StoreSBOM(context.TODO(), &SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to store SBOM file, err: %v", err)
	}
	err = SBOMData.FilterSBOM(context.TODO(), map[string]bool{
		"/usr/share/adduser/adduser.conf": true,
	})
	if err != nil {
		t.Fatalf("fail to filter SBOM, err: %v", err)
	}

}

func TestIsNewRelevantSBOMDataExist(t *testing.T) {
	instanceID, err := instanceidhandlerV1.GenerateInstanceIDFromString(instnaceIDMock)
	if err != nil {
		t.Fatalf("fail to create instance ID, err: %v", err)
	}
	data := CreateSBOMDataSPDXVersionV040(instanceID, afero.NewMemMapFs())
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
	err = SBOMData.StoreSBOM(context.TODO(), &SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to store SBOM file, err: %v", err)
	}
	err = SBOMData.FilterSBOM(context.TODO(), map[string]bool{
		"/usr/share/adduser/adduser.conf": true,
	})
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
	data := CreateSBOMDataSPDXVersionV040(instanceID, afero.NewMemMapFs())
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
	err = SBOMData.StoreSBOM(context.TODO(), &SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to store SBOM file, err: %v", err)
	}
	err = SBOMData.FilterSBOM(context.TODO(), map[string]bool{
		"/usr/share/adduser/adduser.conf": true,
	})
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
	data := CreateSBOMDataSPDXVersionV040(instanceID, afero.NewMemMapFs())
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
	err = SBOMData.StoreSBOM(context.TODO(), &SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to store SBOM file, err: %v", err)
	}
	err = SBOMData.FilterSBOM(context.TODO(), map[string]bool{
		"/usr/share/adduser/adduser.conf": true,
	})
	if err != nil {
		t.Fatalf("fail to filter SBOM, err: %v", err)
	}
}

func TestStoreFilteredSBOMName(t *testing.T) {
	instanceID, err := instanceidhandlerV1.GenerateInstanceIDFromString(instnaceIDMock)
	if err != nil {
		t.Fatalf("fail to create instance ID, err: %v", err)
	}
	data := CreateSBOMDataSPDXVersionV040(instanceID, afero.NewMemMapFs())
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
	err = SBOMData.StoreSBOM(context.TODO(), &SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to store SBOM file, err: %v", err)
	}
	err = SBOMData.FilterSBOM(context.TODO(), map[string]bool{
		"/usr/share/adduser/adduser.conf": true,
	})
	if err != nil {
		t.Fatalf("fail to filter SBOM, err: %v", err)
	}
	SBOMData.SetFilteredSBOMName(instanceID.GetHashed())
	if SBOMData.filteredSpdxData.GetName() != instanceID.GetHashed() {
		t.Fatalf("filteredSpdxData name should be %s not %s", instanceID.GetHashed(), SBOMData.filteredSpdxData.GetName())
	}

}

func TestStoreMetadata(t *testing.T) {
	instanceID, err := instanceidhandlerV1.GenerateInstanceIDFromString(instnaceIDMock)
	if err != nil {
		t.Fatalf("fail to create instance ID, err: %v", err)
	}
	data := CreateSBOMDataSPDXVersionV040(instanceID, afero.NewMemMapFs())
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
	err = SBOMData.StoreSBOM(context.TODO(), &SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to store SBOM file, err: %v", err)
	}
	err = SBOMData.FilterSBOM(context.TODO(), map[string]bool{
		"/usr/share/adduser/adduser.conf":  true,
		"/usr/share/doc/adduser/copyright": true,
	})
	if err != nil {
		t.Fatalf("fail to filter SBOM, err: %v", err)
	}
	SBOMData.StoreMetadata(context.TODO(), "wlid://cluster-test/namespace-aaa/deployment/redis", "e41ced4a64bd065a1a8b79dbc5832b744a3ad82e7fcbe9fb2ebdd1267f972775", instanceID)
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
		case instanceidhandlerV1.ImageTagMetadataKey:
			if SBOMData.filteredSpdxData.Labels[i] != "e41ced4a64bd065a1a8b79dbc5832b744a3ad82e7fcbe9fb2ebdd1267f972775" {
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
	data := CreateSBOMDataSPDXVersionV040(instanceID, afero.NewMemMapFs())
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
	err = SBOMData.StoreSBOM(context.TODO(), &SBOMDataMock)
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

func TestParsedFilesBySourceInfoFiltered(t *testing.T) {
	shouldBeSourcesInfo := []string{"acquired package info from dotnet project assets file: 123, 456", "acquired package info from installed node module manifest file: 123, 456", "acquired package info from installed python package manifest file: 123, 456", "acquired package info from installed java archive: 123, 456", "acquired package info from installed gem metadata file: 123, 456", "acquired package info from go module information: 123, 456", "acquired package info from rust cargo manifest: 123, 456", "acquired package info from PHP composer manifest: 123, 456", "acquired package info from cabal or stack manifest files: 123, 456", "acquired package info from rebar3 or mix manifest files: 123, 456", "acquired package info from linux kernel archive: 123, 456", "acquired package info from linux kernel module files: 123, 456", "acquired package info from the following paths: 123, 456"}
	for i := range shouldBeSourcesInfo {
		list := parsedFilesBySourceInfo(shouldBeSourcesInfo[i])
		if len(list) != 2 {
			t.Fatalf("source Info %s: parsed source Info list must be equal to 2", shouldBeSourcesInfo[i])
		}
		if list[0] != "123" {
			t.Fatalf("list[0] should be %s, not %s", "/usr/local/lib/python3.10/site-packages/Deprecated-1.2.13.dist-info/METADATA", list[0])
		}
		if list[1] != "456" {
			t.Fatalf("list[1] should be %s, not %s", "/usr/local/lib/python3.10/site-packages/Deprecated-1.2.13.dist-info/RECORD", list[1])
		}
	}

	shouldNotBeSourcesInfo := []string{"acquired package info from ALPM DB: 1234, 456", "acquired package info from RPM DB: 1234, 456", "acquired package info from APK DB: 1234, 456", "acquired package info from DPKG DB: 1234, 456", "acquired package info from installed cocoapods manifest file: 1234, 456", "acquired package info from conan manifest: 1234, 456", "acquired package info from portage DB: 1234, 456", "acquired package info from nix store path: 123, 456"}
	for i := range shouldNotBeSourcesInfo {
		list := parsedFilesBySourceInfo(shouldNotBeSourcesInfo[i])
		if len(list) != 0 {
			t.Fatalf("source Info %s: parsed source Info list must be equal to 0", shouldNotBeSourcesInfo[i])
		}
	}
}

func TestSBOMIncomplete(t *testing.T) {
	instanceID, err := instanceidhandlerV1.GenerateInstanceIDFromString(instnaceIDMock)
	if err != nil {
		t.Fatalf("fail to create instance ID, err: %v", err)
	}
	data := CreateSBOMDataSPDXVersionV040(instanceID, afero.NewMemMapFs())
	SBOMData := data.(*SBOMData)

	var SBOMDataMock spdxv1beta1.SBOMSPDXv2p3
	nginxSBOMPath := path.Join(utils.CurrentDir(), "..", "testdata", "sbom-incomplete-mock.json")
	bytes, err := os.ReadFile(nginxSBOMPath)
	if err != nil {
		t.Fatalf("fail to read SBOM file, err: %v", err)
	}
	err = json.Unmarshal(bytes, &SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to unmarshal SBOM file, err: %v", err)
	}
	err = SBOMData.StoreSBOM(context.TODO(), &SBOMDataMock)
	if err != nil {
		t.Fatalf("fail to store SBOM file, err: %v", err)
	}
	if err = SBOMData.ValidateSBOM(context.TODO()); err == nil {
		t.Fatalf("SBOM should mark as incomplete")
	}
	if SBOMData.status != instanceidhandlerV1.Incomplete {
		t.Fatalf("SBOM status should be in complete")
	}
}
