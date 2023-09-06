package storage

import (
	"encoding/json"
	"node-agent/pkg/utils"
	"os"
	"path"

	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	NginxKey      = "nginx-c9b3ae"
	NginxImageID  = "nginx@sha256:6a59f1cbb8d28ac484176d52c473494859a512ddba3ea62a547258cf16c9b3ae"
	NginxImageTag = "nginx"
)

type StorageHttpClientMock struct {
	FilteredSBOMs      []*spdxv1beta1.SBOMSPDXv2p3Filtered
	ImageCounters      map[string]int
	nginxSBOMSpdxBytes *spdxv1beta1.SBOMSPDXv2p3
}

var _ StorageClient = (*StorageHttpClientMock)(nil)

func CreateSBOMStorageHttpClientMock(sbom string) *StorageHttpClientMock {
	var data spdxv1beta1.SBOMSPDXv2p3
	nginxSBOMPath := path.Join(utils.CurrentDir(), "testdata", sbom)
	bytes, err := os.ReadFile(nginxSBOMPath)
	if err != nil {
		return nil
	}
	err = json.Unmarshal(bytes, &data)
	if err != nil {
		return nil
	}

	return &StorageHttpClientMock{
		ImageCounters:      map[string]int{},
		nginxSBOMSpdxBytes: &data,
	}
}

func (sc *StorageHttpClientMock) CreateFilteredSBOM(SBOM *spdxv1beta1.SBOMSPDXv2p3Filtered) error {
	sc.FilteredSBOMs = append(sc.FilteredSBOMs, SBOM)
	return nil
}

func (sc *StorageHttpClientMock) GetSBOM(name string) (*spdxv1beta1.SBOMSPDXv2p3, error) {
	if name == NginxKey {
		return sc.nginxSBOMSpdxBytes, nil
	}
	return nil, nil
}

func (sc *StorageHttpClientMock) PatchFilteredSBOM(_ string, _ *spdxv1beta1.SBOMSPDXv2p3Filtered) error {
	return nil
}

func (sc *StorageHttpClientMock) IncrementImageUse(imageID string) {
	if _, ok := sc.ImageCounters[imageID]; !ok {
		sc.ImageCounters[imageID] = 0
	}
	sc.ImageCounters[imageID]++
}

func (sc *StorageHttpClientMock) DecrementImageUse(imageID string) {
	if _, ok := sc.ImageCounters[imageID]; !ok {
		sc.ImageCounters[imageID] = 0
	}
	sc.ImageCounters[imageID]--

}
