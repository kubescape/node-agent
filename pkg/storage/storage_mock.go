package storage

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	NginxKey         = "nginx-c9b3ae" // TODO: remove this constant as it is unused @matthias?
	NginxImageID     = "nginx@sha256:6a59f1cbb8d28ac484176d52c473494859a512ddba3ea62a547258cf16c9b3ae"
	FluentBitImageID = "fluentbit@sha256:236f7d961b0ba8b91796955f155819d64801e0d00fa666147502ab9b5b80f623"
)

type StorageHttpClientMock struct {
	SyftSBOMs         []*spdxv1beta1.SBOMSyft
	ContainerProfiles []*v1beta1.ContainerProfile
	ImageCounters     map[string]int
	mockSBOM          *v1beta1.SBOMSyft
}

var _ StorageClient = (*StorageHttpClientMock)(nil)

func (sc *StorageHttpClientMock) CreateSBOM(SBOM *v1beta1.SBOMSyft) (*v1beta1.SBOMSyft, error) {
	sc.SyftSBOMs = append(sc.SyftSBOMs, SBOM)
	return SBOM, nil
}

func (sc *StorageHttpClientMock) GetSBOM(_ string) (*v1beta1.SBOMSyft, error) {
	return sc.mockSBOM, nil
}

func (sc *StorageHttpClientMock) GetSBOMMeta(_ string) (*v1beta1.SBOMSyft, error) {
	return sc.mockSBOM, nil
}

func (sc *StorageHttpClientMock) ReplaceSBOM(SBOM *v1beta1.SBOMSyft) (*v1beta1.SBOMSyft, error) {
	sc.SyftSBOMs = append(sc.SyftSBOMs, SBOM)
	return SBOM, nil
}

func (sc *StorageHttpClientMock) CreateContainerProfile(profile *v1beta1.ContainerProfile, namespace string) error {
	sc.ContainerProfiles = append(sc.ContainerProfiles, profile)
	return nil
}
