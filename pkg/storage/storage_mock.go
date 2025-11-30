package storage

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
)

const (
	NginxImageID     = "nginx@sha256:6a59f1cbb8d28ac484176d52c473494859a512ddba3ea62a547258cf16c9b3ae"
	FluentBitImageID = "fluentbit@sha256:236f7d961b0ba8b91796955f155819d64801e0d00fa666147502ab9b5b80f623"
)

type StorageHttpClientMock struct {
	SyftSBOMs         []*spdxv1beta1.SBOMSyft
	ContainerProfiles []*v1beta1.ContainerProfile
	ImageCounters     map[string]int
	mockSBOM          *v1beta1.SBOMSyft
}

var _ ProfileClient = (*StorageHttpClientMock)(nil)
var _ ProfileCreator = (*StorageHttpClientMock)(nil)
var _ SbomClient = (*StorageHttpClientMock)(nil)
var _ StorageClient = (*StorageHttpClientMock)(nil)

func (sc *StorageHttpClientMock) CreateContainerProfileDirect(profile *v1beta1.ContainerProfile) error {
	sc.ContainerProfiles = append(sc.ContainerProfiles, profile)
	return nil
}

func (sc *StorageHttpClientMock) CreateSBOM(SBOM *v1beta1.SBOMSyft) (*v1beta1.SBOMSyft, error) {
	sc.SyftSBOMs = append(sc.SyftSBOMs, SBOM)
	return SBOM, nil
}

func (sc *StorageHttpClientMock) GetApplicationProfile(_, _ string) (*spdxv1beta1.ApplicationProfile, error) {
	//TODO implement me
	panic("implement me")
}

func (sc *StorageHttpClientMock) GetNetworkNeighborhood(_, _ string) (*spdxv1beta1.NetworkNeighborhood, error) {
	//TODO implement me
	panic("implement me")
}
func (sc *StorageHttpClientMock) GetSBOMMeta(_ string) (*v1beta1.SBOMSyft, error) {
	return sc.mockSBOM, nil
}

func (sc *StorageHttpClientMock) GetStorageClient() beta1.SpdxV1beta1Interface {
	return nil
}

func (sc *StorageHttpClientMock) ListApplicationProfiles(_ string) (*spdxv1beta1.ApplicationProfileList, error) {
	//TODO implement me
	panic("implement me")
}

func (sc *StorageHttpClientMock) ListNetworkNeighborhoods(_ string) (*spdxv1beta1.NetworkNeighborhoodList, error) {
	//TODO implement me
	panic("implement me")
}

func (sc *StorageHttpClientMock) ReplaceSBOM(SBOM *v1beta1.SBOMSyft) (*v1beta1.SBOMSyft, error) {
	sc.SyftSBOMs = append(sc.SyftSBOMs, SBOM)
	return SBOM, nil
}
