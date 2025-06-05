package storage

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	NginxKey         = "nginx-c9b3ae"
	NginxImageID     = "nginx@sha256:6a59f1cbb8d28ac484176d52c473494859a512ddba3ea62a547258cf16c9b3ae"
	FluentBitImageID = "fluentbit@sha256:236f7d961b0ba8b91796955f155819d64801e0d00fa666147502ab9b5b80f623"
)

type StorageHttpClientMock struct {
	ApplicationProfiles  []*spdxv1beta1.ApplicationProfile
	SyftSBOMs            []*spdxv1beta1.SBOMSyft
	NetworkNeighborhoods []*v1beta1.NetworkNeighborhood
	ContainerProfiles    []*v1beta1.ContainerProfile
	ImageCounters        map[string]int
	mockSBOM             *v1beta1.SBOMSyft
	failedOnce           bool
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

func (sc *StorageHttpClientMock) CreateContainerProfile(profile *v1beta1.ContainerProfile, namespace string) error {
	sc.ContainerProfiles = append(sc.ContainerProfiles, profile)
	return nil
}
