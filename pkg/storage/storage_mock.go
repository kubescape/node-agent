package storage

import (
	"encoding/json"
	"node-agent/pkg/utils"
	"os"
	"path"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	NginxKey      = "nginx-c9b3ae"
	NginxImageID  = "nginx@sha256:6a59f1cbb8d28ac484176d52c473494859a512ddba3ea62a547258cf16c9b3ae"
	NginxImageTag = "nginx"
)

type StorageHttpClientMock struct {
	ApplicationActivities       []*spdxv1beta1.ApplicationActivity
	ApplicationProfiles         []*spdxv1beta1.ApplicationProfile
	ApplicationProfileSummaries []*spdxv1beta1.ApplicationProfileSummary
	FilteredSBOMs               []*spdxv1beta1.SBOMSPDXv2p3Filtered
	NetworkNeighborses          []*v1beta1.NetworkNeighbors
	ImageCounters               map[string]int
	nginxSBOMSpdxBytes          *spdxv1beta1.SBOMSPDXv2p3
}

func (sc *StorageHttpClientMock) GetApplicationActivity(_, _ string) (*spdxv1beta1.ApplicationActivity, error) {
	return &spdxv1beta1.ApplicationActivity{
		Spec: spdxv1beta1.ApplicationActivitySpec{
			Syscalls: []string{"open"},
		},
	}, nil
}

func (sc *StorageHttpClientMock) GetApplicationProfile(_, _ string) (*spdxv1beta1.ApplicationProfile, error) {
	return &spdxv1beta1.ApplicationProfile{
		Spec: spdxv1beta1.ApplicationProfileSpec{
			Capabilities: []string{"NET_BROADCAST"},
		},
	}, nil
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

func (sc *StorageHttpClientMock) CreateApplicationActivity(activity *spdxv1beta1.ApplicationActivity, _ string) error {
	sc.ApplicationActivities = append(sc.ApplicationActivities, activity)
	return nil
}

func (sc *StorageHttpClientMock) CreateApplicationProfile(profile *spdxv1beta1.ApplicationProfile, _ string) error {
	sc.ApplicationProfiles = append(sc.ApplicationProfiles, profile)
	return nil
}

func (sc *StorageHttpClientMock) CreateApplicationProfileSummary(summary *spdxv1beta1.ApplicationProfileSummary, namespace string) error {
	sc.ApplicationProfileSummaries = append(sc.ApplicationProfileSummaries, summary)
	return nil
}

func (sc *StorageHttpClientMock) CreateNetworkNeighbors(networkNeighbors *v1beta1.NetworkNeighbors, namespace string) error {
	sc.NetworkNeighborses = append(sc.NetworkNeighborses, networkNeighbors)
	return nil
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

func (sc *StorageHttpClientMock) GetNetworkNeighbors(namespace, name string) (*v1beta1.NetworkNeighbors, error) {
	for _, nn := range sc.NetworkNeighborses {
		if nn.Name == name {
			return nn, nil
		}
	}
	return nil, nil
}

func (sc *StorageHttpClientMock) PatchNetworkNeighborsMatchLabels(name, namespace string, networkNeighbors *v1beta1.NetworkNeighbors) error {
	return nil
}

func (sc *StorageHttpClientMock) PatchNetworkNeighborsIngressAndEgress(name, namespace string, networkNeighbors *v1beta1.NetworkNeighbors) error {
	return nil
}
