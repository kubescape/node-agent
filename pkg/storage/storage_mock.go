package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"node-agent/pkg/utils"
	"os"
	"path"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	NginxKey      = "nginx-c9b3ae"
	NginxImageID  = "nginx@sha256:6a59f1cbb8d28ac484176d52c473494859a512ddba3ea62a547258cf16c9b3ae"
	NginxImageTag = "nginx"
)

type StorageHttpClientMock struct {
	ApplicationActivities []*spdxv1beta1.ApplicationActivity
	ApplicationProfiles   []*spdxv1beta1.ApplicationProfile
	FilteredSyftSBOMs     []*spdxv1beta1.SBOMSyftFiltered
	NetworkNeighborses    []*v1beta1.NetworkNeighbors
	ImageCounters         map[string]int
	nginxSBOMSpdxBytes    *spdxv1beta1.SBOMSPDXv2p3
	mockSBOM              *v1beta1.SBOMSyft
	failedOnce            bool
}

func (sc *StorageHttpClientMock) GetApplicationActivity(_, _ string) (*spdxv1beta1.ApplicationActivity, error) {
	return &spdxv1beta1.ApplicationActivity{
		Spec: spdxv1beta1.ApplicationActivitySpec{
			Syscalls: []string{"open"},
		},
	}, nil
}

func (sc *StorageHttpClientMock) GetApplicationProfile(_, _ string) (*spdxv1beta1.ApplicationProfile, error) {
	if len(sc.ApplicationProfiles) == 0 {
		return &spdxv1beta1.ApplicationProfile{
			Spec: spdxv1beta1.ApplicationProfileSpec{
				Containers: []spdxv1beta1.ApplicationProfileContainer{
					{Capabilities: []string{"SYS_ADMIN"}},
					{Capabilities: []string{"NET_BROADCAST"}},
				},
			},
		}, nil
	}
	return sc.ApplicationProfiles[len(sc.ApplicationProfiles)-1], nil
}

var _ StorageClient = (*StorageHttpClientMock)(nil)

func CreateSyftSBOMStorageHttpClientMock(sbom spdxv1beta1.SBOMSyft) *StorageHttpClientMock {
	return &StorageHttpClientMock{
		ImageCounters: map[string]int{},
		mockSBOM:      &sbom,
	}
}

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
	if !sc.failedOnce {
		sc.failedOnce = true
		return errors.New("first time fail")
	}
	sc.ApplicationProfiles = append(sc.ApplicationProfiles, profile)
	return nil
}

func (sc *StorageHttpClientMock) PatchApplicationProfile(name, _ string, patchJSON []byte, _ chan error) error {
	if len(sc.ApplicationProfiles) == 0 {
		return apierrors.NewNotFound(v1beta1.Resource("applicationprofile"), name)
	}
	// get last profile
	lastProfile, err := json.Marshal(sc.ApplicationProfiles[len(sc.ApplicationProfiles)-1])
	if err != nil {
		return fmt.Errorf("marshal last profile: %w", err)
	}
	patch, err := jsonpatch.DecodePatch(patchJSON)
	if err != nil {
		return fmt.Errorf("decode patch: %w", err)
	}
	patchedProfile, err := patch.Apply(lastProfile)
	if err != nil {
		return fmt.Errorf("apply patch: %w", err)
	}
	profile := &spdxv1beta1.ApplicationProfile{}
	if err := json.Unmarshal(patchedProfile, profile); err != nil {
		return fmt.Errorf("unmarshal patched profile: %w", err)
	}
	sc.ApplicationProfiles = append(sc.ApplicationProfiles, profile)
	return nil
}

func (sc *StorageHttpClientMock) CreateNetworkNeighbors(networkNeighbors *v1beta1.NetworkNeighbors, _ string) error {
	sc.NetworkNeighborses = append(sc.NetworkNeighborses, networkNeighbors)
	return nil
}

func (sc *StorageHttpClientMock) CreateFilteredSBOM(SBOM *v1beta1.SBOMSyftFiltered) error {
	sc.FilteredSyftSBOMs = append(sc.FilteredSyftSBOMs, SBOM)
	return nil
}

func (sc *StorageHttpClientMock) GetFilteredSBOM(name string) (*v1beta1.SBOMSyftFiltered, error) {
	for _, sbom := range sc.FilteredSyftSBOMs {
		if sbom.Name == name {
			return sbom, nil
		}
	}
	return nil, errors.New("not found")
}
func (sc *StorageHttpClientMock) GetSBOM(_ string) (*v1beta1.SBOMSyft, error) {
	return sc.mockSBOM, nil
}

func (sc *StorageHttpClientMock) PatchFilteredSBOM(_ string, _ *spdxv1beta1.SBOMSyftFiltered) error {
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

func (sc *StorageHttpClientMock) GetNetworkNeighbors(_, name string) (*v1beta1.NetworkNeighbors, error) {
	for _, nn := range sc.NetworkNeighborses {
		if nn.Name == name {
			return nn, nil
		}
	}
	return nil, nil
}

func (sc *StorageHttpClientMock) PatchNetworkNeighborsMatchLabels(_, _ string, _ *v1beta1.NetworkNeighbors) error {
	return nil
}

func (sc *StorageHttpClientMock) PatchNetworkNeighborsIngressAndEgress(_, _ string, _ *v1beta1.NetworkNeighbors) error {
	return nil
}
