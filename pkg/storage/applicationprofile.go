package storage

import (
	"encoding/json"
	"errors"
	"fmt"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	errors2 "k8s.io/apimachinery/pkg/api/errors"
)

func (sc *StorageHttpClientMock) GetContainerProfile(namespace, name string) (*v1beta1.ContainerProfile, error) {
	if len(sc.ContainerProfiles) == 0 {
		return &v1beta1.ContainerProfile{
			Spec: v1beta1.ContainerProfileSpec{
				Capabilities: []string{"SYS_ADMIN"},
			},
		}, nil
	}
	return sc.ContainerProfiles[len(sc.ContainerProfiles)-1], nil
}

func (sc *StorageHttpClientMock) CreateContainerProfile(profile *v1beta1.ContainerProfile, namespace string) error {
	if !sc.failedOnce {
		sc.failedOnce = true
		return errors.New("first time fail")
	}
	sc.ContainerProfiles = append(sc.ContainerProfiles, profile)
	return nil
}

func (sc *StorageHttpClientMock) PatchApplicationProfile(name, _ string, operations []utils.PatchOperation, _ *utils.WatchedContainerData) error {
	if len(sc.ContainerProfiles) == 0 {
		return errors2.NewNotFound(v1beta1.Resource("applicationprofile"), name)
	}
	// get last profile
	lastProfile, err := json.Marshal(sc.ContainerProfiles[len(sc.ContainerProfiles)-1])
	if err != nil {
		return fmt.Errorf("marshal last profile: %w", err)
	}
	patchJSON, err := json.Marshal(operations)
	if err != nil {
		return fmt.Errorf("marshal patch: %w", err)
	}
	patch, err := jsonpatch.DecodePatch(patchJSON)
	if err != nil {
		return fmt.Errorf("decode patch: %w", err)
	}
	patchedProfile, err := patch.Apply(lastProfile)
	if err != nil {
		return fmt.Errorf("apply patch: %w", err)
	}
	profile := &v1beta1.ContainerProfile{}
	if err := json.Unmarshal(patchedProfile, profile); err != nil {
		return fmt.Errorf("unmarshal patched profile: %w", err)
	}
	sc.ContainerProfiles = append(sc.ContainerProfiles, profile)
	return nil
}
