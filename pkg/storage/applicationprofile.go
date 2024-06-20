package storage

import (
	"encoding/json"
	"errors"
	"fmt"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	errors2 "k8s.io/apimachinery/pkg/api/errors"
)

func (sc *StorageHttpClientMock) GetApplicationProfile(_, _ string) (*v1beta1.ApplicationProfile, error) {
	if len(sc.ApplicationProfiles) == 0 {
		return &v1beta1.ApplicationProfile{
			Spec: v1beta1.ApplicationProfileSpec{
				Containers: []v1beta1.ApplicationProfileContainer{
					{Capabilities: []string{"SYS_ADMIN"}},
					{Capabilities: []string{"NET_BROADCAST"}},
				},
			},
		}, nil
	}
	return sc.ApplicationProfiles[len(sc.ApplicationProfiles)-1], nil
}

func (sc *StorageHttpClientMock) CreateApplicationProfile(profile *v1beta1.ApplicationProfile, _ string) error {
	if !sc.failedOnce {
		sc.failedOnce = true
		return errors.New("first time fail")
	}
	sc.ApplicationProfiles = append(sc.ApplicationProfiles, profile)
	return nil
}

func (sc *StorageHttpClientMock) PatchApplicationProfile(name, _ string, patchJSON []byte, _ chan error) error {
	if len(sc.ApplicationProfiles) == 0 {
		return errors2.NewNotFound(v1beta1.Resource("applicationprofile"), name)
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
	profile := &v1beta1.ApplicationProfile{}
	if err := json.Unmarshal(patchedProfile, profile); err != nil {
		return fmt.Errorf("unmarshal patched profile: %w", err)
	}
	sc.ApplicationProfiles = append(sc.ApplicationProfiles, profile)
	return nil
}
