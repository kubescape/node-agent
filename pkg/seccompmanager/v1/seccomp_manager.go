package seccompmanager

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/kubescape/node-agent/pkg/seccompmanager"

	securejoin "github.com/cyphar/filepath-securejoin"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	v1beta1api "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/spf13/afero"
	"go.uber.org/multierr"
	"k8s.io/apimachinery/pkg/types"
)

type SeccompManager struct {
	appFs              afero.Fs
	profilesPaths      maps.SafeMap[types.UID, mapset.Set[string]]
	seccompProfilesDir string
}

func NewSeccompManager() (*SeccompManager, error) {
	seccompProfilesDir, err := getProfilesDir()
	if err != nil {
		return nil, err
	}
	return &SeccompManager{
		appFs:              afero.NewOsFs(),
		seccompProfilesDir: seccompProfilesDir,
	}, nil
}

var _ seccompmanager.SeccompManagerClient = (*SeccompManager)(nil)

func (s *SeccompManager) AddSeccompProfile(sp *v1beta1api.SeccompProfile) error {
	// store the profile for each container
	var errs error
	profilePaths := mapset.NewSet[string]()
	for _, containerProfile := range slices.Concat(sp.Spec.Containers, sp.Spec.InitContainers, sp.Spec.EphemeralContainers) {
		if containerProfile.Path == "" {
			errs = multierr.Append(errs, fmt.Errorf("seccomp profile path is empty for %s", containerProfile.Name))
			continue
		}
		profilePath := filepath.Join(s.seccompProfilesDir, containerProfile.Path)
		logger.L().Debug("SeccompManager - adding seccomp profile", helpers.String("name", sp.Name),
			helpers.String("container", containerProfile.Name), helpers.String("path", profilePath))
		profileBytes, err := json.Marshal(containerProfile.Spec)
		if err != nil {
			errs = multierr.Append(errs, fmt.Errorf("failed to marshal seccomp profile for %s: %w", containerProfile.Name, err))
			continue
		}
		if err := s.appFs.MkdirAll(filepath.Dir(profilePath), 0755); err != nil {
			errs = multierr.Append(errs, fmt.Errorf("failed to make dirs: %w", err))
			continue
		}
		if err := afero.WriteFile(s.appFs, profilePath, profileBytes, 0644); err != nil {
			errs = multierr.Append(errs, fmt.Errorf("failed to write seccomp profile: %w", err))
			continue
		}
		profilePaths.Add(profilePath)
	}
	s.profilesPaths.Set(sp.GetUID(), profilePaths)
	return errs
}

func (s *SeccompManager) DeleteSeccompProfile(obj *v1beta1api.SeccompProfile) error {
	uid := obj.GetUID()
	var errs error
	for _, path := range s.profilesPaths.Get(uid).ToSlice() {
		logger.L().Debug("SeccompManager - deleting seccomp profile", helpers.String("path", path))
		if err := s.appFs.Remove(path); err != nil {
			errs = multierr.Append(errs, fmt.Errorf("failed to delete seccomp profile: %w", err))
		}
	}
	s.profilesPaths.Delete(uid)
	return errs
}

func (s *SeccompManager) GetSeccompProfile(name string, path *string) (v1beta1.SingleSeccompProfile, error) {
	if path == nil {
		return v1beta1.SingleSeccompProfile{}, nil
	}
	profilePath := filepath.Join(s.seccompProfilesDir, *path)
	logger.L().Debug("SeccompManager - getting seccomp profile", helpers.String("path", profilePath))
	profileBytes, err := afero.ReadFile(s.appFs, profilePath)
	if err != nil {
		return v1beta1.SingleSeccompProfile{}, fmt.Errorf("failed to read seccomp profile: %w", err)
	}
	sp := v1beta1.SingleSeccompProfile{
		Name: name,
		Path: *path,
	}
	err = json.Unmarshal(profileBytes, &sp.Spec)
	if err != nil {
		return v1beta1.SingleSeccompProfile{}, fmt.Errorf("failed to unmarshal seccomp profile: %w", err)
	}
	return sp, nil
}

func getProfilesDir() (string, error) {
	// read HOST_ROOT from env
	hostRoot, exists := os.LookupEnv("HOST_ROOT")
	if !exists {
		hostRoot = "/host"
	}
	// read KUBELET_ROOT from env
	kubeletRoot, exists := os.LookupEnv("KUBELET_ROOT")
	if !exists {
		kubeletRoot = "/var/lib/kubelet"
	}
	// use securejoin to join the two, add seccomp and store in seccompProfilesDir
	seccompProfilesDir, err := securejoin.SecureJoin(filepath.Join(hostRoot, kubeletRoot), "seccomp")
	if err != nil {
		return "", fmt.Errorf("failed to join seccomp profiles dir: %w", err)
	}
	return seccompProfilesDir, nil
}
