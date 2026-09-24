package storage

import (
	"context"
	"fmt"
	"sync"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

const (
	NginxImageID     = "nginx@sha256:6a59f1cbb8d28ac484176d52c473494859a512ddba3ea62a547258cf16c9b3ae"
	FluentBitImageID = "fluentbit@sha256:236f7d961b0ba8b91796955f155819d64801e0d00fa666147502ab9b5b80f623"
)

type StorageHttpClientMock struct {
	// containerProfilesMu guards ContainerProfiles: CreateContainerProfileDirect
	// can be invoked from a caller's own background goroutine (e.g. the
	// container profile manager's persistent queue processing loop), so a
	// test reading ContainerProfiles from a different goroutine while that
	// loop is still running must go through ContainerProfilesSnapshot instead
	// of reading the field directly.
	containerProfilesMu sync.Mutex
	SyftSBOMs           []*spdxv1beta1.SBOMSyft
	ContainerProfiles   []*v1beta1.ContainerProfile
	ImageCounters       map[string]int
	mockSBOM            *v1beta1.SBOMSyft
}

var _ ProfileClient = (*StorageHttpClientMock)(nil)
var _ ProfileCreator = (*StorageHttpClientMock)(nil)
var _ SbomClient = (*StorageHttpClientMock)(nil)
var _ StorageClient = (*StorageHttpClientMock)(nil)

// CreateContainerProfileDirect records profile as if it had been persisted to
// storage. Guarded by containerProfilesMu since it may be invoked from a
// caller's own background goroutine (e.g. the container profile manager's
// persistent queue processing loop).
func (sc *StorageHttpClientMock) CreateContainerProfileDirect(profile *v1beta1.ContainerProfile) error {
	sc.containerProfilesMu.Lock()
	defer sc.containerProfilesMu.Unlock()
	sc.ContainerProfiles = append(sc.ContainerProfiles, profile)
	return nil
}

// ContainerProfilesSnapshot returns a thread-safe copy of the container
// profiles recorded so far. Use this instead of reading ContainerProfiles
// directly when CreateContainerProfileDirect may still be called
// concurrently (e.g. while polling for delivery via require.Eventually).
func (sc *StorageHttpClientMock) ContainerProfilesSnapshot() []*v1beta1.ContainerProfile {
	sc.containerProfilesMu.Lock()
	defer sc.containerProfilesMu.Unlock()
	out := make([]*v1beta1.ContainerProfile, len(sc.ContainerProfiles))
	copy(out, sc.ContainerProfiles)
	return out
}

func (sc *StorageHttpClientMock) CreateSBOM(SBOM *v1beta1.SBOMSyft) (*v1beta1.SBOMSyft, error) {
	sc.SyftSBOMs = append(sc.SyftSBOMs, SBOM)
	return SBOM, nil
}

// GetContainerProfile finds a previously recorded profile by namespace and
// name, or (nil, nil) if none matches.
func (sc *StorageHttpClientMock) GetContainerProfile(_ context.Context, namespace, name string) (*v1beta1.ContainerProfile, error) {
	sc.containerProfilesMu.Lock()
	defer sc.containerProfilesMu.Unlock()
	for _, p := range sc.ContainerProfiles {
		if p != nil && p.Namespace == namespace && p.Name == name {
			return p, nil
		}
	}
	return nil, nil
}

func (sc *StorageHttpClientMock) GetSBOMMeta(_ string) (*v1beta1.SBOMSyft, error) {
	return sc.mockSBOM, nil
}

func (sc *StorageHttpClientMock) GetStorageClient() beta1.SpdxV1beta1Interface {
	return nil
}

func (sc *StorageHttpClientMock) ReplaceSBOM(SBOM *v1beta1.SBOMSyft) (*v1beta1.SBOMSyft, error) {
	sc.SyftSBOMs = append(sc.SyftSBOMs, SBOM)
	return SBOM, nil
}

func (sc *StorageHttpClientMock) PatchSBOMAnnotations(_ string, annotations map[string]any) (*v1beta1.SBOMSyft, error) {
	if sc.mockSBOM == nil {
		return nil, nil
	}
	if sc.mockSBOM.Annotations == nil {
		sc.mockSBOM.Annotations = map[string]string{}
	}
	for k, v := range annotations {
		if v == nil {
			delete(sc.mockSBOM.Annotations, k)
			continue
		}
		sc.mockSBOM.Annotations[k] = fmt.Sprintf("%v", v)
	}
	return sc.mockSBOM, nil
}

// SeccompProfileClientMock is a mock implementation of SeccompProfileClient for testing
type SeccompProfileClientMock struct {
	Profiles     []*v1beta1.SeccompProfile
	WatchEvents  chan watch.Event
	WatchStopped bool
	GetError     error
	ListError    error
	WatchError   error
}

var _ SeccompProfileClient = (*SeccompProfileClientMock)(nil)

func NewSeccompProfileClientMock() *SeccompProfileClientMock {
	return &SeccompProfileClientMock{
		Profiles:    make([]*v1beta1.SeccompProfile, 0),
		WatchEvents: make(chan watch.Event, 100),
	}
}

func (m *SeccompProfileClientMock) WatchSeccompProfiles(_ string, _ metav1.ListOptions) (watch.Interface, error) {
	if m.WatchError != nil {
		return nil, m.WatchError
	}
	return &mockWatch{events: m.WatchEvents, stopped: &m.WatchStopped}, nil
}

func (m *SeccompProfileClientMock) ListSeccompProfiles(_ string, _ metav1.ListOptions) (*v1beta1.SeccompProfileList, error) {
	if m.ListError != nil {
		return nil, m.ListError
	}
	items := make([]v1beta1.SeccompProfile, 0, len(m.Profiles))
	for _, p := range m.Profiles {
		if p != nil {
			items = append(items, *p)
		}
	}
	return &v1beta1.SeccompProfileList{Items: items}, nil
}

func (m *SeccompProfileClientMock) GetSeccompProfile(namespace, name string) (*v1beta1.SeccompProfile, error) {
	if m.GetError != nil {
		return nil, m.GetError
	}
	for _, p := range m.Profiles {
		if p != nil && p.Namespace == namespace && p.Name == name {
			return p, nil
		}
	}
	return nil, nil
}

// mockWatch implements watch.Interface for testing
type mockWatch struct {
	events  chan watch.Event
	stopped *bool
}

func (m *mockWatch) Stop() {
	*m.stopped = true
}

func (m *mockWatch) ResultChan() <-chan watch.Event {
	return m.events
}
