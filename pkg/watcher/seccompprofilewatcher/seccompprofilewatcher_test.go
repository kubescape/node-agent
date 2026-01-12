package seccompprofilewatcher

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	v1beta1api "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

// trackingSeccompManagerMock tracks profiles for testing
type trackingSeccompManagerMock struct {
	mu       sync.Mutex
	profiles map[string]*v1beta1api.SeccompProfile
}

var _ seccompmanager.SeccompManagerClient = (*trackingSeccompManagerMock)(nil)

func newTrackingSeccompManagerMock() *trackingSeccompManagerMock {
	return &trackingSeccompManagerMock{
		profiles: make(map[string]*v1beta1api.SeccompProfile),
	}
}

func (m *trackingSeccompManagerMock) AddSeccompProfile(profile *v1beta1api.SeccompProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := profile.Namespace + "/" + profile.Name
	m.profiles[key] = profile
	return nil
}

func (m *trackingSeccompManagerMock) DeleteSeccompProfile(profile *v1beta1api.SeccompProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := profile.Namespace + "/" + profile.Name
	delete(m.profiles, key)
	return nil
}

func (m *trackingSeccompManagerMock) GetSeccompProfile(_ string, _ *string) (v1beta1api.SingleSeccompProfile, error) {
	return v1beta1api.SingleSeccompProfile{}, nil
}

func (m *trackingSeccompManagerMock) GetProfileCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.profiles)
}

func TestNewSeccompProfileWatcher(t *testing.T) {
	mockClient := storage.NewSeccompProfileClientMock()
	mockManager := newTrackingSeccompManagerMock()

	watcher := NewSeccompProfileWatcher(mockClient, mockManager)

	assert.NotNil(t, watcher)
	assert.NotNil(t, watcher.client)
	assert.NotNil(t, watcher.seccompManager)
	assert.NotNil(t, watcher.stopCh)
}

func TestSeccompProfileWatcher_HandleAdd(t *testing.T) {
	mockClient := storage.NewSeccompProfileClientMock()
	mockManager := newTrackingSeccompManagerMock()
	watcher := NewSeccompProfileWatcher(mockClient, mockManager)

	profile := &v1beta1api.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-profile",
			Namespace: "test-namespace",
		},
		Spec: v1beta1api.SeccompProfileSpec{
			Containers: []v1beta1api.SingleSeccompProfile{
				{Name: "container1"},
			},
		},
	}

	ctx := context.Background()
	watcher.handleAdd(ctx, profile)

	// Verify the profile was added to the mock manager
	assert.Equal(t, 1, mockManager.GetProfileCount())
}

func TestSeccompProfileWatcher_HandleModify(t *testing.T) {
	mockClient := storage.NewSeccompProfileClientMock()
	mockManager := newTrackingSeccompManagerMock()
	watcher := NewSeccompProfileWatcher(mockClient, mockManager)

	profile := &v1beta1api.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-profile",
			Namespace: "test-namespace",
		},
	}

	ctx := context.Background()
	watcher.handleModify(ctx, profile)

	// Modify also adds the profile
	assert.Equal(t, 1, mockManager.GetProfileCount())
}

func TestSeccompProfileWatcher_HandleDelete(t *testing.T) {
	mockClient := storage.NewSeccompProfileClientMock()
	mockManager := newTrackingSeccompManagerMock()
	watcher := NewSeccompProfileWatcher(mockClient, mockManager)

	profile := &v1beta1api.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-profile",
			Namespace: "test-namespace",
		},
	}

	// First add the profile
	ctx := context.Background()
	watcher.handleAdd(ctx, profile)
	assert.Equal(t, 1, mockManager.GetProfileCount())

	// Then delete it
	watcher.handleDelete(ctx, profile)
	assert.Equal(t, 0, mockManager.GetProfileCount())
}

func TestSeccompProfileWatcher_ListExisting(t *testing.T) {
	mockClient := storage.NewSeccompProfileClientMock()
	mockManager := newTrackingSeccompManagerMock()
	watcher := NewSeccompProfileWatcher(mockClient, mockManager)

	// Add some profiles to the mock client
	mockClient.Profiles = []*v1beta1api.SeccompProfile{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "profile1",
				Namespace: "ns1",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "profile2",
				Namespace: "ns2",
			},
		},
	}

	ctx := context.Background()
	err := watcher.listExisting(ctx)

	assert.NoError(t, err)
	assert.Equal(t, 2, mockManager.GetProfileCount())
}

func TestSeccompProfileWatcher_ProcessEvents(t *testing.T) {
	mockClient := storage.NewSeccompProfileClientMock()
	mockManager := newTrackingSeccompManagerMock()
	watcher := NewSeccompProfileWatcher(mockClient, mockManager)

	profile := &v1beta1api.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "test-profile",
			Namespace:       "test-namespace",
			ResourceVersion: "123",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Create a mock watch that will send events
	mockWatch := &testWatch{
		events: make(chan watch.Event, 3),
	}

	// Send add event
	mockWatch.events <- watch.Event{
		Type:   watch.Added,
		Object: profile,
	}

	// Close the watch
	close(mockWatch.events)

	rv := watcher.processEvents(ctx, mockWatch)

	assert.Equal(t, "123", rv)
	assert.Equal(t, 1, mockManager.GetProfileCount())
}

func TestSeccompProfileWatcher_Stop(t *testing.T) {
	mockClient := storage.NewSeccompProfileClientMock()
	mockManager := newTrackingSeccompManagerMock()
	watcher := NewSeccompProfileWatcher(mockClient, mockManager)

	// Should not panic
	watcher.Stop()

	// Channel should be closed
	select {
	case _, ok := <-watcher.stopCh:
		assert.False(t, ok, "stopCh should be closed")
	default:
		t.Error("stopCh should be closed")
	}
}

// testWatch is a simple test implementation of watch.Interface
type testWatch struct {
	events  chan watch.Event
	stopped bool
}

func (w *testWatch) Stop() {
	w.stopped = true
}

func (w *testWatch) ResultChan() <-chan watch.Event {
	return w.events
}
