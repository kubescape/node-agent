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

	rv, exit := watcher.processEvents(ctx, mockWatch)

	assert.Equal(t, "123", rv)
	assert.Equal(t, exitChannelClosed, exit)
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

// erroringClient is a SeccompProfileClient whose watches immediately emit a 410
// error event. It counts how often the watcher re-Lists and re-Watches so we can
// prove the retry loop re-Lists on error and does not hot-spin.
type erroringClient struct {
	mu         sync.Mutex
	listCalls  int
	watchCalls int
}

var _ storage.SeccompProfileClient = (*erroringClient)(nil)

func (c *erroringClient) WatchSeccompProfiles(_ string, _ metav1.ListOptions) (watch.Interface, error) {
	c.mu.Lock()
	c.watchCalls++
	c.mu.Unlock()
	ch := make(chan watch.Event, 1)
	ch <- watch.Event{Type: watch.Error, Object: &metav1.Status{Reason: metav1.StatusReasonExpired, Code: 410}}
	// Do NOT close ch: processEvents returns on the error event, then Stops the watch.
	return &testWatch{events: ch}, nil
}

func (c *erroringClient) ListSeccompProfiles(_ string, _ metav1.ListOptions) (*v1beta1api.SeccompProfileList, error) {
	c.mu.Lock()
	c.listCalls++
	c.mu.Unlock()
	return &v1beta1api.SeccompProfileList{ListMeta: metav1.ListMeta{ResourceVersion: "fresh"}}, nil
}

func (c *erroringClient) GetSeccompProfile(_ string, _ string) (*v1beta1api.SeccompProfile, error) {
	return nil, nil
}

func (c *erroringClient) counts() (list, watch int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.listCalls, c.watchCalls
}

func TestSeccompProfileWatcher_ReListsAndBacksOffOnError(t *testing.T) {
	client := &erroringClient{}
	watcher := NewSeccompProfileWatcher(client, newTrackingSeccompManagerMock())

	go watcher.watchWithRetry(context.Background())

	// Re-List must engage on the error event (pre-fix: never re-Lists).
	assert.Eventually(t, func() bool {
		list, _ := client.counts()
		return list >= 1
	}, 3*time.Second, 10*time.Millisecond, "watcher must re-List after a watch.Error")

	// Let it run a fixed window, then stop and assert it did NOT hot-spin.
	time.Sleep(time.Second)
	watcher.Stop()

	list, watchCount := client.counts()
	assert.GreaterOrEqual(t, list, 1)
	// Pre-fix this loop spins hundreds-to-thousands of times/sec with zero delay.
	// Post-fix each error triggers re-List + exponential backoff (>=~250ms), so a
	// ~1s window yields only a handful of attempts. 20 is a generous ceiling that
	// still separates cleanly from the pre-fix hot loop.
	assert.Less(t, watchCount, 20, "retry loop must back off, not hot-spin")
}
