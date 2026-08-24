package healthmanager

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/stretchr/testify/assert"
)

type mockUnreadyWatcher struct {
	containerwatcher.ContainerWatcherMock
}

func (m *mockUnreadyWatcher) Ready() bool {
	return false
}

func TestNewHealthManager(t *testing.T) {
	hm := NewHealthManager()
	assert.NotNil(t, hm)
	assert.Equal(t, 7888, hm.port)
	assert.Nil(t, hm.containerWatcher)
}

func TestLivenessProbe_AlwaysReturnsOK(t *testing.T) {
	hm := NewHealthManager()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/livez", nil)
	w := httptest.NewRecorder()

	hm.livenessProbe(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestReadinessProbe(t *testing.T) {
	tests := []struct {
		name           string
		setWatcher     bool
		isReady        bool
		expectedStatus int
	}{
		{
			name:           "nil container watcher returns 500",
			setWatcher:     false,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "unready container watcher returns 500",
			setWatcher:     true,
			isReady:        false,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "container watcher ready returns 200",
			setWatcher:     true,
			isReady:        true,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hm := NewHealthManager()

			if tt.setWatcher {
				if tt.isReady {
					hm.SetContainerWatcher(&containerwatcher.ContainerWatcherMock{})
				} else {
					hm.SetContainerWatcher(&mockUnreadyWatcher{})
				}
			}

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil)
			w := httptest.NewRecorder()

			hm.readinessProbe(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestSetContainerWatcher(t *testing.T) {
	hm := NewHealthManager()
	assert.Nil(t, hm.containerWatcher)

	mock := &containerwatcher.ContainerWatcherMock{}
	hm.SetContainerWatcher(mock)

	assert.NotNil(t, hm.containerWatcher)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	hm.readinessProbe(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
