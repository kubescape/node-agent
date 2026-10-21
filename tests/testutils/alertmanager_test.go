package testutils

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGetAlertsCancelsBlockedRequest(t *testing.T) {
	entered := make(chan struct{})
	canceled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(entered)
		<-request.Context().Done()
		close(canceled)
	}))
	defer server.Close()
	t.Setenv("ALERTMANAGER_URL", server.URL)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := GetAlertsWithContext(ctx, "test")
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("alert request did not reach the server")
	}
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("alert request ignored cancellation")
	}
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("request I/O was abandoned rather than canceled")
	}
}
