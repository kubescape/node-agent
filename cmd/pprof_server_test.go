package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPprofServer(t *testing.T) {
	srv := newPprofServer("localhost:6060")

	assert.Equal(t, "localhost:6060", srv.Addr)
	assert.Equal(t, 10*time.Second, srv.ReadHeaderTimeout)

	require.NotNil(t, srv.Handler)
	_, isMux := srv.Handler.(*http.ServeMux)
	assert.True(t, isMux, "handler should be a dedicated *http.ServeMux")
	assert.NotSame(t, http.DefaultServeMux, srv.Handler, "handler must not be http.DefaultServeMux")
}

func TestNewPprofServerServesPprofIndex(t *testing.T) {
	srv := newPprofServer("localhost:6060")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	srv.Handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}
