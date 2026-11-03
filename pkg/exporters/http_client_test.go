package exporters

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHTTPClient(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *HTTPExporterConfig
		wantTimeout time.Duration
		wantErr     bool
		wantBearer  bool
	}{
		{name: "nil config uses fallback", cfg: nil, wantTimeout: 7 * time.Second},
		{name: "unset timeout uses fallback", cfg: &HTTPExporterConfig{URL: "http://sync:8089"}, wantTimeout: 7 * time.Second},
		{name: "configured timeout", cfg: &HTTPExporterConfig{URL: "http://sync:8089", TimeoutSeconds: 3}, wantTimeout: 3 * time.Second},
		{name: "token file installs bearer transport", cfg: &HTTPExporterConfig{URL: "http://sync:8089", TokenFile: "/token"}, wantTimeout: 7 * time.Second, wantBearer: true},
		{name: "token file with unparsable url", cfg: &HTTPExporterConfig{URL: "http://[::1", TokenFile: "/token"}, wantErr: true},
		{name: "token file with url lacking a host", cfg: &HTTPExporterConfig{URL: "synchronizer:8089", TokenFile: "/token"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewHTTPClient(tt.cfg, 7*time.Second)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantTimeout, client.Timeout)
			assert.Equal(t, tt.wantBearer, client.Transport != nil)
		})
	}
}

// syncHost is the exporter host in the redirect tests. Both test servers are
// reached through it (https on :443, http on :80), so a downgrade redirect
// lands on the very host the bearer transport sends the token to, as it would
// against a real server answering both schemes.
const syncHost = "sync.test"

// routedTransport dials syncHost:443 to tlsSrv and syncHost:80 to plainSrv,
// and trusts tlsSrv's certificate.
func routedTransport(t *testing.T, tlsSrv, plainSrv *httptest.Server) *http.Transport {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(tlsSrv.Certificate())
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var target string
			switch addr {
			case syncHost + ":443":
				target = tlsSrv.Listener.Addr().String()
			case syncHost + ":80":
				target = plainSrv.Listener.Addr().String()
			default:
				return nil, fmt.Errorf("unexpected dial to %s", addr)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, target)
		},
		// The httptest certificate is issued for example.com.
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"},
	}
}

// authRecorder records the Authorization header of every request it serves.
type authRecorder struct {
	mu   sync.Mutex
	seen []string
}

func (a *authRecorder) record(r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seen = append(a.seen, r.URL.Path+" "+r.Header.Get("Authorization"))
}

func (a *authRecorder) requests() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.seen...)
}

func TestNewHTTPClient_RedirectPolicyWithToken(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("tok"), 0o600))

	plain := &authRecorder{}
	plainSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plain.record(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer plainSrv.Close()

	secure := &authRecorder{}
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secure.record(r)
		switch r.URL.Path {
		case "/downgrade":
			http.Redirect(w, r, "http://"+syncHost+"/landed", http.StatusFound)
		case "/upgrade-only":
			http.Redirect(w, r, "https://"+syncHost+"/final", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer tlsSrv.Close()

	client, err := newHTTPClient(&HTTPExporterConfig{URL: "https://" + syncHost, TokenFile: tokenFile},
		5*time.Second, routedTransport(t, tlsSrv, plainSrv))
	require.NoError(t, err)

	post := func(path string) error {
		resp, err := client.Post("https://"+syncHost+path, "application/json", nil)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return nil
	}

	t.Run("https to http is refused", func(t *testing.T) {
		err := post("/downgrade")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refusing redirect from https to http while a bearer token is configured")
		assert.Empty(t, plain.requests(), "the plaintext server must never be contacted")
	})

	t.Run("https to https is followed with the token", func(t *testing.T) {
		require.NoError(t, post("/upgrade-only"))
		assert.Contains(t, secure.requests(), "/final Bearer tok")
	})

	t.Run("redirect limit is kept", func(t *testing.T) {
		err := post("/loop")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "stopped after 10 redirects")
	})
}

// TestNewHTTPClient_NoTokenKeepsDefaultRedirects: without a token there is
// nothing to leak, so Go's default policy, downgrades included, still applies.
func TestNewHTTPClient_NoTokenKeepsDefaultRedirects(t *testing.T) {
	client, err := NewHTTPClient(&HTTPExporterConfig{URL: "https://" + syncHost}, 5*time.Second)
	require.NoError(t, err)
	assert.Nil(t, client.CheckRedirect)
}
