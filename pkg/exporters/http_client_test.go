package exporters

import (
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
