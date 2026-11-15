package networkstream

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSendNetworkEvent_SendsBearerFromTokenFile: the synchronizer authorizes
// networkstreams with RBAC, so the stream post must carry the exporter's token.
func TestSendNetworkEvent_SendsBearerFromTokenFile(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("tok"), 0o600))

	tests := []struct {
		name      string
		tokenFile string
		want      string
	}{
		{name: "token file set", tokenFile: tokenFile, want: "Bearer tok"},
		{name: "token file empty", tokenFile: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath, gotAuth string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotAuth = r.Header.Get("Authorization")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			// KubernetesMode is off while constructing so no k8s inventory is
			// needed; the client is still the factory-built one.
			ns, err := NewNetworkStream(context.Background(), config.Config{
				Exporters: exporters.ExportersConfig{
					HTTPExporterConfig: &exporters.HTTPExporterConfig{
						URL:       server.URL,
						Method:    http.MethodPost,
						TokenFile: tt.tokenFile,
					},
				},
			}, nil, stubResolver{}, testNodeName, nil, true, nil)
			require.NoError(t, err)
			// sendNetworkEvent only posts in Kubernetes mode.
			ns.cfg.KubernetesMode = true

			stream := &armotypes.NetworkStream{Entities: map[string]armotypes.NetworkStreamEntity{
				testNodeName: {
					Kind:     armotypes.NetworkStreamEntityKindHost,
					Outbound: map[string]armotypes.NetworkStreamEvent{"1.2.3.4/443/TCP": {}},
				},
			}}
			require.NoError(t, ns.sendNetworkEvent(stream))
			assert.Equal(t, "/v1/networkstreams", gotPath)
			assert.Equal(t, tt.want, gotAuth)
		})
	}
}

func TestNewNetworkStream_RejectsTokenFileWithoutURLHost(t *testing.T) {
	_, err := NewNetworkStream(context.Background(), config.Config{
		Exporters: exporters.ExportersConfig{
			HTTPExporterConfig: &exporters.HTTPExporterConfig{URL: "synchronizer:8089", TokenFile: "/token"},
		},
	}, nil, stubResolver{}, testNodeName, nil, true, nil)
	assert.Error(t, err)
}
