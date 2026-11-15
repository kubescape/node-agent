//go:build !sandbox_shared_qualification

package integration

import (
	"strings"
	"testing"

	"github.com/kubescape/node-agent/pkg/config"
)

// A default build never runs a configured shared engine's image as
// per-binding owners: it refuses before building the engine.
func TestDefaultEngineRefusesSharedSelection(t *testing.T) {
	for _, engine := range []string{"shared", "legacy"} {
		_, err := newFullEngine(nil, nil, nil, ServiceOptions{Engine: config.SandboxPolicyEngineConfig{Engine: engine}}, nil)
		if err == nil || !strings.Contains(err.Error(), "requires a sandbox_shared_qualification build") {
			t.Fatalf("engine %q: %v", engine, err)
		}
	}
	for _, engine := range []string{"", "full"} {
		_, err := newFullEngine(nil, nil, nil, ServiceOptions{Engine: config.SandboxPolicyEngineConfig{Engine: engine}, MaxOwners: 1}, nil)
		if err != nil && strings.Contains(err.Error(), "sandbox_shared_qualification") {
			t.Fatalf("engine %q refused as shared: %v", engine, err)
		}
	}
}
