//go:build experimental_signing

package healthmanager

import (
	"encoding/json"
	"net/http"

	"github.com/kubescape/node-agent/pkg/signature/bundle"
)

type policyHealth struct{ policyStatus func() *bundle.PolicyStatus }

func (h *HealthManager) registerPolicyHandler() { http.HandleFunc("/policyz", h.policyzHandler) }
func (h *HealthManager) SetPolicyStatus(getter func() *bundle.PolicyStatus) {
	h.policyStatus = getter
}

func (h *HealthManager) policyzHandler(w http.ResponseWriter, _ *http.Request) {
	if h.policyStatus == nil {
		http.NotFound(w, nil)
		return
	}
	s := h.policyStatus()
	if s == nil {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s)
}
