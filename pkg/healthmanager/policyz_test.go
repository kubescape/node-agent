//go:build experimental_signing

package healthmanager

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/stretchr/testify/require"
)

func TestPolicyz_NotFoundWhenUnset(t *testing.T) {
	h := NewHealthManager()
	rec := httptest.NewRecorder()
	h.policyzHandler(rec, nil)
	require.Equal(t, 404, rec.Code)

	h.SetPolicyStatus(func() *bundle.PolicyStatus { return nil })
	rec = httptest.NewRecorder()
	h.policyzHandler(rec, nil)
	require.Equal(t, 404, rec.Code, "nil snapshot must 404, not serve an empty status")
}

func TestPolicyz_ServesIdentityWithoutPolicyBody(t *testing.T) {
	h := NewHealthManager()
	h.SetPolicyStatus(func() *bundle.PolicyStatus {
		return &bundle.PolicyStatus{
			InForceDigest:  "abc123",
			Mode:           "enforce",
			RuleClassCount: 2,
			RulesAdmitted:  1,
			RulesRejected:  3,
		}
	})
	rec := httptest.NewRecorder()
	h.policyzHandler(rec, nil)
	require.Equal(t, 200, rec.Code)

	var got map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, "abc123", got["inForceDigest"])
	require.Equal(t, "enforce", got["mode"])
	require.EqualValues(t, 3, got["rulesRejected"])

	body := rec.Body.String()
	for _, forbidden := range []string{"signers", "allowedRuleIDs", "allowedSpecPaths", "classes\""} {
		require.False(t, strings.Contains(body, forbidden),
			"policyz must not leak policy contents, found %q in %s", forbidden, body)
	}
}
