package sandboxpolicy

import (
	"strings"
	"testing"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

func TestPrivilegeDocumentRejectsFlaglessClone(t *testing.T) {
	section := func(syscall string, flags ...string) api.PrivilegeSection {
		return api.PrivilegeSection{Default: api.ActionAllow, Rules: []api.PrivilegeRule{{
			Rule:   api.Rule{Name: "r", Action: api.ActionDeny},
			Target: api.PrivilegeTarget{Syscall: []string{syscall}, Flags: flags},
		}}}
	}
	for _, sc := range []string{"clone", "clone3"} {
		if _, err := PrivilegeDocument("p", api.ModeEnforce, section(sc)); err == nil || !strings.Contains(err.Error(), "plain fork") {
			t.Errorf("%s without flags must be rejected with a clear error: %v", sc, err)
		}
		if _, err := PrivilegeDocument("p", api.ModeEnforce, section(sc, "CLONE_NEWNS")); err != nil {
			t.Errorf("%s with flags: %v", sc, err)
		}
	}
}

func TestPrivilegeDocumentExceptAndOrigin(t *testing.T) {
	origin := "catalog/P1"
	rule := api.PrivilegeRule{Rule: api.Rule{Name: "r", Action: api.ActionDeny, Origin: &origin}, Target: api.PrivilegeTarget{Syscall: []string{"mount"}}}
	doc, err := PrivilegeDocument("p", api.ModeEnforce, api.PrivilegeSection{Default: api.ActionAllow, Rules: []api.PrivilegeRule{rule}})
	if err != nil || doc.Policy.Privilege.Rules[0].Origin != origin {
		t.Fatalf("origin: %+v %v", doc.Policy.Privilege.Rules, err)
	}
	rule.Except = []api.PrivilegeException{{}}
	if _, err := PrivilegeDocument("p", api.ModeEnforce, api.PrivilegeSection{Default: api.ActionAllow, Rules: []api.PrivilegeRule{rule}}); err == nil || !strings.Contains(err.Error(), "exceptions") {
		t.Fatalf("an exception must be rejected: %v", err)
	}
}
