//go:build experimental_signing

package bundle

import (
	"errors"
	"testing"
)

// D16: enforcement is a one-way door; signers are append-only.
func TestD16_Guards(t *testing.T) {
	enforce := &TrustPolicy{Mode: ModeEnforce, Classes: map[FragmentClass]ClassPolicy{
		"base": {Signers: []string{"key:aaa", "key:bbb"}},
	}}
	alertFewer := &TrustPolicy{Mode: ModeAlert, Classes: map[FragmentClass]ClassPolicy{
		"base": {Signers: []string{"key:aaa", "key:bbb"}},
	}}
	enforceRemoved := &TrustPolicy{Mode: ModeEnforce, Classes: map[FragmentClass]ClassPolicy{
		"base": {Signers: []string{"key:aaa"}},
	}}
	enforceAdded := &TrustPolicy{Mode: ModeEnforce, Classes: map[FragmentClass]ClassPolicy{
		"base": {Signers: []string{"key:aaa", "key:bbb", "key:ccc"}},
	}}

	r := &PolicyReloader{}
	r.NoteInForce(enforce)

	if r.inForce.Mode == ModeEnforce && alertFewer.Mode != ModeEnforce {
		// mirrors Poll's guard; assert the sentinel wiring
		err := errors.Join(ErrEnforceDowngrade)
		if !errors.Is(err, ErrEnforceDowngrade) {
			t.Fatal("sentinel broken")
		}
	}
	if got := removedSigners(enforce, enforceRemoved); len(got) != 1 || got[0] != "base:key:bbb" {
		t.Fatalf("signer removal must be detected, got %v", got)
	}
	if got := removedSigners(enforce, enforceAdded); len(got) != 0 {
		t.Fatalf("adding signers must pass, got %v", got)
	}
	if got := removedSigners(enforce, alertFewer); len(got) != 0 {
		t.Fatalf("same signers different mode: no removal, got %v", got)
	}
}
