//go:build experimental_signing

package ruleswatcher

import (
	"context"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
)

func TestPolicyReloadCannotBeOverwrittenByInFlightAdmission(t *testing.T) {
	fragment := sign(t, rulesObj("baseline", "kubescape", "", string(bundle.RuleClassBase), "R0001"), testKey(t))
	creator := rulecreator.NewRuleCreator()
	w := NewRulesWatcher(newFakeK8sClient(t, fragment), creator, nil)
	w.SetTrustPolicy(&bundle.TrustPolicy{RuleClasses: map[bundle.RuleClass]bundle.RuleClassPolicy{
		bundle.RuleClassBase: {Signers: []string{signerOf(t, fragment)}, AllowedRuleIDs: []string{"*"}},
	}})

	w.ResyncNow(context.Background())
	if got := creator.CreateAllRules(); len(got) != 1 {
		t.Fatalf("initial policy did not load the signed rule: %v", got)
	}

	// Stop the old sync after it has admitted a fragment with the old signer.
	admitted, resume := make(chan struct{}), make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(resume) })
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(fragment)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, _, err := w.admitAndSyncRules(context.Background(), []unstructured.Unstructured{{Object: raw}}, func(*typesv1.Rules) {
			close(admitted)
			<-resume
		})
		done <- err
	}()
	select {
	case <-admitted:
	case <-time.After(5 * time.Second):
		t.Fatal("old sync did not reach admission")
	}

	// Complete a reload while the old admission is paused. The replacement
	// signer rejects the old fragment and removes its rules.
	w.SetTrustPolicy(&bundle.TrustPolicy{RuleClasses: map[bundle.RuleClass]bundle.RuleClassPolicy{
		bundle.RuleClassBase: {Signers: []string{"replacement-signer"}, AllowedRuleIDs: []string{"*"}},
	}})
	w.ResyncNow(context.Background())
	if got := creator.CreateAllRules(); len(got) != 0 {
		t.Fatalf("reload retained rejected rules: %v", got)
	}

	release.Do(func() { close(resume) })
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("old sync did not finish after reload")
	}
	if got := creator.CreateAllRules(); len(got) != 0 {
		t.Fatalf("old admission restored revoked rules after reload: %v", got)
	}
}
