package profiles

import (
	"strings"
	"testing"

	rulemanagertypesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
)

func TestRulesAdapterGetContent(t *testing.T) {
	rules := &rulemanagertypesv1.Rules{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rules",
			Namespace: "default",
			UID:       k8stypes.UID("test-uid"),
			Labels:    map[string]string{"label": "value"},
		},
		Spec: rulemanagertypesv1.RulesSpec{
			Rules: []rulemanagertypesv1.Rule{
				{
					Enabled:     true,
					ID:          "rule-1",
					Name:        "Test Rule",
					Description: "A test rule",
					Expressions: rulemanagertypesv1.RuleExpressions{
						Message:        "message",
						UniqueID:       "uniqueId",
						RuleExpression: []rulemanagertypesv1.RuleExpression{},
					},
					ProfileDependency: 0,
					Severity:          1,
					SupportPolicy:     false,
					Tags:              []string{"test"},
				},
			},
		},
	}

	adapter := NewRulesAdapter(rules)
	content := adapter.GetContent()

	if content == nil {
		t.Fatal("Expected content not to be nil")
	}

	contentMap, ok := content.(map[string]interface{})
	if !ok {
		t.Fatal("Expected content to be a map")
	}

	if contentMap["apiVersion"] != "kubescape.io/v1" {
		t.Errorf("Expected apiVersion 'kubescape.io/v1', got '%v'", contentMap["apiVersion"])
	}

	if contentMap["kind"] != "Rules" {
		t.Errorf("Expected kind 'Rules', got '%v'", contentMap["kind"])
	}

	metadata, ok := contentMap["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected metadata to be a map")
	}

	if metadata["name"] != "test-rules" {
		t.Errorf("Expected name 'test-rules', got '%v'", metadata["name"])
	}

	if metadata["namespace"] != "default" {
		t.Errorf("Expected namespace 'default', got '%v'", metadata["namespace"])
	}

	if _, ok := contentMap["spec"]; !ok {
		t.Error("Expected spec in content")
	}
}

func TestRulesAdapterSignAndVerify(t *testing.T) {
	rules := &rulemanagertypesv1.Rules{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "kubescape.io/v1",
			Kind:       "Rules",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sign-test-rules",
			Namespace: "default",
			UID:       k8stypes.UID("sign-rules-uid"),
			Labels: map[string]string{
				"test": "rules-signing",
			},
		},
		Spec: rulemanagertypesv1.RulesSpec{
			Rules: []rulemanagertypesv1.Rule{
				{
					Enabled:     true,
					ID:          "test-rule-id",
					Name:        "Test Rule",
					Description: "A test rule",
					Expressions: rulemanagertypesv1.RuleExpressions{
						Message:        "message",
						UniqueID:       "uniqueId",
						RuleExpression: []rulemanagertypesv1.RuleExpression{},
					},
					ProfileDependency: 0,
					Severity:          1,
					SupportPolicy:     false,
					Tags:              []string{"test"},
				},
			},
		},
	}

	adapter := NewRulesAdapter(rules)

	err := signature.SignObjectDisableKeyless(adapter)
	if err != nil {
		t.Fatalf("SignObjectDisableKeyless failed: %v", err)
	}

	if rules.Annotations == nil {
		t.Error("Expected annotations to be set on rules")
	}

	if _, ok := rules.Annotations[signature.AnnotationSignature]; !ok {
		t.Error("Expected signature annotation on rules")
	}

	err = signature.VerifyObjectAllowUntrusted(adapter)
	if err != nil {
		t.Fatalf("VerifyObjectAllowUntrusted failed: %v", err)
	}
}

func TestRulesAdapterSignAndVerifyWithTampering(t *testing.T) {
	rules := &rulemanagertypesv1.Rules{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "kubescape.io/v1",
			Kind:       "Rules",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tamper-test-rules",
			Namespace: "default",
		},
		Spec: rulemanagertypesv1.RulesSpec{
			Rules: []rulemanagertypesv1.Rule{
				{
					Enabled:     true,
					ID:          "tamper-rule-id",
					Name:        "Tamper Test Rule",
					Description: "A tamper test rule",
					Expressions: rulemanagertypesv1.RuleExpressions{
						Message:        "message",
						UniqueID:       "uniqueId",
						RuleExpression: []rulemanagertypesv1.RuleExpression{},
					},
					ProfileDependency: 0,
					Severity:          1,
					SupportPolicy:     false,
					Tags:              []string{"test"},
				},
			},
		},
	}

	adapter := NewRulesAdapter(rules)

	err := signature.SignObjectDisableKeyless(adapter)
	if err != nil {
		t.Fatalf("SignObjectDisableKeyless failed: %v", err)
	}

	rules.Spec.Rules[0].Name = "Modified Rule Name"

	err = signature.VerifyObjectAllowUntrusted(adapter)
	if err == nil {
		t.Fatal("Expected verification to fail after tampering, but it succeeded")
	}

	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("Expected signature verification error, got: %v", err)
	}
}
