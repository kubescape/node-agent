package profiles

import (
	rulemanagertypesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

type RulesAdapter struct {
	rules *rulemanagertypesv1.Rules
}

func NewRulesAdapter(rules *rulemanagertypesv1.Rules) *RulesAdapter {
	return &RulesAdapter{
		rules: rules,
	}
}

func (r *RulesAdapter) GetAnnotations() map[string]string {
	return r.rules.Annotations
}

func (r *RulesAdapter) SetAnnotations(annotations map[string]string) {
	r.rules.Annotations = annotations
}

func (r *RulesAdapter) GetUID() string {
	return string(r.rules.UID)
}

func (r *RulesAdapter) GetNamespace() string {
	return r.rules.Namespace
}

func (r *RulesAdapter) GetName() string {
	return r.rules.Name
}

func (r *RulesAdapter) GetContent() interface{} {
	apiVersion := r.rules.APIVersion
	if apiVersion == "" {
		apiVersion = "kubescape.io/v1"
	}
	kind := r.rules.Kind
	if kind == "" {
		kind = "Rules"
	}
	return map[string]interface{}{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]interface{}{
			"name":      r.rules.Name,
			"namespace": r.rules.Namespace,
			"labels":    r.rules.Labels,
		},
		"spec": r.rules.Spec,
	}
}

func (r *RulesAdapter) GetUpdatedObject() interface{} {
	return r.rules
}
