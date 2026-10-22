//go:build experimental_signing

package profiles

import (
	rulebindingtypesv1 "github.com/kubescape/node-agent/pkg/rulebindingmanager/types/v1"
)

type RuleBindingAdapter struct {
	binding *rulebindingtypesv1.RuntimeAlertRuleBinding
}

func NewRuleBindingAdapter(binding *rulebindingtypesv1.RuntimeAlertRuleBinding) *RuleBindingAdapter {
	return &RuleBindingAdapter{
		binding: binding,
	}
}

func (r *RuleBindingAdapter) GetAnnotations() map[string]string {
	return r.binding.Annotations
}

func (r *RuleBindingAdapter) SetAnnotations(annotations map[string]string) {
	r.binding.Annotations = annotations
}

func (r *RuleBindingAdapter) GetUID() string {
	return string(r.binding.UID)
}

func (r *RuleBindingAdapter) GetNamespace() string {
	return r.binding.Namespace
}

func (r *RuleBindingAdapter) GetName() string {
	return r.binding.Name
}

func (r *RuleBindingAdapter) GetContent() interface{} {
	apiVersion := r.binding.APIVersion
	if apiVersion == "" {
		apiVersion = "kubescape.io/v1"
	}
	kind := r.binding.Kind
	if kind == "" {
		kind = "RuntimeRuleAlertBinding"
	}
	return map[string]interface{}{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]interface{}{
			"name":   r.binding.Name,
			"labels": r.binding.Labels,
		},
		"spec": r.binding.Spec,
	}
}

func (r *RuleBindingAdapter) GetUpdatedObject() interface{} {
	return r.binding
}
