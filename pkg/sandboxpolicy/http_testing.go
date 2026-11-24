package sandboxpolicy

import (
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// HTTPPolicyForTest describes a policy with an http section for tests of
// other packages. An empty Namespace makes a ClusterSandboxPolicy.
type HTTPPolicyForTest struct {
	UID                        string
	Namespace                  string
	Generation                 int64
	PodLabels, NamespaceLabels map[string]string
	Containers                 []string
	Off, Deny                  bool
}

// HTTPPoliciesForTest builds HTTPPolicy values through the same parser the
// controller uses, so Selects behaves as it does on a listed object.
func HTTPPoliciesForTest(policies ...HTTPPolicyForTest) ([]HTTPPolicy, error) {
	var out []HTTPPolicy
	for _, t := range policies {
		spec := api.PolicySpec{Mode: api.ModeAudit, Containers: t.Containers, HTTP: &api.HTTPSection{
			Default: api.HTTPDefault{LLM: api.HTTPDefaultAudit, MCP: api.HTTPDefaultAudit, Other: api.HTTPDefaultAllow},
		}}
		if t.Off {
			spec.Mode = api.ModeOff
		}
		if t.Deny {
			spec.HTTP.OnUnavailable = api.HTTPUnavailableDeny
		}
		meta := metav1.ObjectMeta{Name: t.UID, Namespace: t.Namespace, UID: types.UID(t.UID), Generation: t.Generation}
		var object any
		if t.Namespace != "" {
			object = &api.SandboxPolicy{TypeMeta: metav1.TypeMeta{APIVersion: api.SchemeGroupVersion.String(), Kind: "SandboxPolicy"}, ObjectMeta: meta,
				Spec: api.SandboxPolicySpec{Selector: api.PodPolicySelector{PodSelector: metav1.LabelSelector{MatchLabels: t.PodLabels}}, PolicySpec: spec}}
		} else {
			object = &api.ClusterSandboxPolicy{TypeMeta: metav1.TypeMeta{APIVersion: api.SchemeGroupVersion.String(), Kind: "ClusterSandboxPolicy"}, ObjectMeta: meta,
				Spec: api.ClusterSandboxPolicySpec{Selector: api.ClusterPolicySelector{PodSelector: metav1.LabelSelector{MatchLabels: t.PodLabels}, NamespaceSelector: &metav1.LabelSelector{MatchLabels: t.NamespaceLabels}}, PolicySpec: spec}}
		}
		raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
		if err != nil {
			return nil, err
		}
		p := parsePolicy(&unstructured.Unstructured{Object: raw})
		if p.err != nil {
			return nil, p.err
		}
		out = append(out, HTTPPolicy{Identity: p.identity, Off: t.Off, Deny: t.Deny, policy: p})
	}
	return out, nil
}
