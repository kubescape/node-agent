//go:build experimental_signing

package bundle

import (
	"reflect"
	"testing"

	rulemanagertypesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func fullSpec() v1beta1.ContainerProfileSpec {
	port := int32(80)
	return v1beta1.ContainerProfileSpec{
		Architectures:        []string{"amd64"},
		Capabilities:         []string{"CAP_NET_ADMIN"},
		Execs:                []v1beta1.ExecCalls{{Path: "/bin/x"}},
		Opens:                []v1beta1.OpenCalls{{Path: "/data/x", Flags: []string{"O_RDONLY"}}},
		Syscalls:             []string{"open"},
		SeccompProfile:       v1beta1.SingleSeccompProfile{Spec: v1beta1.SingleSeccompProfileSpec{BaseProfileName: "base"}},
		Endpoints:            []v1beta1.HTTPEndpoint{{Endpoint: "/api"}},
		ImageID:              "sha256:abc",
		ImageTag:             "v1",
		PolicyByRuleId:       map[string]v1beta1.RulePolicy{"R0001": {}},
		IdentifiedCallStacks: []v1beta1.IdentifiedCallStack{{CallID: "c1"}},
		LabelSelector:        metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
		Ingress:              []v1beta1.NetworkNeighbor{{Identifier: "n", Type: "internal", Ports: []v1beta1.NetworkPort{{Name: "TCP-80", Port: &port, Protocol: "TCP"}}}},
		Egress:               []v1beta1.NetworkNeighbor{{Identifier: "m", Type: "internal"}},
	}
}

// The divergence table and the class-confinement check must cover the same
// field list: a new spec field joining only one of them would either leak past
// confinement or hide from divergence reporting.
func TestSpecPathTableMatchesSetSpecPaths(t *testing.T) {
	spec := fullSpec()
	empty := v1beta1.ContainerProfileSpec{}
	fromDiff := DiffSpecPaths(&spec, &empty)
	fromSet := setSpecPaths(&spec)
	require.ElementsMatch(t, fromSet, fromDiff,
		"setSpecPaths and the divergence table disagree on the spec field list")
}

func TestDiffSpecPaths(t *testing.T) {
	a := fullSpec()
	b := fullSpec()
	require.Empty(t, DiffSpecPaths(&a, &b))

	b.Execs = append(b.Execs, v1beta1.ExecCalls{Path: "/bin/backdoor"})
	b.ImageTag = "v2"
	require.Equal(t, []string{"execs", "imageTag"}, DiffSpecPaths(&a, &b))
}

func embeddedFragment(t *testing.T, name string, spec v1beta1.ContainerProfileSpec) *v1beta1.ContainerProfile {
	t.Helper()
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "redis", Labels: map[string]string{LabelBundle: "redis", LabelFragmentClass: "base"}},
		Spec:       spec,
	}
	require.NoError(t, signature.SignObject(profiles.NewContainerProfileAdapter(cp), signature.WithPrivateKey(genKey(t)), signature.WithEmbedContent(true)))
	return cp
}

func TestFragmentStoredDivergence(t *testing.T) {
	clean := embeddedFragment(t, "frag", cpSpecForPath("execs"))
	paths, _, ok := FragmentStoredDivergence(clean)
	require.True(t, ok)
	require.Empty(t, paths, "an unedited fragment must report no divergence")

	edited := embeddedFragment(t, "frag", cpSpecForPath("execs"))
	edited.Spec.Execs = append(edited.Spec.Execs, v1beta1.ExecCalls{Path: "/bin/backdoor"})
	paths, h1, ok := FragmentStoredDivergence(edited)
	require.True(t, ok)
	require.Equal(t, []string{"execs"}, paths)
	require.NotEmpty(t, h1)

	noEmbed := buildFragment(t, "plain", "redis", "base", cpSpecForPath("execs"), genKey(t), true)
	_, _, ok = FragmentStoredDivergence(noEmbed)
	require.False(t, ok, "nothing to compare without embedded content")
}

// AC #70-1/2: a stored-spec edit changes neither the composite nor the Merkle
// root — the injected content is not enforced — while the divergence reports.
func TestStoredSpecEdit_CompositeAndRootUnchanged(t *testing.T) {
	key := genKey(t)
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "base-frag", Namespace: "redis", Labels: map[string]string{LabelBundle: "redis", LabelFragmentClass: "base"}},
		Spec:       cpSpecForPath("execs"),
	}
	require.NoError(t, signature.SignObject(profiles.NewContainerProfileAdapter(cp), signature.WithPrivateKey(key), signature.WithEmbedContent(true)))
	fp := signerIDOf(t, cp)
	policy := TrustPolicy{Classes: map[FragmentClass]ClassPolicy{
		ClassBase: {Signers: []string{fp}, AllowedSpecPaths: []string{"execs"}},
	}}

	composite1, m1, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{cp}, policy)
	require.NoError(t, err)

	cp.Spec.Execs = append(cp.Spec.Execs, v1beta1.ExecCalls{Path: "/bin/backdoor"})
	composite2, m2, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{cp}, policy)
	require.NoError(t, err, "a stored-spec edit must not affect admission")
	require.Equal(t, m1.Root, m2.Root, "Merkle root must bind the signed content, not the stored spec")
	require.True(t, reflect.DeepEqual(composite1.Spec, composite2.Spec), "the injected stored content must not reach the composite")
	for _, e := range composite2.Spec.Execs {
		require.NotEqual(t, "/bin/backdoor", e.Path)
	}

	paths, _, ok := FragmentStoredDivergence(cp)
	require.True(t, ok)
	require.Equal(t, []string{"execs"}, paths)
}

func TestRulesStoredDivergence(t *testing.T) {
	r := &rulemanagertypesv1.Rules{
		TypeMeta:   metav1.TypeMeta{APIVersion: "kubescape.io/v1", Kind: "Rules"},
		ObjectMeta: metav1.ObjectMeta{Name: "baseline", Namespace: "kubescape", Labels: map[string]string{LabelFragmentClass: "base"}},
		Spec:       rulemanagertypesv1.RulesSpec{Rules: []rulemanagertypesv1.Rule{{Enabled: true, ID: "R0001", Name: "r"}}},
	}
	require.NoError(t, signature.SignObject(profiles.NewRulesAdapter(r), signature.WithPrivateKey(genKey(t)), signature.WithEmbedContent(true)))

	d, _, _, _, ok := RulesStoredDivergence(r)
	require.True(t, ok)
	require.False(t, d)

	r.Spec.Rules = append(r.Spec.Rules, rulemanagertypesv1.Rule{Enabled: true, ID: "R9999", Name: "rogue"})
	d, stored, signed, h, ok := RulesStoredDivergence(r)
	require.True(t, ok)
	require.True(t, d)
	require.Equal(t, 2, stored)
	require.Equal(t, 1, signed)
	require.NotEmpty(t, h)
}
