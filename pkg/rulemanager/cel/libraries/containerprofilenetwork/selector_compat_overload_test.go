package containerprofilenetwork

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The selector verbs gained (port, protocol) during review. A rule body written
// against the earlier 3-argument shape must keep COMPILING — a compile failure
// disables the whole rule expression silently — and must keep its selector
// allowlisting with port-agnostic semantics. Both overloads coexist; the
// 5-argument one stays port-aware.
func TestWasSelectorIn_ThreeArgCompatOverload(t *testing.T) {
	https := int32(443)
	lib := buildLibWithContainer(t,
		[]v1beta1.NetworkNeighbor{
			{Identifier: "api", PodSelector: podSel(map[string]string{"app": "api"}),
				Ports: []v1beta1.NetworkPort{{Name: "https", Protocol: v1beta1.ProtocolTCP, Port: &https}}},
		},
		[]v1beta1.NetworkNeighbor{
			{Identifier: "lb", PodSelector: podSel(map[string]string{"app": "lb"}),
				Ports: []v1beta1.NetworkPort{{Name: "https", Protocol: v1beta1.ProtocolTCP, Port: &https}}},
		})
	env, err := cel.NewEnv(cel.Variable("containerID", cel.StringType), cel.Lib(lib))
	require.NoError(t, err)

	cases := []struct {
		expr string
		want bool
		why  string
	}{
		// 3-arg: selector + namespace only, ports ignored.
		{`cp.was_selector_in_egress(containerID, "redis", {"app": "api"})`, true, "3-arg compat overload compiles and matches the declared peer regardless of port"},
		{`cp.was_selector_in_egress(containerID, "", {"app": "api"})`, false, "3-arg: empty peer namespace (external IP) fails closed"},
		{`cp.was_selector_in_egress(containerID, "redis", {})`, false, "3-arg: empty label map fails closed"},
		{`cp.was_selector_in_egress(containerID, "redis", {"app": "other"})`, false, "3-arg: undeclared peer alerts"},
		{`cp.was_selector_in_ingress(containerID, "redis", {"app": "lb"})`, true, "3-arg ingress twin matches"},
		{`cp.was_selector_in_ingress(containerID, "redis", {"app": "api"})`, false, "3-arg: egress-only selector must not open ingress"},
		// 5-arg: port-aware semantics are unchanged by adding the compat overload.
		{`cp.was_selector_in_egress(containerID, "redis", {"app": "api"}, 443, "TCP")`, true, "5-arg on the listed port matches"},
		{`cp.was_selector_in_egress(containerID, "redis", {"app": "api"}, 9999, "TCP")`, false, "5-arg on an unlisted port alerts (port-aware)"},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			ast, issues := env.Compile(tc.expr)
			require.NoError(t, issues.Err(), "must compile: %s", tc.why)
			prg, err := env.Program(ast)
			require.NoError(t, err)
			out, _, err := prg.Eval(map[string]interface{}{"containerID": "cid"})
			require.NoError(t, err)
			assert.Equal(t, tc.want, out.Value(), tc.why)
		})
	}

	// The exact rule body that was silently disabled in the field: it must compile.
	body := `cp.was_selector_in_egress(containerID, "redis", {"app": "api"}) || cp.was_selector_in_ingress(containerID, "redis", {"app": "lb"})`
	_, issues := env.Compile(body)
	require.NoError(t, issues.Err(), "a pre-port-aware rule body must not fail to compile")

	// Unknown container: profile-unavailable converts to false at the binding, never an error.
	ast, issues := env.Compile(`cp.was_selector_in_egress(containerID, "redis", {"app": "api"})`)
	require.NoError(t, issues.Err())
	prg, err := env.Program(ast)
	require.NoError(t, err)
	out, _, err := prg.Eval(map[string]interface{}{"containerID": "unknown-cid"})
	require.NoError(t, err)
	assert.Equal(t, false, out.Value())
}
