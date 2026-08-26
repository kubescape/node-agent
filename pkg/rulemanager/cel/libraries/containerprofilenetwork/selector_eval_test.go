package containerprofilenetwork

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

func buildSelectorLib(t *testing.T) *containerProfileNetworkLibrary {
	t.Helper()
	return buildLibWithContainer(t,
		[]v1beta1.NetworkNeighbor{
			{Identifier: "redis-clients", PodSelector: podSel(map[string]string{"app": "redis-client"})},
			{Identifier: "metrics", PodSelector: podSel(map[string]string{"app": "metrics"}), NamespaceSelector: nsSel("monitoring")},
			{Identifier: "plain-ip", IPAddresses: []string{"10.0.0.5"}},
		},
		[]v1beta1.NetworkNeighbor{
			{Identifier: "lb", PodSelector: podSel(map[string]string{"app": "ingress-client"})},
		})
}

func labelsVal(m map[string]string) ref.Val {
	return types.DefaultTypeAdapter.NativeToValue(m)
}

func TestWasSelectorIn_EvalTruthTable(t *testing.T) {
	lib := buildSelectorLib(t)
	cases := []struct {
		name    string
		ingress bool
		cid     string
		ns      string
		labels  map[string]string
		want    bool
		why     string
	}{
		{"egress label match, nil nsSel", false, "cid", "redis", map[string]string{"app": "redis-client"}, true, "labels match; nil namespaceSelector not consulted"},
		{"egress label match, foreign ns", false, "cid", "attacker", map[string]string{"app": "redis-client"}, true, "nil namespaceSelector does not scope by namespace"},
		{"egress label mismatch", false, "cid", "redis", map[string]string{"app": "other"}, false, "unknown peer identity must alert"},
		{"egress peer only in ingress list", false, "cid", "redis", map[string]string{"app": "ingress-client"}, false, "direction isolation: ingress-only selector must not open egress"},
		{"ingress peer matches", true, "cid", "redis", map[string]string{"app": "ingress-client"}, true, "declared ingress selector matches"},
		{"ingress peer only in egress list", true, "cid", "redis", map[string]string{"app": "redis-client"}, false, "direction isolation: egress-only selector must not open ingress"},
		{"ns-scoped peer, right ns", false, "cid", "monitoring", map[string]string{"app": "metrics"}, true, "explicit namespaceSelector matches metadata.name"},
		{"ns-scoped peer, wrong ns", false, "cid", "prod", map[string]string{"app": "metrics"}, false, "explicit namespaceSelector rejects other namespaces"},
		{"empty namespace fails closed", false, "cid", "", map[string]string{"app": "redis-client"}, false, "an unresolved peer (no ns) never satisfies a selector"},
		{"nil labels fail closed", false, "cid", "redis", nil, false, "a peer with no labels matches no non-empty selector"},
		{"empty labels fail closed", false, "cid", "redis", map[string]string{}, false, "empty label set matches no non-empty selector"},
		{"profile unavailable", false, "missing-cid", "redis", map[string]string{"app": "redis-client"}, false, "no profile means no allowlist entry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var res ref.Val
			if tc.ingress {
				res = lib.wasSelectorInIngress(types.String(tc.cid), types.String(tc.ns), labelsVal(tc.labels), types.Int(443), types.String("TCP"))
			} else {
				res = lib.wasSelectorInEgress(types.String(tc.cid), types.String(tc.ns), labelsVal(tc.labels), types.Int(443), types.String("TCP"))
			}
			res = cache.ConvertProfileNotAvailableErrToBool(res, false)
			assert.Equal(t, types.Bool(tc.want), res, tc.why)
		})
	}
}

func TestWasSelectorIn_NoPeersFailsClosed(t *testing.T) {
	lib := buildLibWithContainer(t, []v1beta1.NetworkNeighbor{
		{Identifier: "plain-ip", IPAddresses: []string{"10.0.0.5"}},
	}, nil)
	res := lib.wasSelectorInEgress(types.String("cid"), types.String("redis"), labelsVal(map[string]string{"app": "redis-client"}), types.Int(443), types.String("TCP"))
	res = cache.ConvertProfileNotAvailableErrToBool(res, false)
	assert.Equal(t, types.Bool(false), res, "a profile with no selector peers must match no peer identity")
	res = lib.wasSelectorInIngress(types.String("cid"), types.String("redis"), labelsVal(map[string]string{"app": "redis-client"}), types.Int(443), types.String("TCP"))
	res = cache.ConvertProfileNotAvailableErrToBool(res, false)
	assert.Equal(t, types.Bool(false), res)
}

func TestWasSelectorIn_ErrorEdges(t *testing.T) {
	nilLib := &containerProfileNetworkLibrary{objectCache: nil}
	assert.True(t, types.IsError(nilLib.wasSelectorInEgress(types.String("cid"), types.String("ns"), labelsVal(nil), types.Int(443), types.String("TCP"))))
	assert.True(t, types.IsError(nilLib.wasSelectorInIngress(types.String("cid"), types.String("ns"), labelsVal(nil), types.Int(443), types.String("TCP"))))

	lib := buildSelectorLib(t)
	assert.True(t, types.IsError(lib.wasSelectorInEgress(types.Int(1), types.String("ns"), labelsVal(nil), types.Int(443), types.String("TCP"))))
	assert.True(t, types.IsError(lib.wasSelectorInEgress(types.String("cid"), types.Int(1), labelsVal(nil), types.Int(443), types.String("TCP"))))
}

func TestRefValToStringMap(t *testing.T) {
	assert.Nil(t, refValToStringMap(nil))
	assert.Nil(t, refValToStringMap(types.String("not-a-map")))
	assert.Equal(t, map[string]string{"a": "b"}, refValToStringMap(labelsVal(map[string]string{"a": "b"})))
}

func TestWasSelectorIn_CELEndToEnd(t *testing.T) {
	lib := buildSelectorLib(t)
	env, err := cel.NewEnv(cel.Variable("containerID", cel.StringType), cel.Lib(lib))
	assert.NoError(t, err)

	cases := []struct {
		expr string
		want bool
		why  string
	}{
		{`cp.was_selector_in_egress(containerID, "redis", {"app": "redis-client"}, 443, "TCP")`, true, "declared egress peer matches through the CEL binding"},
		{`cp.was_selector_in_egress(containerID, "", {"app": "redis-client"}, 443, "TCP")`, false, "empty peer namespace fails closed through the binding"},
		{`cp.was_selector_in_egress(containerID, "redis", {}, 443, "TCP")`, false, "empty label map fails closed"},
		{`cp.was_selector_in_ingress(containerID, "redis", {"app": "ingress-client"}, 443, "TCP")`, true, "declared ingress peer matches"},
		{`cp.was_selector_in_ingress(containerID, "redis", {"app": "redis-client"}, 443, "TCP")`, false, "egress-only selector must not open ingress"},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			ast, issues := env.Compile(tc.expr)
			assert.NoError(t, issues.Err())
			prg, err := env.Program(ast)
			assert.NoError(t, err)
			out, _, err := prg.Eval(map[string]interface{}{"containerID": "cid"})
			assert.NoError(t, err)
			assert.Equal(t, tc.want, out.Value(), tc.why)
		})
	}

	ast, issues := env.Compile(`cp.was_selector_in_egress(containerID, "redis", {"app": "redis-client"}, 443, "TCP")`)
	assert.NoError(t, issues.Err())
	prg, err := env.Program(ast)
	assert.NoError(t, err)
	out, _, err := prg.Eval(map[string]interface{}{"containerID": "unknown-cid"})
	assert.NoError(t, err)
	assert.Equal(t, false, out.Value(), "profile-unavailable converts to false at the binding, never an error")
}
