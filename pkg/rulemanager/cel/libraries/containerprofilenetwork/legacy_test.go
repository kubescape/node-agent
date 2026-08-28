package containerprofilenetwork

import (
	"sort"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// TestLegacyNNDeclarationsMirrorCP is a drift guard: NN() must expose
// exactly the cp.* function set under the nn. prefix, one-for-one, with no
// functions gained or lost, and every nn.* overload id must be unique from
// its cp.* counterpart (cel-go requires overload ids to be unique per
// environment).
func TestLegacyNNDeclarationsMirrorCP(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{}
	base := New(&objCache, config.Config{}).(*containerProfileNetworkLibrary)
	alias := &legacyContainerProfileNetworkLibrary{base: base, name: "nn", prefix: "nn."}

	wantNames := make([]string, 0)
	for name := range base.Declarations() {
		wantNames = append(wantNames, "nn."+strings.TrimPrefix(name, "cp."))
	}
	gotNames := make([]string, 0)
	for name := range alias.Declarations() {
		gotNames = append(gotNames, name)
	}
	sort.Strings(wantNames)
	sort.Strings(gotNames)
	assert.Equal(t, wantNames, gotNames, "nn.* alias set must exactly mirror cp.*'s declared functions")
	assert.Equal(t, "nn", alias.LibraryName())

	// Registering both namespaces in one env must not collide.
	_, err := cel.NewEnv(CPNetwork(&objCache, config.Config{}), NN(&objCache, config.Config{}))
	assert.NoError(t, err, "cp.* and nn.* must register into the same env without overload id collisions")
}

// TestLegacyNNMatchesCP proves that every nn.* alias evaluates identically
// to its cp.* equivalent against the same ContainerProfile egress/ingress
// data — and that cp.* itself is unaffected by NN() also being registered
// (regression guard for #864's cp.* namespace). Covers all 6 nn.* helpers.
func TestLegacyNNMatchesCP(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}
	objCache.SetSharedContainerData("test-container-id", &objectcache.WatchedContainerData{
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {{Name: "test-container"}},
		},
	})

	profile := &v1beta1.ContainerProfile{}
	profile.Namespace = "redis"
	profile.Spec = v1beta1.ContainerProfileSpec{
		Egress: []v1beta1.NetworkNeighbor{
			{
				IPAddress: "192.168.1.100",
				DNSNames:  []string{"api.example.com"},
				Ports: []v1beta1.NetworkPort{
					{Name: "tcp-80", Protocol: "TCP", Port: ptr.To(int32(80))},
				},
			},
			{
				Identifier:  "redis-clients",
				PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "redis-client"}},
			},
		},
		Ingress: []v1beta1.NetworkNeighbor{
			{
				IPAddress: "172.16.0.10",
				DNSNames:  []string{"loadbalancer.example.com"},
				Ports: []v1beta1.NetworkPort{
					{Name: "tcp-8080", Protocol: "TCP", Port: ptr.To(int32(8080))},
				},
			},
			{
				Identifier:  "lb-clients",
				PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "lb-client"}},
			},
		},
	}
	objCache.SetContainerProfile(profile)

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		CPNetwork(&objCache, config.Config{}),
		NN(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	testCases := []struct {
		name string
		cp   string
		nn   string
		want bool
	}{
		{
			name: "was_address_in_egress",
			cp:   `cp.was_address_in_egress(containerID, "192.168.1.100")`,
			nn:   `nn.was_address_in_egress(containerID, "192.168.1.100")`,
			want: true,
		},
		{
			name: "was_address_in_egress (miss)",
			cp:   `cp.was_address_in_egress(containerID, "10.0.0.1")`,
			nn:   `nn.was_address_in_egress(containerID, "10.0.0.1")`,
			want: false,
		},
		{
			name: "was_address_in_ingress",
			cp:   `cp.was_address_in_ingress(containerID, "172.16.0.10")`,
			nn:   `nn.was_address_in_ingress(containerID, "172.16.0.10")`,
			want: true,
		},
		{
			name: "is_domain_in_egress",
			cp:   `cp.is_domain_in_egress(containerID, "api.example.com")`,
			nn:   `nn.is_domain_in_egress(containerID, "api.example.com")`,
			want: true,
		},
		{
			name: "is_domain_in_ingress",
			cp:   `cp.is_domain_in_ingress(containerID, "loadbalancer.example.com")`,
			nn:   `nn.is_domain_in_ingress(containerID, "loadbalancer.example.com")`,
			want: true,
		},
		{
			name: "was_address_port_protocol_in_egress",
			cp:   `cp.was_address_port_protocol_in_egress(containerID, "192.168.1.100", 80, "TCP")`,
			nn:   `nn.was_address_port_protocol_in_egress(containerID, "192.168.1.100", 80, "TCP")`,
			want: true,
		},
		{
			name: "was_address_port_protocol_in_ingress",
			cp:   `cp.was_address_port_protocol_in_ingress(containerID, "172.16.0.10", 8080, "TCP")`,
			nn:   `nn.was_address_port_protocol_in_ingress(containerID, "172.16.0.10", 8080, "TCP")`,
			want: true,
		},
		{
			name: "was_selector_in_egress",
			cp:   `cp.was_selector_in_egress(containerID, "redis", {"app": "redis-client"}, 443, "TCP")`,
			nn:   `nn.was_selector_in_egress(containerID, "redis", {"app": "redis-client"}, 443, "TCP")`,
			want: true,
		},
		{
			name: "was_selector_in_ingress",
			cp:   `cp.was_selector_in_ingress(containerID, "redis", {"app": "lb-client"}, 443, "TCP")`,
			nn:   `nn.was_selector_in_ingress(containerID, "redis", {"app": "lb-client"}, 443, "TCP")`,
			want: true,
		},
		{
			name: "was_selector_in_egress (miss)",
			cp:   `cp.was_selector_in_egress(containerID, "redis", {"app": "unknown"}, 443, "TCP")`,
			nn:   `nn.was_selector_in_egress(containerID, "redis", {"app": "unknown"}, 443, "TCP")`,
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cpResult := evalBool(t, env, tc.cp, map[string]interface{}{"containerID": "test-container-id"})
			nnResult := evalBool(t, env, tc.nn, map[string]interface{}{"containerID": "test-container-id"})
			assert.Equal(t, tc.want, cpResult, "cp.* result for %s", tc.name)
			assert.Equal(t, cpResult, nnResult, "nn.* must match cp.* for %s", tc.name)
		})
	}
}

// evalBool compiles and evaluates a CEL boolean expression against env,
// failing the test on any compile/program/eval error.
func evalBool(t *testing.T, env *cel.Env, expr string, activation map[string]interface{}) bool {
	t.Helper()
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("failed to compile %q: %v", expr, issues.Err())
	}
	program, err := env.Program(ast)
	if err != nil {
		t.Fatalf("failed to create program for %q: %v", expr, err)
	}
	out, _, err := program.Eval(activation)
	if err != nil {
		t.Fatalf("failed to eval %q: %v", expr, err)
	}
	result, ok := out.Value().(bool)
	if !ok {
		t.Fatalf("expr %q returned %T, expected bool", expr, out.Value())
	}
	return result
}
