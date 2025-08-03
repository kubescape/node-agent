package networkneighborhood

import (
	"testing"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/library/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

func TestIntegrationWithAllNetworkFunctions(t *testing.T) {
	objCache := profilevalidator.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}

	objCache.SetSharedContainerData("test-container-id", &objectcache.WatchedContainerData{
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {
				{
					Name: "test-container",
				},
			},
		},
	})

	nn := &v1beta1.NetworkNeighborhood{}
	nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
		Name: "test-container",
		Egress: []v1beta1.NetworkNeighbor{
			{
				IPAddress: "192.168.1.100",
				DNSNames:  []string{"api.example.com", "api2.example.com"},
			},
			{
				IPAddress: "10.0.0.50",
				DNSNames:  []string{"database.internal"},
			},
			{
				IPAddress: "8.8.8.8",
				DNSNames:  []string{"dns.google.com"},
			},
		},
		Ingress: []v1beta1.NetworkNeighbor{
			{
				IPAddress: "172.16.0.10",
				DNSNames:  []string{"loadbalancer.example.com", "lb.example.com"},
			},
			{
				IPAddress: "10.0.0.20",
				DNSNames:  []string{"monitoring.internal"},
			},
		},
	})
	objCache.SetNetworkNeighborhood(nn)

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		NN(&objCache, config.Config{
			CelConfigCache: cache.FunctionCacheConfig{
				MaxSize: 1000,
				TTL:     1 * time.Minute,
			},
		}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	testCases := []struct {
		name           string
		expression     string
		expectedResult bool
	}{
		{
			name:           "Check egress address",
			expression:     `nn.was_address_in_egress(containerID, "192.168.1.100")`,
			expectedResult: true,
		},
		{
			name:           "Check ingress address",
			expression:     `nn.was_address_in_ingress(containerID, "172.16.0.10")`,
			expectedResult: true,
		},
		{
			name:           "Check egress domain",
			expression:     `nn.is_domain_in_egress(containerID, "api.example.com")`,
			expectedResult: true,
		},
		{
			name:           "Check ingress domain",
			expression:     `nn.is_domain_in_ingress(containerID, "loadbalancer.example.com")`,
			expectedResult: true,
		},
		{
			name:           "Complex network check - external communication",
			expression:     `nn.was_address_in_egress(containerID, "8.8.8.8") && nn.is_domain_in_egress(containerID, "dns.google.com")`,
			expectedResult: true,
		},
		{
			name:           "Complex network check - internal communication",
			expression:     `nn.was_address_in_egress(containerID, "10.0.0.50") && nn.is_domain_in_egress(containerID, "database.internal")`,
			expectedResult: true,
		},
		{
			name:           "Complex network check - load balancer access",
			expression:     `nn.was_address_in_ingress(containerID, "172.16.0.10") && nn.is_domain_in_ingress(containerID, "lb.example.com")`,
			expectedResult: true,
		},
		{
			name:           "Check non-existent network communication",
			expression:     `nn.was_address_in_egress(containerID, "192.168.1.200") || nn.is_domain_in_ingress(containerID, "nonexistent.example.com")`,
			expectedResult: false,
		},
		{
			name:           "Mixed valid and invalid checks",
			expression:     `nn.was_address_in_egress(containerID, "192.168.1.100") && nn.was_address_in_egress(containerID, "192.168.1.200")`,
			expectedResult: false,
		},
		{
			name:           "Multiple valid egress checks",
			expression:     `nn.was_address_in_egress(containerID, "192.168.1.100") || nn.was_address_in_egress(containerID, "10.0.0.50")`,
			expectedResult: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ast, issues := env.Compile(tc.expression)
			if issues != nil {
				t.Fatalf("failed to compile expression: %v", issues.Err())
			}

			program, err := env.Program(ast)
			if err != nil {
				t.Fatalf("failed to create program: %v", err)
			}

			result, _, err := program.Eval(map[string]interface{}{
				"containerID": "test-container-id",
			})
			if err != nil {
				t.Fatalf("failed to eval program: %v", err)
			}

			actualResult := result.Value().(bool)
			assert.Equal(t, tc.expectedResult, actualResult, "Expression result should match expected value for: %s", tc.expression)
		})
	}
}
