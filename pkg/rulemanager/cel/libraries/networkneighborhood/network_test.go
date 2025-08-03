package networkneighborhood

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"k8s.io/utils/ptr"
)

func TestWasAddressPortProtocolInEgress(t *testing.T) {
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
				Ports: []v1beta1.NetworkPort{
					{
						Name:     "tcp-80",
						Protocol: v1beta1.Protocol("TCP"),
						Port:     ptr.To(int32(80)),
					},
					{
						Name:     "tcp-443",
						Protocol: v1beta1.Protocol("TCP"),
						Port:     ptr.To(int32(443)),
					},
				},
			},
			{
				IPAddress: "8.8.8.8",
				Ports: []v1beta1.NetworkPort{
					{
						Name:     "udp-53",
						Protocol: v1beta1.Protocol("UDP"),
						Port:     ptr.To(int32(53)),
					},
				},
			},
		},
	})
	objCache.SetNetworkNeighborhood(nn)

	lib := &nnLibrary{
		objectCache:   &objCache,
		functionCache: cache.NewFunctionCache(cache.DefaultFunctionCacheConfig()),
	}

	testCases := []struct {
		name           string
		containerID    string
		address        string
		port           int64
		protocol       string
		expectedResult bool
	}{
		{
			name:           "Valid TCP port 80",
			containerID:    "test-container-id",
			address:        "192.168.1.100",
			port:           80,
			protocol:       "TCP",
			expectedResult: true,
		},
		{
			name:           "Valid TCP port 443",
			containerID:    "test-container-id",
			address:        "192.168.1.100",
			port:           443,
			protocol:       "TCP",
			expectedResult: true,
		},
		{
			name:           "Valid UDP port 53",
			containerID:    "test-container-id",
			address:        "8.8.8.8",
			port:           53,
			protocol:       "UDP",
			expectedResult: true,
		},
		{
			name:           "Invalid port",
			containerID:    "test-container-id",
			address:        "192.168.1.100",
			port:           9999,
			protocol:       "TCP",
			expectedResult: false,
		},
		{
			name:           "Invalid protocol",
			containerID:    "test-container-id",
			address:        "192.168.1.100",
			port:           80,
			protocol:       "UDP",
			expectedResult: false,
		},
		{
			name:           "Invalid address",
			containerID:    "test-container-id",
			address:        "192.168.1.200",
			port:           80,
			protocol:       "TCP",
			expectedResult: false,
		},
		{
			name:           "Invalid container ID",
			containerID:    "invalid-container-id",
			address:        "192.168.1.100",
			port:           80,
			protocol:       "TCP",
			expectedResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := lib.wasAddressPortProtocolInEgress(
				types.String(tc.containerID),
				types.String(tc.address),
				types.Int(tc.port),
				types.String(tc.protocol),
			)
			assert.Equal(t, types.Bool(tc.expectedResult), result)
		})
	}
}

func TestWasAddressPortProtocolInIngress(t *testing.T) {
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
		Ingress: []v1beta1.NetworkNeighbor{
			{
				IPAddress: "172.16.0.10",
				Ports: []v1beta1.NetworkPort{
					{
						Name:     "tcp-8080",
						Protocol: v1beta1.Protocol("TCP"),
						Port:     ptr.To(int32(8080)),
					},
					{
						Name:     "tcp-9090",
						Protocol: v1beta1.Protocol("TCP"),
						Port:     ptr.To(int32(9090)),
					},
				},
			},
			{
				IPAddress: "10.0.0.20",
				Ports: []v1beta1.NetworkPort{
					{
						Name:     "tcp-3000",
						Protocol: v1beta1.Protocol("TCP"),
						Port:     ptr.To(int32(3000)),
					},
				},
			},
		},
	})
	objCache.SetNetworkNeighborhood(nn)

	lib := &nnLibrary{
		objectCache:   &objCache,
		functionCache: cache.NewFunctionCache(cache.DefaultFunctionCacheConfig()),
	}

	testCases := []struct {
		name           string
		containerID    string
		address        string
		port           int64
		protocol       string
		expectedResult bool
	}{
		{
			name:           "Valid TCP port 8080",
			containerID:    "test-container-id",
			address:        "172.16.0.10",
			port:           8080,
			protocol:       "TCP",
			expectedResult: true,
		},
		{
			name:           "Valid TCP port 9090",
			containerID:    "test-container-id",
			address:        "172.16.0.10",
			port:           9090,
			protocol:       "TCP",
			expectedResult: true,
		},
		{
			name:           "Valid TCP port 3000",
			containerID:    "test-container-id",
			address:        "10.0.0.20",
			port:           3000,
			protocol:       "TCP",
			expectedResult: true,
		},
		{
			name:           "Invalid port",
			containerID:    "test-container-id",
			address:        "172.16.0.10",
			port:           9999,
			protocol:       "TCP",
			expectedResult: false,
		},
		{
			name:           "Invalid protocol",
			containerID:    "test-container-id",
			address:        "172.16.0.10",
			port:           8080,
			protocol:       "UDP",
			expectedResult: false,
		},
		{
			name:           "Invalid address",
			containerID:    "test-container-id",
			address:        "172.16.0.20",
			port:           8080,
			protocol:       "TCP",
			expectedResult: false,
		},
		{
			name:           "Invalid container ID",
			containerID:    "invalid-container-id",
			address:        "172.16.0.10",
			port:           8080,
			protocol:       "TCP",
			expectedResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := lib.wasAddressPortProtocolInIngress(
				types.String(tc.containerID),
				types.String(tc.address),
				types.Int(tc.port),
				types.String(tc.protocol),
			)
			assert.Equal(t, types.Bool(tc.expectedResult), result)
		})
	}
}

func TestWasAddressPortProtocolWithNilObjectCache(t *testing.T) {
	lib := &nnLibrary{
		objectCache:   nil,
		functionCache: cache.NewFunctionCache(cache.DefaultFunctionCacheConfig()),
	}

	result := lib.wasAddressPortProtocolInEgress(
		types.String("test-container-id"),
		types.String("192.168.1.100"),
		types.Int(80),
		types.String("TCP"),
	)
	assert.True(t, types.IsError(result))

	result = lib.wasAddressPortProtocolInIngress(
		types.String("test-container-id"),
		types.String("172.16.0.10"),
		types.Int(8080),
		types.String("TCP"),
	)
	assert.True(t, types.IsError(result))
}

func TestWasAddressPortProtocolWithInvalidTypes(t *testing.T) {
	objCache := profilevalidator.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}

	lib := &nnLibrary{
		objectCache:   &objCache,
		functionCache: cache.NewFunctionCache(cache.DefaultFunctionCacheConfig()),
	}

	// Test with invalid containerID type
	result := lib.wasAddressPortProtocolInEgress(
		types.Int(123), // Should be string
		types.String("192.168.1.100"),
		types.Int(80),
		types.String("TCP"),
	)
	assert.True(t, types.IsError(result))

	// Test with invalid address type
	result = lib.wasAddressPortProtocolInEgress(
		types.String("test-container-id"),
		types.Int(123), // Should be string
		types.Int(80),
		types.String("TCP"),
	)
	assert.True(t, types.IsError(result))

	// Test with invalid port type
	result = lib.wasAddressPortProtocolInEgress(
		types.String("test-container-id"),
		types.String("192.168.1.100"),
		types.String("80"), // Should be int
		types.String("TCP"),
	)
	assert.True(t, types.IsError(result))

	// Test with invalid protocol type
	result = lib.wasAddressPortProtocolInEgress(
		types.String("test-container-id"),
		types.String("192.168.1.100"),
		types.Int(80),
		types.Int(123), // Should be string
	)
	assert.True(t, types.IsError(result))
}

func TestWasAddressPortProtocolWithNilPort(t *testing.T) {
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
				Ports: []v1beta1.NetworkPort{
					{
						Name:     "tcp-80",
						Protocol: v1beta1.Protocol("TCP"),
						Port:     nil, // Nil port
					},
				},
			},
		},
		Ingress: []v1beta1.NetworkNeighbor{
			{
				IPAddress: "172.16.0.10",
				Ports: []v1beta1.NetworkPort{
					{
						Name:     "tcp-8080",
						Protocol: v1beta1.Protocol("TCP"),
						Port:     nil, // Nil port
					},
				},
			},
		},
	})
	objCache.SetNetworkNeighborhood(nn)

	lib := &nnLibrary{
		objectCache:   &objCache,
		functionCache: cache.NewFunctionCache(cache.DefaultFunctionCacheConfig()),
	}

	// Test egress with nil port
	result := lib.wasAddressPortProtocolInEgress(
		types.String("test-container-id"),
		types.String("192.168.1.100"),
		types.Int(80),
		types.String("TCP"),
	)
	assert.Equal(t, types.Bool(false), result)

	// Test ingress with nil port
	result = lib.wasAddressPortProtocolInIngress(
		types.String("test-container-id"),
		types.String("172.16.0.10"),
		types.Int(8080),
		types.String("TCP"),
	)
	assert.Equal(t, types.Bool(false), result)
}
