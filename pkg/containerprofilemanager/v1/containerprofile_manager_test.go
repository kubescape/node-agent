package containerprofilemanager

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkEventPodLabels(t *testing.T) {
	tests := []struct {
		name           string
		inputLabels    map[string]string
		expectedLabels map[string]string
		expectedString string
	}{
		{
			name: "single label",
			inputLabels: map[string]string{
				"app": "nginx",
			},
			expectedLabels: map[string]string{
				"app": "nginx",
			},
			expectedString: "app=nginx",
		},
		{
			name: "multiple labels sorted",
			inputLabels: map[string]string{
				"version": "1.0",
				"app":     "nginx",
				"env":     "prod",
			},
			expectedLabels: map[string]string{
				"version": "1.0",
				"app":     "nginx",
				"env":     "prod",
			},
			expectedString: "app=nginx,env=prod,version=1.0",
		},
		{
			name:           "empty labels",
			inputLabels:    map[string]string{},
			expectedLabels: map[string]string{},
			expectedString: "",
		},
		{
			name:           "nil labels",
			inputLabels:    nil,
			expectedLabels: map[string]string{},
			expectedString: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ne := &NetworkEvent{}

			// Test SetPodLabels
			ne.SetPodLabels(tt.inputLabels)
			assert.Equal(t, tt.expectedString, ne.PodLabels)

			// Test SetDestinationPodLabels
			ne.SetDestinationPodLabels(tt.inputLabels)
			assert.Equal(t, tt.expectedString, ne.Destination.PodLabels)

			// Test GetDestinationPodLabels
			result := ne.GetDestinationPodLabels()
			assert.Equal(t, tt.expectedLabels, result)
		})
	}
}

func TestNetworkEventString(t *testing.T) {
	ne := NetworkEvent{
		Port:      8080,
		PktType:   "HOST",
		Protocol:  "TCP",
		PodLabels: "app=nginx",
		Destination: Destination{
			Namespace: "default",
			Name:      "nginx-pod",
			Kind:      EndpointKindPod,
			IPAddress: "10.0.0.1",
		},
	}

	expected := "Port: 8080, PktType: HOST, Protocol: TCP, PodLabels: app=nginx, Destination: {default nginx-pod pod  10.0.0.1}"
	assert.Equal(t, expected, ne.String())
}

func TestGeneratePortIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		port     int32
		expected string
	}{
		{
			name:     "TCP port",
			protocol: "TCP",
			port:     8080,
			expected: "TCP-8080",
		},
		{
			name:     "UDP port",
			protocol: "UDP",
			port:     53,
			expected: "UDP-53",
		},
		{
			name:     "HTTP port",
			protocol: "HTTP",
			port:     80,
			expected: "HTTP-80",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GeneratePortIdentifier(tt.protocol, tt.port)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFilterLabels(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]string
		expected map[string]string
	}{
		{
			name: "filter default labels",
			input: map[string]string{
				"app":                      "nginx",
				"controller-revision-hash": "abc123",
				"pod-template-generation":  "1",
				"pod-template-hash":        "def456",
				"version":                  "1.0",
			},
			expected: map[string]string{
				"app":     "nginx",
				"version": "1.0",
			},
		},
		{
			name: "no labels to filter",
			input: map[string]string{
				"app":     "nginx",
				"version": "1.0",
			},
			expected: map[string]string{
				"app":     "nginx",
				"version": "1.0",
			},
		},
		{
			name:     "empty input",
			input:    map[string]string{},
			expected: map[string]string{},
		},
		{
			name: "only default labels",
			input: map[string]string{
				"controller-revision-hash": "abc123",
				"pod-template-generation":  "1",
				"pod-template-hash":        "def456",
			},
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterLabels(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCreateUUID(t *testing.T) {
	uuid1 := createUUID()
	uuid2 := createUUID()

	// UUIDs should be different
	assert.NotEqual(t, uuid1, uuid2)

	// UUIDs should be valid format (36 characters with hyphens)
	assert.Len(t, uuid1, 36)
	assert.Len(t, uuid2, 36)
	assert.Contains(t, uuid1, "-")
	assert.Contains(t, uuid2, "-")
}

func TestGetEndpointIdentifier(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		path        string
		expected    string
		expectError bool
	}{
		{
			name:     "host with port",
			host:     "localhost:8080",
			path:     "/api/v1",
			expected: ":8080/api/v1",
		},
		{
			name:     "host without port",
			host:     "localhost",
			path:     "/api/v1",
			expected: ":80/api/v1",
		},
		{
			name:     "empty host",
			host:     "",
			path:     "/api/v1",
			expected: "/api/v1",
		},
		{
			name:        "invalid host with spaces",
			host:        "local host",
			path:        "/api/v1",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &tracerhttptype.Event{
				Request: &http.Request{
					Host: tt.host,
					URL: &url.URL{
						Path: tt.path,
					},
				},
			}

			result, err := GetEndpointIdentifier(event)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestIsValidHost(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{
			name:     "valid hostname",
			host:     "localhost",
			expected: true,
		},
		{
			name:     "valid hostname with port",
			host:     "localhost:8080",
			expected: true,
		},
		{
			name:     "valid IP",
			host:     "192.168.1.1",
			expected: true,
		},
		{
			name:     "valid IP with port",
			host:     "192.168.1.1:8080",
			expected: true,
		},
		{
			name:     "empty host",
			host:     "",
			expected: false,
		},
		{
			name:     "host with space",
			host:     "local host",
			expected: false,
		},
		{
			name:     "host with tab",
			host:     "localhost\t",
			expected: false,
		},
		{
			name:     "host with newline",
			host:     "localhost\n",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidHost(tt.host)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsPolicyIncluded(t *testing.T) {
	tests := []struct {
		name           string
		existingPolicy *v1beta1.RulePolicy
		newPolicy      *v1beta1.RulePolicy
		expected       bool
	}{
		{
			name:           "nil existing policy",
			existingPolicy: nil,
			newPolicy: &v1beta1.RulePolicy{
				AllowedContainer: false,
				AllowedProcesses: []string{"process1"},
			},
			expected: false,
		},
		{
			name: "new policy allows container but existing doesn't",
			existingPolicy: &v1beta1.RulePolicy{
				AllowedContainer: false,
				AllowedProcesses: []string{"process1"},
			},
			newPolicy: &v1beta1.RulePolicy{
				AllowedContainer: true,
				AllowedProcesses: []string{"process1"},
			},
			expected: false,
		},
		{
			name: "new process not in existing",
			existingPolicy: &v1beta1.RulePolicy{
				AllowedContainer: false,
				AllowedProcesses: []string{"process1"},
			},
			newPolicy: &v1beta1.RulePolicy{
				AllowedContainer: false,
				AllowedProcesses: []string{"process2"},
			},
			expected: false,
		},
		{
			name: "new policy fully included",
			existingPolicy: &v1beta1.RulePolicy{
				AllowedContainer: true,
				AllowedProcesses: []string{"process1", "process2"},
			},
			newPolicy: &v1beta1.RulePolicy{
				AllowedContainer: false,
				AllowedProcesses: []string{"process1"},
			},
			expected: true,
		},
		{
			name: "identical policies",
			existingPolicy: &v1beta1.RulePolicy{
				AllowedContainer: false,
				AllowedProcesses: []string{"process1"},
			},
			newPolicy: &v1beta1.RulePolicy{
				AllowedContainer: false,
				AllowedProcesses: []string{"process1"},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPolicyIncluded(tt.existingPolicy, tt.newPolicy)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCalculateHTTPEndpointHash(t *testing.T) {
	endpoint1 := &v1beta1.HTTPEndpoint{
		Endpoint:  ":80/api/v1",
		Methods:   []string{"GET", "POST"},
		Internal:  false,
		Direction: "inbound",
		Headers:   []byte(`{"Content-Type":["application/json"]}`),
	}

	endpoint2 := &v1beta1.HTTPEndpoint{
		Endpoint:  ":80/api/v1",
		Methods:   []string{"POST", "GET"}, // Different order
		Internal:  false,
		Direction: "inbound",
		Headers:   []byte(`{"Content-Type":["application/json"]}`),
	}

	endpoint3 := &v1beta1.HTTPEndpoint{
		Endpoint:  ":80/api/v2", // Different endpoint
		Methods:   []string{"GET", "POST"},
		Internal:  false,
		Direction: "inbound",
		Headers:   []byte(`{"Content-Type":["application/json"]}`),
	}

	hash1 := CalculateHTTPEndpointHash(endpoint1)
	hash2 := CalculateHTTPEndpointHash(endpoint2)
	hash3 := CalculateHTTPEndpointHash(endpoint3)

	// Same endpoints with different method order should have same hash
	assert.Equal(t, hash1, hash2)

	// Different endpoints should have different hashes
	assert.NotEqual(t, hash1, hash3)

	// Hash should be consistent
	hash1Again := CalculateHTTPEndpointHash(endpoint1)
	assert.Equal(t, hash1, hash1Again)
}

func TestCalculateSHA256CallStackHash(t *testing.T) {
	callStack1 := v1beta1.IdentifiedCallStack{
		CallID: "open",
		CallStack: v1beta1.CallStack{
			Root: v1beta1.CallStackNode{
				Frame: v1beta1.StackFrame{
					FileID: "1",
					Lineno: "42",
				},
				Children: []v1beta1.CallStackNode{},
			},
		},
	}

	callStack2 := v1beta1.IdentifiedCallStack{
		CallID: "exec",
		CallStack: v1beta1.CallStack{
			Root: v1beta1.CallStackNode{
				Frame: v1beta1.StackFrame{
					FileID: "2",
					Lineno: "84",
				},
				Children: []v1beta1.CallStackNode{
					{
						Frame: v1beta1.StackFrame{
							FileID: "3",
							Lineno: "120",
						},
						Children: []v1beta1.CallStackNode{},
					},
				},
			},
		},
	}

	hash1 := CalculateSHA256CallStackHash(callStack1)
	hash2 := CalculateSHA256CallStackHash(callStack2)

	// Different call stacks should produce different hashes
	assert.NotEqual(t, hash1, hash2)

	// Same call stack should produce same hash
	hash1Again := CalculateSHA256CallStackHash(callStack1)
	assert.Equal(t, hash1, hash1Again)

	// Hash should be 64 characters (SHA256 hex encoded)
	assert.Len(t, hash1, 64)
	assert.Len(t, hash2, 64)
}

func TestContainerProfileManagerCreation(t *testing.T) {
	cfg := config.Config{
		InitialDelay:     1 * time.Second,
		MaxSniffingTime:  5 * time.Minute,
		UpdateDataPeriod: 5 * time.Second,
	}
	ctx := context.TODO()
	k8sClient := &k8sclient.K8sClientMock{}
	storageClient := &storage.StorageHttpClientMock{}
	k8sObjectCacheMock := &objectcache.K8sObjectCacheMock{}
	seccompManagerMock := &seccompmanager.SeccompManagerMock{}
	dnsResolverMock := &dnsmanager.DNSManagerMock{}

	cpm, err := NewContainerProfileManager(
		ctx,
		cfg,
		k8sClient,
		k8sObjectCacheMock,
		storageClient,
		dnsResolverMock,
		seccompManagerMock,
		nil,
		nil,
	)

	assert.NoError(t, err)
	assert.NotNil(t, cpm)
	assert.Equal(t, ctx, cpm.ctx)
	assert.Equal(t, cfg, cpm.cfg)
	assert.Equal(t, k8sClient, cpm.k8sClient)
	assert.Equal(t, k8sObjectCacheMock, cpm.k8sObjectCache)
	assert.Equal(t, storageClient, cpm.storageClient)
	assert.Equal(t, dnsResolverMock, cpm.dnsResolverClient)
	assert.Equal(t, seccompManagerMock, cpm.seccompManager)
	assert.NotNil(t, cpm.maxSniffTimeNotificationChan)
}

func TestContainerDataMethods(t *testing.T) {
	cd := &containerData{}

	// Test getCapabilities with nil capabilities
	caps := cd.getCapabilities()
	assert.Empty(t, caps)

	// Test getExecs with nil execs
	execs := cd.getExecs()
	assert.Empty(t, execs)

	// Test getOpens with nil opens
	opens := cd.getOpens()
	assert.Empty(t, opens)

	// Test getEndpoints with nil endpoints
	endpoints := cd.getEndpoints()
	assert.Empty(t, endpoints)

	// Test getRulePolicies with nil rulePolicies
	policies := cd.getRulePolicies()
	assert.Empty(t, policies)

	// Test getCallStacks with nil callStacks
	callStacks := cd.getCallStacks()
	assert.Empty(t, callStacks)

	// Test getIngressNetworkNeighbors with nil networks
	ingress := cd.getIngressNetworkNeighbors("default", nil, nil)
	assert.Empty(t, ingress)

	// Test getEgressNetworkNeighbors with nil networks
	egress := cd.getEgressNetworkNeighbors("default", nil, nil)
	assert.Empty(t, egress)
}

func TestContainerDataEmptyEvents(t *testing.T) {
	cd := &containerData{
		capabilites:  mapset.NewSet[string]("cap1"),
		endpoints:    &maps.SafeMap[string, *v1beta1.HTTPEndpoint]{},
		execs:        &maps.SafeMap[string, []string]{},
		opens:        &maps.SafeMap[string, mapset.Set[string]]{},
		rulePolicies: &maps.SafeMap[string, *v1beta1.RulePolicy]{},
		callStacks:   &maps.SafeMap[string, *v1beta1.IdentifiedCallStack]{},
		networks:     mapset.NewSet[NetworkEvent](),
	}

	cd.emptyEvents()

	assert.Nil(t, cd.capabilites)
	assert.Nil(t, cd.endpoints)
	assert.Nil(t, cd.execs)
	assert.Nil(t, cd.opens)
	assert.Nil(t, cd.rulePolicies)
	assert.Nil(t, cd.callStacks)
	assert.Nil(t, cd.networks)
	// Note: syscalls should remain not nil as per the comment in the code
}

func TestContainerProfileManagerRegisterPeekFunc(t *testing.T) {
	cfg := config.Config{}
	ctx := context.TODO()
	k8sClient := &k8sclient.K8sClientMock{}
	storageClient := &storage.StorageHttpClientMock{}
	k8sObjectCacheMock := &objectcache.K8sObjectCacheMock{}
	seccompManagerMock := &seccompmanager.SeccompManagerMock{}

	cpm, err := NewContainerProfileManager(
		ctx,
		cfg,
		k8sClient,
		k8sObjectCacheMock,
		storageClient,
		nil,
		seccompManagerMock,
		nil,
		nil,
	)
	require.NoError(t, err)

	// Register a peek function
	peekFunc := func(mntns uint64) ([]string, error) {
		return []string{"open", "read"}, nil
	}

	cpm.RegisterPeekFunc(peekFunc)
	assert.NotNil(t, cpm.syscallPeekFunc)

	// Test the registered function
	result, err := cpm.syscallPeekFunc(12345)
	assert.NoError(t, err)
	assert.Equal(t, []string{"open", "read"}, result)
}

func TestEndpointKindConstants(t *testing.T) {
	assert.Equal(t, EndpointKind("pod"), EndpointKindPod)
	assert.Equal(t, EndpointKind("svc"), EndpointKindService)
	assert.Equal(t, EndpointKind("raw"), EndpointKindRaw)
}

func TestTrafficTypeConstants(t *testing.T) {
	assert.Equal(t, "internal", InternalTrafficType)
	assert.Equal(t, "external", ExternalTrafficType)
	assert.Equal(t, "HOST", HostPktType)
	assert.Equal(t, "OUTGOING", OutgoingPktType)
}

func TestDefaultLabelsToIgnore(t *testing.T) {
	expectedLabels := map[string]struct{}{
		"controller-revision-hash": {},
		"pod-template-generation":  {},
		"pod-template-hash":        {},
	}

	assert.Equal(t, expectedLabels, DefaultLabelsToIgnore)
}

func TestErrContainerNotFound(t *testing.T) {
	assert.Equal(t, "container not found", ErrContainerNotFound.Error())
}

func TestMaxSniffingTimeLabelConstant(t *testing.T) {
	assert.Equal(t, "kubescape.io/max-sniffing-time", MaxSniffingTimeLabel)
}

func TestMaxWaitForSharedContainerDataConstant(t *testing.T) {
	assert.Equal(t, 10*time.Minute, MaxWaitForSharedContainerData)
}
