package rulefailurecreator

import (
	"errors"
	"testing"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock implementations
type MockDNSManager struct {
	mock.Mock
}

func (m *MockDNSManager) ResolveIPAddress(ipAddr string) (string, bool) {
	args := m.Called(ipAddr)
	return args.String(0), args.Bool(1)
}

func (m *MockDNSManager) ResolveContainerProcessToCloudServices(containerID string, pid uint32) mapset.Set[string] {
	args := m.Called(containerID, pid)
	return args.Get(0).(mapset.Set[string])
}

type MockEnricher struct {
	mock.Mock
}

func (m *MockEnricher) EnrichRuleFailure(ruleFailure types.RuleFailure) error {
	args := m.Called(ruleFailure)
	return args.Error(0)
}

type MockEventMetadataSetter struct {
	mock.Mock
}

func (m *MockEventMetadataSetter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	m.Called(failure, enrichedEvent)
}

func TestNewRuleFailureCreator(t *testing.T) {
	mockDNS := &MockDNSManager{}
	mockEnricher := &MockEnricher{}

	creator := NewRuleFailureCreator(mockEnricher, mockDNS)

	assert.NotNil(t, creator)
	assert.Equal(t, mockDNS, creator.dnsManager)
	assert.Equal(t, mockEnricher, creator.enricher)
	assert.NotNil(t, creator.setterByEventType)
}

func TestSetContainerIdToPid(t *testing.T) {
	creator := NewRuleFailureCreator(nil, nil)
	containerIdToPid := maps.NewSafeMap[string, uint32]()

	creator.SetContainerIdToPid(containerIdToPid)

	assert.Equal(t, containerIdToPid, creator.containerIdToPid)
}

func TestRegisterCreator(t *testing.T) {
	creator := NewRuleFailureCreator(nil, nil)
	mockSetter := &MockEventMetadataSetter{}

	creator.RegisterCreator(utils.ExecveEventType, mockSetter)

	assert.Equal(t, mockSetter, creator.setterByEventType[utils.ExecveEventType])
}

func TestCreateRuleFailure_Success(t *testing.T) {
	mockDNS := &MockDNSManager{}
	mockEnricher := &MockEnricher{}
	mockSetter := &MockEventMetadataSetter{}

	creator := NewRuleFailureCreator(mockEnricher, mockDNS)
	creator.RegisterCreator(utils.ExecveEventType, mockSetter)

	rule := typesv1.Rule{
		Spec: typesv1.RuleSpec{
			Name:     "test-rule",
			ID:       "test-rule-id",
			Severity: 1, // high severity
		},
	}

	enrichedEvent := &events.EnrichedEvent{
		EventType: utils.ExecveEventType,
		Timestamp: time.Now(),
		ProcessTree: apitypes.Process{
			PID:  12345,
			Path: "/bin/test",
		},
	}

	objectCache := objectcachev1.NewObjectCache(nil, nil, nil, nil)
	message := "Test violation"
	uniqueID := "unique-123"

	mockSetter.On("SetFailureMetadata", mock.AnythingOfType("*types.GenericRuleFailure"), enrichedEvent).Return()
	mockEnricher.On("EnrichRuleFailure", mock.AnythingOfType("*types.GenericRuleFailure")).Return(nil)
	cloudServices := mapset.NewSet[string]()
	cloudServices.Add("aws")
	mockDNS.On("ResolveContainerProcessToCloudServices", "", uint32(0)).Return(cloudServices)

	result := creator.CreateRuleFailure(rule, enrichedEvent, objectCache, message, uniqueID)

	assert.NotNil(t, result)
	assert.Equal(t, uniqueID, result.GetBaseRuntimeAlert().UniqueID)
	assert.Equal(t, "test-rule", result.GetBaseRuntimeAlert().AlertName)
	assert.Equal(t, 1, result.GetBaseRuntimeAlert().Severity)
	assert.Equal(t, "test-rule-id", result.GetRuleId())
	assert.Equal(t, apitypes.AlertSourcePlatformK8s, result.GetAlertPlatform())
	assert.Equal(t, message, result.GetRuleAlert().RuleDescription)

	// Verify cloud services
	assert.Equal(t, []string{"aws"}, result.GetCloudServices())

	mockSetter.AssertExpectations(t)
	mockEnricher.AssertExpectations(t)
	mockDNS.AssertExpectations(t)
}

func TestCreateRuleFailure_NoEventSetter(t *testing.T) {
	creator := NewRuleFailureCreator(nil, nil)

	rule := typesv1.Rule{
		Spec: typesv1.RuleSpec{
			Name: "test-rule",
		},
	}

	enrichedEvent := &events.EnrichedEvent{
		EventType: utils.ExecveEventType,
	}

	objectCache := objectcachev1.NewObjectCache(nil, nil, nil, nil)
	message := "Test violation"
	uniqueID := "unique-123"

	result := creator.CreateRuleFailure(rule, enrichedEvent, objectCache, message, uniqueID)

	assert.Nil(t, result)
}

func TestCreateRuleFailure_EnricherError(t *testing.T) {
	mockDNS := &MockDNSManager{}
	mockEnricher := &MockEnricher{}
	mockSetter := &MockEventMetadataSetter{}

	creator := NewRuleFailureCreator(mockEnricher, mockDNS)
	creator.RegisterCreator(utils.ExecveEventType, mockSetter)

	rule := typesv1.Rule{
		Spec: typesv1.RuleSpec{
			Name: "test-rule",
		},
	}

	enrichedEvent := &events.EnrichedEvent{
		EventType: utils.ExecveEventType,
	}

	objectCache := objectcachev1.NewObjectCache(nil, nil, nil, nil)
	message := "Test violation"
	uniqueID := "unique-123"

	mockSetter.On("SetFailureMetadata", mock.AnythingOfType("*types.GenericRuleFailure"), enrichedEvent).Return()
	mockEnricher.On("EnrichRuleFailure", mock.AnythingOfType("*types.GenericRuleFailure")).Return(errors.New("enrichment error"))
	cloudServices := mapset.NewSet[string]()
	mockDNS.On("ResolveContainerProcessToCloudServices", "", uint32(0)).Return(cloudServices)

	result := creator.CreateRuleFailure(rule, enrichedEvent, objectCache, message, uniqueID)

	assert.NotNil(t, result)
	assert.Equal(t, uniqueID, result.GetBaseRuntimeAlert().UniqueID)

	mockSetter.AssertExpectations(t)
	mockEnricher.AssertExpectations(t)
	mockDNS.AssertExpectations(t)
}

func TestCreateRuleFailure_EnricherShouldNotAlert(t *testing.T) {
	mockDNS := &MockDNSManager{}
	mockEnricher := &MockEnricher{}
	mockSetter := &MockEventMetadataSetter{}

	creator := NewRuleFailureCreator(mockEnricher, mockDNS)
	creator.RegisterCreator(utils.ExecveEventType, mockSetter)

	rule := typesv1.Rule{
		Spec: typesv1.RuleSpec{
			Name: "test-rule",
		},
	}

	enrichedEvent := &events.EnrichedEvent{
		EventType: utils.ExecveEventType,
	}

	objectCache := objectcachev1.NewObjectCache(nil, nil, nil, nil)
	message := "Test violation"
	uniqueID := "unique-123"

	mockSetter.On("SetFailureMetadata", mock.AnythingOfType("*types.GenericRuleFailure"), enrichedEvent).Return()
	mockEnricher.On("EnrichRuleFailure", mock.AnythingOfType("*types.GenericRuleFailure")).Return(ErrRuleShouldNotBeAlerted)
	cloudServices := mapset.NewSet[string]()
	mockDNS.On("ResolveContainerProcessToCloudServices", "", uint32(0)).Return(cloudServices)

	result := creator.CreateRuleFailure(rule, enrichedEvent, objectCache, message, uniqueID)

	assert.NotNil(t, result)
	assert.Equal(t, uniqueID, result.GetBaseRuntimeAlert().UniqueID)

	mockSetter.AssertExpectations(t)
	mockEnricher.AssertExpectations(t)
	mockDNS.AssertExpectations(t)
}

func TestCreateRuleFailure_WithContainerIdToPid(t *testing.T) {
	mockDNS := &MockDNSManager{}
	mockEnricher := &MockEnricher{}
	mockSetter := &MockEventMetadataSetter{}

	creator := NewRuleFailureCreator(mockEnricher, mockDNS)
	creator.RegisterCreator(utils.ExecveEventType, mockSetter)

	containerIdToPid := maps.NewSafeMap[string, uint32]()
	containerIdToPid.Set("container-123", 12345)
	creator.SetContainerIdToPid(containerIdToPid)

	rule := typesv1.Rule{
		Spec: typesv1.RuleSpec{
			Name: "test-rule",
		},
	}

	enrichedEvent := &events.EnrichedEvent{
		EventType: utils.ExecveEventType,
	}

	objectCache := objectcachev1.NewObjectCache(nil, nil, nil, nil)
	message := "Test violation"
	uniqueID := "unique-123"

	mockSetter.On("SetFailureMetadata", mock.AnythingOfType("*types.GenericRuleFailure"), enrichedEvent).Return()
	mockEnricher.On("EnrichRuleFailure", mock.AnythingOfType("*types.GenericRuleFailure")).Return(nil)
	cloudServices := mapset.NewSet[string]()
	mockDNS.On("ResolveContainerProcessToCloudServices", "", uint32(0)).Return(cloudServices)

	result := creator.CreateRuleFailure(rule, enrichedEvent, objectCache, message, uniqueID)

	assert.NotNil(t, result)
	assert.Equal(t, uniqueID, result.GetBaseRuntimeAlert().UniqueID)

	mockSetter.AssertExpectations(t)
	mockEnricher.AssertExpectations(t)
	mockDNS.AssertExpectations(t)
}

func TestCreateRuleFailure_WithProcessTree(t *testing.T) {
	mockDNS := &MockDNSManager{}
	mockEnricher := &MockEnricher{}
	mockSetter := &MockEventMetadataSetter{}

	creator := NewRuleFailureCreator(mockEnricher, mockDNS)
	creator.RegisterCreator(utils.ExecveEventType, mockSetter)

	rule := typesv1.Rule{
		Spec: typesv1.RuleSpec{
			Name: "test-rule",
		},
	}

	processTree := apitypes.Process{
		PID:  12345,
		Comm: "test-command",
	}

	enrichedEvent := &events.EnrichedEvent{
		EventType:   utils.ExecveEventType,
		ProcessTree: processTree,
	}

	objectCache := objectcachev1.NewObjectCache(nil, nil, nil, nil)
	message := "Test violation"
	uniqueID := "unique-123"

	mockSetter.On("SetFailureMetadata", mock.AnythingOfType("*types.GenericRuleFailure"), enrichedEvent).Return()
	mockEnricher.On("EnrichRuleFailure", mock.AnythingOfType("*types.GenericRuleFailure")).Return(nil)
	cloudServices := mapset.NewSet[string]()
	mockDNS.On("ResolveContainerProcessToCloudServices", "", uint32(0)).Return(cloudServices)

	result := creator.CreateRuleFailure(rule, enrichedEvent, objectCache, message, uniqueID)

	assert.NotNil(t, result)
	assert.Equal(t, uniqueID, result.GetBaseRuntimeAlert().UniqueID)

	// Verify process tree details
	runtimeProcessDetails := result.GetRuntimeProcessDetails()
	assert.Equal(t, uint32(12345), runtimeProcessDetails.ProcessTree.PID)
	assert.Equal(t, "test-command", runtimeProcessDetails.ProcessTree.Comm)

	mockSetter.AssertExpectations(t)
	mockEnricher.AssertExpectations(t)
	mockDNS.AssertExpectations(t)
}

func TestCreateRuleFailure_Arguments(t *testing.T) {
	mockDNS := &MockDNSManager{}
	mockEnricher := &MockEnricher{}
	mockSetter := &MockEventMetadataSetter{}

	creator := NewRuleFailureCreator(mockEnricher, mockDNS)
	creator.RegisterCreator(utils.ExecveEventType, mockSetter)

	rule := typesv1.Rule{
		Spec: typesv1.RuleSpec{
			Name: "test-rule",
		},
	}

	enrichedEvent := &events.EnrichedEvent{
		EventType: utils.ExecveEventType,
	}

	objectCache := objectcachev1.NewObjectCache(nil, nil, nil, nil)
	message := "Test violation message"
	uniqueID := "unique-123"

	mockSetter.On("SetFailureMetadata", mock.AnythingOfType("*types.GenericRuleFailure"), enrichedEvent).Return()
	mockEnricher.On("EnrichRuleFailure", mock.AnythingOfType("*types.GenericRuleFailure")).Return(nil)
	cloudServices := mapset.NewSet[string]()
	mockDNS.On("ResolveContainerProcessToCloudServices", "", uint32(0)).Return(cloudServices)

	result := creator.CreateRuleFailure(rule, enrichedEvent, objectCache, message, uniqueID)

	assert.NotNil(t, result)

	// Verify arguments
	arguments := result.GetBaseRuntimeAlert().Arguments
	assert.NotNil(t, arguments)
	assert.Equal(t, message, arguments["message"])

	mockSetter.AssertExpectations(t)
	mockEnricher.AssertExpectations(t)
	mockDNS.AssertExpectations(t)
}
