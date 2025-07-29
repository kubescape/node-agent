package profilevalidator

import (
	"testing"

	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock implementations
type MockProfileValidator struct {
	mock.Mock
	eventType utils.EventType
	id        string // unique identifier for testing
}

func (m *MockProfileValidator) ValidateProfile(event utils.K8sEvent, ap *v1beta1.ApplicationProfileContainer, nn *v1beta1.NetworkNeighborhoodContainer) (ProfileValidationResult, error) {
	args := m.Called(event, ap, nn)
	return args.Get(0).(ProfileValidationResult), args.Error(1)
}

func (m *MockProfileValidator) GetRequiredEventType() utils.EventType {
	return m.eventType
}

type MockRulePolicyValidator struct {
	mock.Mock
}

func (m *MockRulePolicyValidator) ValidateRulePolicy(ruleId string, process string, ap *v1beta1.ApplicationProfileContainer, nn *v1beta1.NetworkNeighborhoodContainer) (ProfileValidationResult, error) {
	args := m.Called(ruleId, process, ap, nn)
	return args.Get(0).(ProfileValidationResult), args.Error(1)
}

func TestNewProfileValidatorFactory(t *testing.T) {
	objectCache := objectcachev1.NewObjectCache(nil, nil, nil, nil)

	factory := NewProfileValidatorFactory(objectCache)

	assert.NotNil(t, factory)
	assert.IsType(t, &ProfileValidatorFactoryImpl{}, factory)
}

func TestGetProfileValidator_Exists(t *testing.T) {
	objectCache := objectcachev1.NewObjectCache(nil, nil, nil, nil)
	factory := NewProfileValidatorFactory(objectCache).(*ProfileValidatorFactoryImpl)

	mockValidator := &MockProfileValidator{eventType: utils.ExecveEventType, id: "test-validator"}
	factory.RegisterProfileValidator(mockValidator, utils.ExecveEventType)

	result := factory.GetProfileValidator(utils.ExecveEventType)

	assert.Equal(t, mockValidator, result)
}

func TestGetProfileValidator_NotExists(t *testing.T) {
	objectCache := objectcachev1.NewObjectCache(nil, nil, nil, nil)
	factory := NewProfileValidatorFactory(objectCache).(*ProfileValidatorFactoryImpl)

	result := factory.GetProfileValidator(utils.ExecveEventType)

	assert.Nil(t, result)
}

func TestRegisterProfileValidator(t *testing.T) {
	objectCache := objectcachev1.NewObjectCache(nil, nil, nil, nil)
	factory := NewProfileValidatorFactory(objectCache).(*ProfileValidatorFactoryImpl)

	mockValidator := &MockProfileValidator{eventType: utils.ExecveEventType, id: "register-test"}

	factory.RegisterProfileValidator(mockValidator, utils.ExecveEventType)

	// Verify it was registered
	result := factory.GetProfileValidator(utils.ExecveEventType)
	assert.Equal(t, mockValidator, result)
}

func TestRegisterProfileValidator_Overwrite(t *testing.T) {
	objectCache := objectcachev1.NewObjectCache(nil, nil, nil, nil)
	factory := NewProfileValidatorFactory(objectCache).(*ProfileValidatorFactoryImpl)

	mockValidator1 := &MockProfileValidator{eventType: utils.ExecveEventType, id: "validator1"}
	mockValidator2 := &MockProfileValidator{eventType: utils.ExecveEventType, id: "validator2"}

	// Register first validator
	factory.RegisterProfileValidator(mockValidator1, utils.ExecveEventType)

	// Verify first validator is returned
	result1 := factory.GetProfileValidator(utils.ExecveEventType)
	assert.Equal(t, mockValidator1, result1)

	// Register second validator (should overwrite)
	factory.RegisterProfileValidator(mockValidator2, utils.ExecveEventType)

	// Verify second validator is returned
	result2 := factory.GetProfileValidator(utils.ExecveEventType)
	assert.Equal(t, mockValidator2, result2)
	assert.NotEqual(t, mockValidator1, result2)
}

func TestUnregisterProfileValidator(t *testing.T) {
	objectCache := objectcachev1.NewObjectCache(nil, nil, nil, nil)
	factory := NewProfileValidatorFactory(objectCache).(*ProfileValidatorFactoryImpl)

	mockValidator := &MockProfileValidator{eventType: utils.ExecveEventType}

	// Register validator
	factory.RegisterProfileValidator(mockValidator, utils.ExecveEventType)

	// Verify it exists
	result := factory.GetProfileValidator(utils.ExecveEventType)
	assert.Equal(t, mockValidator, result)

	// Unregister
	factory.UnregisterProfileValidator(utils.ExecveEventType)

	// Verify it's gone
	result = factory.GetProfileValidator(utils.ExecveEventType)
	assert.Nil(t, result)
}

func TestUnregisterProfileValidator_NotExists(t *testing.T) {
	objectCache := objectcachev1.NewObjectCache(nil, nil, nil, nil)
	factory := NewProfileValidatorFactory(objectCache).(*ProfileValidatorFactoryImpl)

	// Try to unregister non-existent validator
	factory.UnregisterProfileValidator(utils.ExecveEventType)

	// Should not panic and should return nil
	result := factory.GetProfileValidator(utils.ExecveEventType)
	assert.Nil(t, result)
}

func TestGetRulePolicyValidator(t *testing.T) {
	objectCache := objectcachev1.NewObjectCache(nil, nil, nil, nil)
	factory := NewProfileValidatorFactory(objectCache).(*ProfileValidatorFactoryImpl)

	// Initially should be nil
	result := factory.GetRulePolicyValidator()
	assert.Nil(t, result)

	// Set a mock validator
	mockRulePolicyValidator := &MockRulePolicyValidator{}
	factory.rulePolicyValidator = mockRulePolicyValidator

	// Should return the set validator
	result = factory.GetRulePolicyValidator()
	assert.Equal(t, mockRulePolicyValidator, result)
}

func TestMultipleEventTypes(t *testing.T) {
	objectCache := objectcachev1.NewObjectCache(nil, nil, nil, nil)
	factory := NewProfileValidatorFactory(objectCache).(*ProfileValidatorFactoryImpl)

	mockExecValidator := &MockProfileValidator{eventType: utils.ExecveEventType}
	mockOpenValidator := &MockProfileValidator{eventType: utils.OpenEventType}
	mockNetworkValidator := &MockProfileValidator{eventType: utils.NetworkEventType}

	// Register multiple validators
	factory.RegisterProfileValidator(mockExecValidator, utils.ExecveEventType)
	factory.RegisterProfileValidator(mockOpenValidator, utils.OpenEventType)
	factory.RegisterProfileValidator(mockNetworkValidator, utils.NetworkEventType)

	// Verify each validator is returned correctly
	assert.Equal(t, mockExecValidator, factory.GetProfileValidator(utils.ExecveEventType))
	assert.Equal(t, mockOpenValidator, factory.GetProfileValidator(utils.OpenEventType))
	assert.Equal(t, mockNetworkValidator, factory.GetProfileValidator(utils.NetworkEventType))

	// Verify non-existent event type returns nil
	assert.Nil(t, factory.GetProfileValidator(utils.DnsEventType))
}

func TestConcurrentAccess(t *testing.T) {
	objectCache := objectcachev1.NewObjectCache(nil, nil, nil, nil)
	factory := NewProfileValidatorFactory(objectCache).(*ProfileValidatorFactoryImpl)

	// This test verifies that the SafeMap used internally handles concurrent access
	// We'll register and unregister validators concurrently

	done := make(chan bool, 2)

	// Goroutine 1: Register and get validators
	go func() {
		for i := 0; i < 100; i++ {
			mockValidator := &MockProfileValidator{eventType: utils.ExecveEventType}
			factory.RegisterProfileValidator(mockValidator, utils.ExecveEventType)
			factory.GetProfileValidator(utils.ExecveEventType)
		}
		done <- true
	}()

	// Goroutine 2: Register and unregister validators
	go func() {
		for i := 0; i < 100; i++ {
			mockValidator := &MockProfileValidator{eventType: utils.OpenEventType}
			factory.RegisterProfileValidator(mockValidator, utils.OpenEventType)
			factory.UnregisterProfileValidator(utils.OpenEventType)
		}
		done <- true
	}()

	// Wait for both goroutines to complete
	<-done
	<-done

	// Verify final state is consistent
	execValidator := factory.GetProfileValidator(utils.ExecveEventType)
	assert.NotNil(t, execValidator)

	openValidator := factory.GetProfileValidator(utils.OpenEventType)
	assert.Nil(t, openValidator)
}
