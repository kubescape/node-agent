package networkmanager

import (
	"testing"
)

func TestGeneratePodLabels(t *testing.T) {
	tests := []struct {
		name           string
		podLabels      map[string]string
		expectedResult string
	}{
		{
			name:           "Empty Map",
			podLabels:      map[string]string{},
			expectedResult: "",
		},
		{
			name: "Single Label",
			podLabels: map[string]string{
				"key1": "value1",
			},
			expectedResult: "key1=value1,",
		},
		{
			name: "Multiple Labels",
			podLabels: map[string]string{
				"key1": "value1",
				"key2": "value2",
				"key3": "value3",
			},
			expectedResult: "key1=value1,key2=value2,key3=value3,",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualResult := generatePodLabels(test.podLabels)
			if actualResult != test.expectedResult {
				t.Errorf("Expected: %s, but got: %s", test.expectedResult, actualResult)
			}
		})
	}
}

func TestSetPodLabels(t *testing.T) {
	ne := &NetworkEvent{}

	tests := []struct {
		name           string
		podLabels      map[string]string
		expectedResult string
	}{
		{
			name: "Set Pod Labels",
			podLabels: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			expectedResult: "key1=value1,key2=value2,",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ne.SetPodLabels(test.podLabels)
			actualResult := ne.PodLabels
			if actualResult != test.expectedResult {
				t.Errorf("Expected: %s, but got: %s", test.expectedResult, actualResult)
			}
		})
	}
}

func TestSetDestinationPodLabels(t *testing.T) {
	ne := &NetworkEvent{}

	tests := []struct {
		name           string
		podLabels      map[string]string
		expectedResult string
	}{
		{
			name: "Set Destination Pod Labels",
			podLabels: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			expectedResult: "key1=value1,key2=value2,",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ne.SetDestinationPodLabels(test.podLabels)
			actualResult := ne.Destination.PodLabels
			if actualResult != test.expectedResult {
				t.Errorf("Expected: %s, but got: %s", test.expectedResult, actualResult)
			}
		})
	}
}
