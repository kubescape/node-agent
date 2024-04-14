package networkmanager

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
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
			expectedResult: "key1=value1",
		},
		{
			name: "Multiple Labels",
			podLabels: map[string]string{
				"key1": "value1",
				"key2": "value2",
				"key3": "value3",
			},
			expectedResult: "key1=value1,key2=value2,key3=value3",
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

	// test that pod labels are sorted
	podLabels1 := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}

	podLabels2 := map[string]string{
		"key2": "value2",
		"key1": "value1",
	}

	actualResult1 := generatePodLabels(podLabels1)
	actualResult2 := generatePodLabels(podLabels2)
	assert.Equal(t, actualResult1, actualResult2)

}

func TestSetPodLabels(t *testing.T) {
	ne := &NetworkEvent{}

	tests := []struct {
		name           string
		podLabels      map[string]string
		expectedResult string
	}{
		{
			name: "regular order",
			podLabels: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			expectedResult: "key1=value1,key2=value2",
		},
		{
			name: "change order",
			podLabels: map[string]string{
				"key2": "value2",
				"key1": "value1",
			},
			expectedResult: "key1=value1,key2=value2",
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
			name: "regular order",
			podLabels: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			expectedResult: "key1=value1,key2=value2",
		},
		{
			name: "change order",
			podLabels: map[string]string{
				"key2": "value2",
				"key1": "value1",
			},
			expectedResult: "key1=value1,key2=value2",
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

func TestGeneratePortIdentifierFromEvent(t *testing.T) {
	testCases := []struct {
		input    NetworkEvent
		expected string
	}{
		{
			input: NetworkEvent{
				Port:     80,
				PktType:  "TCP",
				Protocol: "HTTP",
				Destination: Destination{
					Namespace: "namespace1",
					Name:      "name1",
					Kind:      EndpointKindPod,
					PodLabels: "label1=labelValue1,label2=labelValue2",
					IPAddress: "192.168.1.1",
				},
			},
			expected: "HTTP-80",
		},
		{
			input: NetworkEvent{
				Port:     333,
				PktType:  "TCP",
				Protocol: "UDP",
				Destination: Destination{
					Namespace: "namespace1",
					Name:      "name1",
					Kind:      EndpointKindPod,
					PodLabels: "label1=labelValue1,label2=labelValue2",
					IPAddress: "192.168.1.1",
				},
			},
			expected: "UDP-333",
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Input: %+v", tc.input), func(t *testing.T) {
			result := GeneratePortIdentifierFromEvent(tc.input)
			if result != tc.expected {
				t.Errorf("Expected: %s, Got: %s", tc.expected, result)
			}
		})
	}
}

func TestGeneratePortIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		port     int32
		protocol string
		expected string
	}{
		{
			name:     "http",
			port:     80,
			protocol: "TCP",
			expected: "TCP-80",
		},
		{
			name:     "udp",
			port:     333,
			protocol: "UDP",
			expected: "UDP-333",
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("Input: %s", tc.name), func(t *testing.T) {
			result := GeneratePortIdentifier(tc.protocol, tc.port)
			assert.Equal(t, tc.expected, result)
		})
	}
}
