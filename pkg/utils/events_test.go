package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test struct that mimics the structure of events with Comm field
type testEventWithComm struct {
	Comm string
}

// Test struct that mimics the structure of events with Runtime field
type testEventWithRuntime struct {
	Runtime struct {
		ContainerID string
	}
}

func TestGetCommFromEvent(t *testing.T) {
	tests := []struct {
		name     string
		event    interface{}
		expected string
	}{
		{
			name: "Event with Comm",
			event: &testEventWithComm{
				Comm: "test-comm",
			},
			expected: "test-comm",
		},
		{
			name:     "nil event",
			event:    nil,
			expected: "",
		},
		{
			name:     "event without Comm field",
			event:    "string",
			expected: "",
		},
		{
			name:     "event with empty Comm field",
			event:    &testEventWithComm{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetCommFromEvent(tt.event)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetContainerIDFromEvent(t *testing.T) {
	tests := []struct {
		name     string
		event    interface{}
		expected string
	}{
		{
			name: "Event with ContainerID",
			event: &testEventWithRuntime{
				Runtime: struct {
					ContainerID string
				}{
					ContainerID: "test-container-id",
				},
			},
			expected: "test-container-id",
		},
		{
			name:     "nil event",
			event:    nil,
			expected: "",
		},
		{
			name:     "event without Runtime field",
			event:    "string",
			expected: "",
		},
		{
			name:     "event with Runtime but no ContainerID",
			event:    &testEventWithRuntime{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetContainerIDFromEvent(tt.event)
			assert.Equal(t, tt.expected, result)
		})
	}
}
