package utils

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
