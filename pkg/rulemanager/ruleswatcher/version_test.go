package ruleswatcher

import (
	"os"
	"testing"
)

func TestIsAgentVersionCompatible(t *testing.T) {
	// Store original value to restore later
	originalVersion := os.Getenv("AGENT_VERSION")
	defer func() {
		if originalVersion == "" {
			os.Unsetenv("AGENT_VERSION")
		} else {
			os.Setenv("AGENT_VERSION", originalVersion)
		}
	}()

	tests := []struct {
		name         string
		agentVersion string
		requirement  string
		expected     bool
		description  string
	}{
		{
			name:         "exact version match",
			agentVersion: "1.2.3",
			requirement:  "1.2.3",
			expected:     true,
			description:  "Should match exact version",
		},
		{
			name:         "greater than requirement satisfied",
			agentVersion: "1.3.0",
			requirement:  ">=1.2.0",
			expected:     true,
			description:  "Should satisfy greater than or equal requirement",
		},
		{
			name:         "greater than requirement not satisfied",
			agentVersion: "1.1.0",
			requirement:  ">=1.2.0",
			expected:     false,
			description:  "Should not satisfy greater than or equal requirement",
		},
		{
			name:         "less than requirement satisfied",
			agentVersion: "1.1.5",
			requirement:  "<1.2.0",
			expected:     true,
			description:  "Should satisfy less than requirement",
		},
		{
			name:         "less than requirement not satisfied",
			agentVersion: "1.2.0",
			requirement:  "<1.2.0",
			expected:     false,
			description:  "Should not satisfy less than requirement",
		},
		{
			name:         "range requirement satisfied",
			agentVersion: "1.5.2",
			requirement:  ">=1.2.0, <2.0.0",
			expected:     true,
			description:  "Should satisfy range requirement",
		},
		{
			name:         "range requirement not satisfied - too low",
			agentVersion: "1.1.0",
			requirement:  ">=1.2.0, <2.0.0",
			expected:     false,
			description:  "Should not satisfy range requirement when version is too low",
		},
		{
			name:         "range requirement not satisfied - too high",
			agentVersion: "2.1.0",
			requirement:  ">=1.2.0, <2.0.0",
			expected:     false,
			description:  "Should not satisfy range requirement when version is too high",
		},
		{
			name:         "tilde constraint satisfied",
			agentVersion: "1.2.5",
			requirement:  "~1.2.0",
			expected:     true,
			description:  "Should satisfy tilde constraint (patch level changes)",
		},
		{
			name:         "tilde constraint not satisfied",
			agentVersion: "1.3.0",
			requirement:  "~1.2.0",
			expected:     false,
			description:  "Should not satisfy tilde constraint for minor version change",
		},
		{
			name:         "caret constraint satisfied",
			agentVersion: "1.5.0",
			requirement:  "^1.2.0",
			expected:     true,
			description:  "Should satisfy caret constraint (compatible changes)",
		},
		{
			name:         "caret constraint not satisfied",
			agentVersion: "2.0.0",
			requirement:  "^1.2.0",
			expected:     false,
			description:  "Should not satisfy caret constraint for major version change",
		},
		{
			name:         "prerelease version - less than normal",
			agentVersion: "1.2.3-alpha.1",
			requirement:  ">=1.2.0",
			expected:     false,
			description:  "Prerelease versions are considered less than normal versions in semver",
		},
		{
			name:         "prerelease version - explicit prerelease constraint",
			agentVersion: "1.2.3-alpha.1",
			requirement:  ">=1.2.3-alpha.0",
			expected:     true,
			description:  "Prerelease versions can satisfy explicit prerelease constraints",
		},
		{
			name:         "build metadata version",
			agentVersion: "1.2.3+build.1",
			requirement:  ">=1.2.0",
			expected:     true,
			description:  "Should handle build metadata in versions",
		},
		{
			name:         "empty agent version should allow all",
			agentVersion: "",
			requirement:  ">=1.2.0",
			expected:     true,
			description:  "Should allow all rules when AGENT_VERSION is not set",
		},
		{
			name:         "invalid agent version should allow all",
			agentVersion: "invalid-version",
			requirement:  ">=1.2.0",
			expected:     true,
			description:  "Should allow all rules when AGENT_VERSION is invalid",
		},
		{
			name:         "invalid requirement should allow all",
			agentVersion: "1.2.3",
			requirement:  "invalid-requirement",
			expected:     true,
			description:  "Should allow all rules when requirement is invalid",
		},
		{
			name:         "empty requirement string",
			agentVersion: "1.2.3",
			requirement:  "",
			expected:     true,
			description:  "Should allow rule when requirement is empty",
		},
		{
			name:         "complex version comparison with prereleases",
			agentVersion: "2.1.0-beta.1",
			requirement:  ">=2.0.0-alpha, <3.0.0-0",
			expected:     true,
			description:  "Should handle complex version comparisons with explicit prerelease bounds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set the environment variable
			if tt.agentVersion == "" {
				os.Unsetenv("AGENT_VERSION")
			} else {
				os.Setenv("AGENT_VERSION", tt.agentVersion)
			}

			result := isAgentVersionCompatible(tt.requirement)
			if result != tt.expected {
				t.Errorf("isAgentVersionCompatible(%q) with AGENT_VERSION=%q = %v, want %v\nDescription: %s",
					tt.requirement, tt.agentVersion, result, tt.expected, tt.description)
			}
		})
	}
}

func TestIsAgentVersionCompatible_EdgeCases(t *testing.T) {
	originalVersion := os.Getenv("AGENT_VERSION")
	defer func() {
		if originalVersion == "" {
			os.Unsetenv("AGENT_VERSION")
		} else {
			os.Setenv("AGENT_VERSION", originalVersion)
		}
	}()

	// Test with various malformed versions
	malformedTests := []struct {
		name         string
		agentVersion string
		requirement  string
		expected     bool
	}{
		{
			name:         "version with v prefix",
			agentVersion: "v1.2.3",
			requirement:  ">=1.2.0",
			expected:     true, // semver library should handle v prefix
		},
		{
			name:         "version without patch",
			agentVersion: "1.2",
			requirement:  ">=1.2.0",
			expected:     true, // should work with missing patch
		},
		{
			name:         "requirement with spaces",
			agentVersion: "1.2.3",
			requirement:  " >= 1.2.0 ",
			expected:     true, // should handle whitespace
		},
		{
			name:         "version with extra dots",
			agentVersion: "1.2.3.4",
			requirement:  ">=1.2.0",
			expected:     true, // should handle build versions
		},
	}

	for _, tt := range malformedTests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("AGENT_VERSION", tt.agentVersion)
			result := isAgentVersionCompatible(tt.requirement)
			if result != tt.expected {
				t.Errorf("isAgentVersionCompatible(%q) with AGENT_VERSION=%q = %v, want %v",
					tt.requirement, tt.agentVersion, result, tt.expected)
			}
		})
	}
}

// Benchmark the version compatibility function
func BenchmarkIsAgentVersionCompatible(b *testing.B) {
	os.Setenv("AGENT_VERSION", "1.2.3")
	requirement := ">=1.2.0, <2.0.0"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isAgentVersionCompatible(requirement)
	}
}

// Test that ensures the function doesn't panic with various inputs
func TestIsAgentVersionCompatible_NoPanic(t *testing.T) {
	originalVersion := os.Getenv("AGENT_VERSION")
	defer func() {
		if originalVersion == "" {
			os.Unsetenv("AGENT_VERSION")
		} else {
			os.Setenv("AGENT_VERSION", originalVersion)
		}
	}()

	// Test inputs that might cause panics
	testInputs := []struct {
		agentVersion string
		requirement  string
	}{
		{"", ""},
		{"1.2.3", ""},
		{"", ">=1.2.0"},
		{"null", "null"},
		{"1.2.3", "!@#$%"},
		{"!@#$%", ">=1.2.0"},
		{"1.2.3", ">="},
		{"1.2.3", "<"},
		{"1.2.3", "~"},
		{"1.2.3", "^"},
		{"999999999999999999999999999.0.0", ">=1.0.0"},
		{"1.2.3", ">=999999999999999999999999999.0.0"},
	}

	for _, input := range testInputs {
		t.Run(input.agentVersion+"_"+input.requirement, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("isAgentVersionCompatible panicked with agentVersion=%q, requirement=%q: %v",
						input.agentVersion, input.requirement, r)
				}
			}()

			if input.agentVersion == "" {
				os.Unsetenv("AGENT_VERSION")
			} else {
				os.Setenv("AGENT_VERSION", input.agentVersion)
			}

			// Should not panic regardless of input
			_ = isAgentVersionCompatible(input.requirement)
		})
	}
}
