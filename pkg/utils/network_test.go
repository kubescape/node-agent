package utils

import (
	"fmt"
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGenerateNeighborsIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		input    v1beta1.NetworkNeighbor
		expected string
	}{
		{
			name: "external",
			input: v1beta1.NetworkNeighbor{
				Type:              "external",
				DNS:               "example.com",
				Ports:             []v1beta1.NetworkPort{{Name: "port1", Protocol: "TCP"}},
				PodSelector:       nil,
				NamespaceSelector: nil,
				IPAddress:         "192.168.1.1",
			},
			expected: "a13ce4ca8de4083d05986cdc9874c5bc75870f93a89363acc36e12511ceae5d8",
		},
		{
			name: "external - different IP has different identifier",
			input: v1beta1.NetworkNeighbor{
				Type:              "external",
				DNS:               "example.com",
				Ports:             []v1beta1.NetworkPort{{Name: "port1", Protocol: "TCP"}},
				PodSelector:       nil,
				NamespaceSelector: nil,
				IPAddress:         "192.168.1.3",
			},
			expected: "5e620390e1aa074ccca30576eb9e09db9254a07b1d6cef9b45d7f98a1f72c863",
		},
		{
			name: "internal",
			input: v1beta1.NetworkNeighbor{
				Type:              "internal",
				DNS:               "example.com",
				Ports:             []v1beta1.NetworkPort{{Name: "port1", Protocol: "TCP"}},
				PodSelector:       &v1.LabelSelector{MatchLabels: map[string]string{"app": "nginx"}},
				NamespaceSelector: nil,
				IPAddress:         "192.168.1.1",
			},
			expected: "fd41d439d5de80f684d53dc9682ca335f93f6f754031d6e3624a9772b8010680",
		},
		{
			name: "internal - different ports has same identifier",
			input: v1beta1.NetworkNeighbor{
				Type:              "internal",
				DNS:               "example.com",
				Ports:             []v1beta1.NetworkPort{{Name: "port2", Protocol: "udp"}},
				PodSelector:       &v1.LabelSelector{MatchLabels: map[string]string{"app": "nginx"}},
				NamespaceSelector: nil,
				IPAddress:         "192.168.1.1",
			},
			expected: "fd41d439d5de80f684d53dc9682ca335f93f6f754031d6e3624a9772b8010680",
		},
		{
			name: "internal - different pod labels has different identifier",
			input: v1beta1.NetworkNeighbor{
				Type:              "internal",
				DNS:               "example.com",
				Ports:             []v1beta1.NetworkPort{{Name: "port2", Protocol: "udp"}},
				PodSelector:       &v1.LabelSelector{MatchLabels: map[string]string{"app2": "nginx"}},
				NamespaceSelector: nil,
				IPAddress:         "192.168.1.1",
			},
			expected: "0848cb483e73375684bbc7333f64d74dfa13260fc9d9ff178cdead9b1f695944",
		},
		{
			name: "internal - different namespace labels has different identifier",
			input: v1beta1.NetworkNeighbor{
				Type:              "internal",
				DNS:               "example.com",
				Ports:             []v1beta1.NetworkPort{{Name: "port2", Protocol: "udp"}},
				PodSelector:       &v1.LabelSelector{MatchLabels: map[string]string{"app2": "nginx"}},
				NamespaceSelector: &v1.LabelSelector{MatchLabels: map[string]string{"app2": "nginx"}},
				IPAddress:         "192.168.1.1",
			},
			expected: "d4e9bce7335a0eee24b725edb9de785fecfebad7bfc4f2ea4a49830925b745da",
		},
		{
			name: "internal - different dns has different identifier",
			input: v1beta1.NetworkNeighbor{
				Type:              "internal",
				DNS:               "another.co m",
				Ports:             []v1beta1.NetworkPort{{Name: "port2", Protocol: "udp"}},
				PodSelector:       &v1.LabelSelector{MatchLabels: map[string]string{"app2": "nginx"}},
				NamespaceSelector: nil,
				IPAddress:         "192.168.1.1",
			},
			expected: "f3dd4abe5311abc6ab3768182af5a15cb96746dd82573a744e2132d9ac90f52d",
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("Input: %s", tc.name), func(t *testing.T) {
			result, err := GenerateNeighborsIdentifier(tc.input)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetNamespaceMatchLabels(t *testing.T) {
	tests := []struct {
		name                 string
		destinationNamespace string
		sourceNamespace      string
		expected             map[string]string
	}{
		{
			name:                 "same namespace - should not have namespace selector",
			destinationNamespace: "default",
			sourceNamespace:      "default",
			expected:             nil,
		},
		{
			name:                 "different namespace - should have the destination namespace as selector",
			sourceNamespace:      "default",
			destinationNamespace: "kubescape",
			expected:             map[string]string{"kubernetes.io/metadata.name": "kubescape"},
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("Input: %s", tc.name), func(t *testing.T) {
			result := GetNamespaceMatchLabels(tc.destinationNamespace, tc.sourceNamespace)
			assert.Equal(t, tc.expected, result)
		})
	}
}
