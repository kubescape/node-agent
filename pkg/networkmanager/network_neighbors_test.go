package networkmanager

import (
	"testing"

	_ "embed"
)

func TestFilterLabels(t *testing.T) {
	tests := []struct {
		name           string
		labels         map[string]string
		expectedLabels map[string]string
	}{
		{
			name: "one label",
			labels: map[string]string{
				"test": "1",
			},
			expectedLabels: map[string]string{
				"test": "1",
			},
		},
		{
			name: "multiple labels",
			labels: map[string]string{
				"test":  "1",
				"test2": "2",
				"test3": "3",
			},
			expectedLabels: map[string]string{
				"test":  "1",
				"test2": "2",
				"test3": "3",
			},
		},
		{
			name: "multiple labels with one ignore label",
			labels: map[string]string{
				"controller-revision-hash": "1",
				"test":                     "1",
				"test2":                    "2",
			},
			expectedLabels: map[string]string{
				"test":  "1",
				"test2": "2",
			},
		},
		{
			name: "multiple labels with multiple  ignore labels",
			labels: map[string]string{
				"controller-revision-hash": "1",
				"pod-template-generation":  "1",
				"pod-template-hash":        "1",
				"test":                     "1",
				"test2":                    "2",
				"test3":                    "3",
			},
			expectedLabels: map[string]string{
				"test":  "1",
				"test2": "2",
				"test3": "3",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualLabels := FilterLabels(test.labels)
			if len(actualLabels) != len(test.expectedLabels) {
				t.Errorf("expected %d labels, got %d", len(test.expectedLabels), len(actualLabels))
			}

			for key, value := range test.expectedLabels {
				if actualLabels[key] != value {
					t.Errorf("expected label %s with value %s, got %s", key, value, actualLabels[key])
				}
			}
		})
	}
}
