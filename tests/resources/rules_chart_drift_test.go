package resources

import (
	"os"
	"strings"
	"testing"
)

// The standalone rules chart ships a copy of the test chart's rules; a drift
// between the two would deploy different detection semantics than CI validates.
func TestRulesChartMatchesTestChart(t *testing.T) {
	pairs := [][2]string{
		{"../chart/templates/node-agent/default-rules.yaml", "../../charts/kubescape-rules/templates/rules.yaml"},
		{"../chart/templates/node-agent/default-rule-binding.yaml", "../../charts/kubescape-rules/templates/binding.yaml"},
	}
	for _, p := range pairs {
		a, err := os.ReadFile(p[0])
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(p[1])
		if err != nil {
			t.Fatal(err)
		}
		got := strings.ReplaceAll(string(b), "{{ .Values.ksNamespace }}", "kubescape")
		if got != string(a) {
			t.Errorf("%s drifted from %s — regenerate the chart copy", p[1], p[0])
		}
	}
}
