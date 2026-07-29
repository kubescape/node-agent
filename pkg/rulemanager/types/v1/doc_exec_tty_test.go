package types

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"

	"sigs.k8s.io/yaml"
)

// TestExecTTYDocRuleYAMLIsParseable keeps docs/features/exec-tty-field.md
// honest. That doc's example rule YAML was fixed by human review from
// snake_case keys (rule_expression, event_type) to the camelCase keys node-agent
// actually parses (ruleExpression, eventType); with the wrong keys the rule
// loads without error but its expression list silently unmarshals to empty, so
// the rule never fires. Nothing guarded that regression, so this test extracts
// every fenced ```yaml block from the doc and asserts each one unmarshals into
// the real Rule type with a non-empty rule-expression list whose entry carries
// a non-empty event type — exactly what the snake_case bug would have failed.
func TestExecTTYDocRuleYAMLIsParseable(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file location via runtime.Caller")
	}

	// pkg/rulemanager/types/v1 -> repo root is four levels up.
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..")
	docPath := filepath.Join(repoRoot, "docs", "features", "exec-tty-field.md")

	content, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read documented rule example at %s: %v", docPath, err)
	}

	blocks := extractYAMLBlocks(string(content))
	if len(blocks) == 0 {
		t.Fatal("no yaml code blocks found in docs/features/exec-tty-field.md")
	}

	for i, block := range blocks {
		block := block
		t.Run("block", func(t *testing.T) {
			// The example in the doc is a YAML sequence fragment (a single
			// list item), matching the shape of RulesSpec.Rules ([]Rule), not
			// a whole Rules document. Unmarshal into []Rule directly.
			var rules []Rule
			if err := yaml.Unmarshal([]byte(block), &rules); err != nil {
				t.Fatalf("yaml block %d did not parse as []Rule: %v\n---\n%s", i, err, block)
			}

			if len(rules) == 0 {
				t.Fatalf("yaml block %d parsed but yielded zero rules:\n%s", i, block)
			}

			for _, r := range rules {
				if len(r.Expressions.RuleExpression) == 0 {
					t.Fatalf("rule %q parsed with an empty RuleExpression list — this is exactly"+
						" the symptom of the snake_case key bug (rule_expression/event_type instead"+
						" of ruleExpression/eventType), where the YAML parses without error but the"+
						" expressions are silently dropped:\n%s", r.Name, block)
				}
				for _, re := range r.Expressions.RuleExpression {
					if re.EventType == "" {
						t.Fatalf("rule %q has a RuleExpression with an empty EventType — same"+
							" snake_case symptom (event_type vs eventType):\n%s", r.Name, block)
					}
				}
			}
		})
	}
}

var yamlFenceRe = regexp.MustCompile("(?s)```ya?ml\\n(.*?)```")

// extractYAMLBlocks returns the content of every fenced ```yaml (or ```yml)
// code block in md.
func extractYAMLBlocks(md string) []string {
	matches := yamlFenceRe.FindAllStringSubmatch(md, -1)
	blocks := make([]string, 0, len(matches))
	for _, m := range matches {
		blocks = append(blocks, m[1])
	}
	return blocks
}
