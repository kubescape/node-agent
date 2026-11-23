package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRuntimeAlertRuleBindingRule_Equal(t *testing.T) {
	base := &RuntimeAlertRuleBindingRule{
		RuleName:   "Unexpected process",
		RuleID:     "R0001",
		Severity:   "High",
		RuleTags:   []string{"exec", "process"},
		Parameters: map[string]any{"allow": "/bin/sh"},
	}

	same := &RuntimeAlertRuleBindingRule{
		RuleName:   "Unexpected process",
		RuleID:     "R0001",
		Severity:   "High",
		RuleTags:   []string{"exec", "process"},
		Parameters: map[string]any{"allow": "/bin/sh"},
	}
	assert.True(t, base.Equal(same))

	diffName := *base
	diffName.RuleName = "Other"
	assert.False(t, base.Equal(&diffName))

	diffID := *base
	diffID.RuleID = "R0002"
	assert.False(t, base.Equal(&diffID))

	diffTags := *base
	diffTags.RuleTags = []string{"network"}
	assert.False(t, base.Equal(&diffTags))

	diffSeverity := *base
	diffSeverity.Severity = "Low"
	assert.False(t, base.Equal(&diffSeverity))

	diffParams := *base
	diffParams.Parameters = map[string]any{"allow": "/usr/bin/bash"}
	assert.False(t, base.Equal(&diffParams))
}
