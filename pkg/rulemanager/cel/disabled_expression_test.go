package cel

import (
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A rule whose expression fails to compile must not go silent: the failure is
// cached (never retried), but every later evaluation attempt re-reports it,
// rate-limited per expression. Observed in the field: a selector-verb arity
// change left R0011/R0012 "enabled" with zero evaluations for days, with a
// single warning at first compile as the only trace.
func TestDisabledExpression_IsReportedAgainOnLaterAttempts(t *testing.T) {
	c, err := NewCEL(objectcache.NewObjectCacheMock(), config.Config{})
	require.NoError(t, err)

	// Wrong arity for the selector verb — exactly the field failure.
	bad := `cp.was_selector_in_egress(event.containerId, event.dstNamespace)`

	// First attempt: compile fails, cached as disabled (nil program), error returned.
	prg, err := c.getOrCreateProgram(bad)
	assert.Nil(t, prg)
	assert.Error(t, err, "first compile reports the failure")
	c.disabledMu.Lock()
	_, loggedAtFirst := c.disabledLoggedAt[bad]
	c.disabledMu.Unlock()
	assert.False(t, loggedAtFirst, "the first compile logs via the compile path, not the re-report path")

	// Second attempt: served from the cache — no recompile, but it MUST be re-reported.
	prg, err = c.getOrCreateProgram(bad)
	assert.Nil(t, prg)
	assert.NoError(t, err, "cached failure is not retried (unchanged behaviour)")
	c.disabledMu.Lock()
	first, ok := c.disabledLoggedAt[bad]
	c.disabledMu.Unlock()
	require.True(t, ok, "a cached compile failure must be re-reported on a later evaluation attempt")

	// Third attempt inside the interval: rate-limited (timestamp unchanged).
	prg, _ = c.getOrCreateProgram(bad)
	assert.Nil(t, prg)
	c.disabledMu.Lock()
	second := c.disabledLoggedAt[bad]
	c.disabledMu.Unlock()
	assert.Equal(t, first, second, "re-reports are rate-limited to once per interval")

	// After the interval elapses it is reported again.
	c.disabledMu.Lock()
	c.disabledLoggedAt[bad] = time.Now().Add(-disabledLogInterval - time.Second)
	c.disabledMu.Unlock()
	prg, _ = c.getOrCreateProgram(bad)
	assert.Nil(t, prg)
	c.disabledMu.Lock()
	third := c.disabledLoggedAt[bad]
	c.disabledMu.Unlock()
	assert.True(t, third.After(first), "once the interval has passed the disabled rule is reported again")

	// A valid expression is unaffected and never enters the disabled ledger.
	good := `event.pktType == 'OUTGOING'`
	prg, err = c.getOrCreateProgram(good)
	assert.NoError(t, err)
	assert.NotNil(t, prg)
	c.disabledMu.Lock()
	_, inLedger := c.disabledLoggedAt[good]
	c.disabledMu.Unlock()
	assert.False(t, inLedger)
}
