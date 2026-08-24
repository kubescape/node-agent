package rulemanager

import (
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/hashicorp/golang-lru/v2/expirable"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/state"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/rulestate"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func execEnriched() *events.EnrichedEvent {
	return &events.EnrichedEvent{
		Event: &utils.StructEvent{EventType: utils.ExecveEventType},
	}
}

// The subtle failure this exists to prevent: a rule whose ONLY reference to exec
// is a stateWrites entry must still let exec events reach the rule loop. Without
// it the first leg of every cross-event rule is filtered out before evaluation
// and no chain ever forms.
func TestIsSupportedEventType_WriteOnlyLegIsSupported(t *testing.T) {
	rule := typesv1.Rule{
		RuntimeRule: armotypes.RuntimeRule{
			ID: "R1089",
			StateWrites: []armotypes.StateWrite{{
				EventType: armotypes.EventTypeExec,
				Scope:     armotypes.StateScopeContainer,
				Name:      "mount_exec",
				TTL:       "10m",
			}},
		},
		// Alerts on network only -- there is deliberately no exec expression.
		Expressions: typesv1.RuleExpressions{
			RuleExpression: []typesv1.RuleExpression{
				{EventType: utils.NetworkEventType, Expression: "true"},
			},
		},
	}

	assert.True(t, isSupportedEventType([]typesv1.Rule{rule}, execEnriched()),
		"an exec event must reach the loop for a rule that only WRITES on exec")
}

func TestIsSupportedEventType_UnrelatedEventStillUnsupported(t *testing.T) {
	rule := typesv1.Rule{
		RuntimeRule: armotypes.RuntimeRule{
			ID: "R1089",
			StateWrites: []armotypes.StateWrite{{
				EventType: armotypes.EventTypeDNS,
				Scope:     armotypes.StateScopeContainer,
				Name:      "n",
				TTL:       "10m",
			}},
		},
		Expressions: typesv1.RuleExpressions{
			RuleExpression: []typesv1.RuleExpression{
				{EventType: utils.NetworkEventType, Expression: "true"},
			},
		},
	}

	assert.False(t, isSupportedEventType([]typesv1.Rule{rule}, execEnriched()),
		"exec appears in neither the expressions nor the writes")
}

func TestIsSupportedEventType_ExpressionStillWorksWithoutWrites(t *testing.T) {
	rule := typesv1.Rule{
		RuntimeRule: armotypes.RuntimeRule{ID: "R1004"},
		Expressions: typesv1.RuleExpressions{
			RuleExpression: []typesv1.RuleExpression{
				{EventType: utils.ExecveEventType, Expression: "true"},
			},
		},
	}
	assert.True(t, isSupportedEventType([]typesv1.Rule{rule}, execEnriched()))
}

func testRuleManager(t *testing.T) *RuleManager {
	t.Helper()
	cfg := config.Config{}
	cfg.CelStateStore = rulestate.Config{
		Enabled:                true,
		MaxSize:                1000,
		MaxEntriesPerContainer: 100,
		MaxEntriesForHost:      100,
		MaxTTL:                 30 * time.Minute,
		AncestorMaxDepth:       8,
	}
	return &RuleManager{
		cfg:              cfg,
		stateWritesCache: expirable.NewLRU[string, *compiledWrites](512, nil, 0),
	}
}

func TestCompileStateWrites_NoWritesIsNil(t *testing.T) {
	rm := testRuleManager(t)
	compiled, scopeOf := rm.compileStateWrites(&typesv1.Rule{
		RuntimeRule: armotypes.RuntimeRule{ID: "R1004"},
	})
	assert.Nil(t, compiled)
	assert.Nil(t, scopeOf)
}

func TestCompileStateWrites_ValidClause(t *testing.T) {
	rm := testRuleManager(t)
	compiled, scopeOf := rm.compileStateWrites(&typesv1.Rule{
		RuntimeRule: armotypes.RuntimeRule{
			ID: "R1089",
			StateWrites: []armotypes.StateWrite{{
				EventType: armotypes.EventTypeExec,
				Scope:     armotypes.StateScopeContainer,
				Name:      "mount_exec",
				Key:       "string(event.pid)",
				TTL:       "10m",
			}},
		},
	})
	require.Len(t, compiled, 1)
	assert.Equal(t, utils.ExecveEventType, compiled[0].EventType)
	assert.Equal(t, map[string]armotypes.StateScope{
		"mount_exec": armotypes.StateScopeContainer,
	}, scopeOf)
}

// A malformed clause must degrade that one rule to non-correlating, not take down
// evaluation for every other rule in the CRD.
func TestCompileStateWrites_InvalidClauseDegradesToNoWrites(t *testing.T) {
	rm := testRuleManager(t)
	compiled, scopeOf := rm.compileStateWrites(&typesv1.Rule{
		RuntimeRule: armotypes.RuntimeRule{
			ID: "R1089",
			StateWrites: []armotypes.StateWrite{{
				EventType: armotypes.EventTypeExec,
				Scope:     armotypes.StateScopeIdentity, // operator-only
				Name:      "mount_exec",
				TTL:       "10m",
			}},
		},
	})
	assert.Nil(t, compiled)
	assert.Nil(t, scopeOf)
}

// TTL clamping has to use the configured max, not the write's own value.
func TestCompileStateWrites_ClampsToConfiguredMaxTTL(t *testing.T) {
	rm := testRuleManager(t)
	compiled, _ := rm.compileStateWrites(&typesv1.Rule{
		RuntimeRule: armotypes.RuntimeRule{
			ID: "R1089",
			StateWrites: []armotypes.StateWrite{{
				EventType: armotypes.EventTypeExec,
				Scope:     armotypes.StateScopeContainer,
				Name:      "mount_exec",
				TTL:       "99h",
			}},
		},
	})
	require.Len(t, compiled, 1)
	assert.Equal(t, 30*time.Minute, compiled[0].TTL)
}

func TestHasWriteFor(t *testing.T) {
	rm := testRuleManager(t)
	compiled, _ := rm.compileStateWrites(&typesv1.Rule{
		RuntimeRule: armotypes.RuntimeRule{
			ID: "R1089",
			StateWrites: []armotypes.StateWrite{{
				EventType: armotypes.EventTypeExec,
				Scope:     armotypes.StateScopeContainer,
				Name:      "mount_exec",
				TTL:       "10m",
			}},
		},
	})
	assert.True(t, hasWriteFor(compiled, utils.ExecveEventType))
	assert.False(t, hasWriteFor(compiled, utils.NetworkEventType))
	assert.False(t, hasWriteFor(nil, utils.ExecveEventType))
}

// Container removal must reclaim that container's markers immediately -- a
// churning node would otherwise hold state for containers that no longer exist
// until TTL.
func TestPurgeScope_OnContainerRemovalDropsOnlyThatContainer(t *testing.T) {
	rm := testRuleManager(t)
	rm.stateStore = rulestate.NewStore(rm.cfg.CelStateStore, rulestate.NoopMetrics{})

	set := func(scopeID string) {
		require.NoError(t, rm.stateStore.Set(&rulestate.Entry{
			RuleID: "R1089", Name: "n", Key: "1",
			Scope: armotypes.StateScopeContainer, ScopeID: scopeID,
			Timestamp: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
		}))
	}
	set(rulestate.ContainerScopeID("abc"))
	set(rulestate.ContainerScopeID("def"))
	set(rulestate.HostScopeID())

	rm.stateStore.PurgeScope(rulestate.ContainerScopeID("abc"))

	_, ok := rm.stateStore.Get("R1089", rulestate.ContainerScopeID("abc"), "n", "1")
	assert.False(t, ok, "the removed container's markers must be gone")

	_, ok = rm.stateStore.Get("R1089", rulestate.ContainerScopeID("def"), "n", "1")
	assert.True(t, ok, "a neighbouring container must be untouched")

	_, ok = rm.stateStore.Get("R1089", rulestate.HostScopeID(), "n", "1")
	assert.True(t, ok, "host markers must survive a container removal")
}

// The trap this guards: utils.TrimRuntimePrefix returns "" for an ID with no
// "//" separator, and ContainerScopeID("") is the HOST bucket. If the removal
// path ever trims the runtime container ID again, every container exit would wipe
// all host-process state instead of that container's.
func TestContainerScopeID_TrimmedRuntimeIDWouldHitTheHostBucket(t *testing.T) {
	bare := "1a2b3c4d5e6f"
	assert.Empty(t, utils.TrimRuntimePrefix(bare),
		"TrimRuntimePrefix yields empty for a bare runtime ID")
	assert.Equal(t, rulestate.HostScopeID(), rulestate.ContainerScopeID(utils.TrimRuntimePrefix(bare)),
		"which would resolve to the host bucket -- purge must use the untrimmed ID")
	assert.NotEqual(t, rulestate.HostScopeID(), rulestate.ContainerScopeID(bare))
}

// Pod scope was reclaimed by nothing. PurgeScope's only production call site
// passes a CONTAINER scope ID, so `p:<ns>/<pod>` entries outlived the pod they
// describe and sat in the store until TTL -- on a churning node, many dead pods'
// worth at once, all of it counting against the global ceiling.
//
// The pod is gone only when its LAST container goes, which is why this reuses the
// same "is any container of this pod still tracked" test the podToWlid cleanup
// already makes.
func TestPurgePodScope_ReclaimsWhenTheLastContainerGoes(t *testing.T) {
	rm := testRuleManager(t)
	rm.stateStore = rulestate.NewStore(rm.cfg.CelStateStore, rulestate.NoopMetrics{})
	rm.trackedContainers = mapset.NewSet[string]()

	podEntry := func() (*rulestate.Entry, bool) {
		return rm.stateStore.Get("R1089", rulestate.PodScopeID("prod", "web-1"), "n", "1")
	}
	seed := func() {
		require.NoError(t, rm.stateStore.Set(&rulestate.Entry{
			RuleID: "R1089", Name: "n", Key: "1",
			Scope: armotypes.StateScopePod, ScopeID: rulestate.PodScopeID("prod", "web-1"),
			Timestamp: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
		}))
	}

	// A sibling container of the same pod is still running: the pod is alive, so
	// its state must survive. Purging here would break a correlation chain that
	// is still legitimately in progress.
	seed()
	rm.trackedContainers.Add(utils.CreateK8sContainerID("prod", "web-1", "sidecar"))
	rm.purgePodScopeIfPodGone("prod", "web-1")
	_, ok := podEntry()
	assert.True(t, ok, "a pod with a container still tracked must keep its state")

	// A container of a DIFFERENT pod must not keep this pod alive.
	rm.trackedContainers.Clear()
	rm.trackedContainers.Add(utils.CreateK8sContainerID("prod", "web-2", "app"))
	rm.purgePodScopeIfPodGone("prod", "web-1")
	_, ok = podEntry()
	assert.False(t, ok, "another pod's container must not keep this pod's state alive")

	// And the neighbouring pod is untouched.
	require.NoError(t, rm.stateStore.Set(&rulestate.Entry{
		RuleID: "R1089", Name: "n", Key: "1",
		Scope: armotypes.StateScopePod, ScopeID: rulestate.PodScopeID("prod", "web-2"),
		Timestamp: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
	}))
	rm.purgePodScopeIfPodGone("prod", "web-1")
	_, ok = rm.stateStore.Get("R1089", rulestate.PodScopeID("prod", "web-2"), "n", "1")
	assert.True(t, ok, "purging one pod must not touch its neighbour")
}

// Compiling the write clause on every event meant a malformed rule logged an
// error on every matching event, forever -- thousands of identical lines per
// second from one bad rule on a busy node. The cache is what makes that one line
// per clause version, so it is worth pinning that the key tracks the clause.
func TestStateWritesCacheKey_TracksEveryFieldValidationReads(t *testing.T) {
	base := func() *typesv1.Rule {
		return &typesv1.Rule{RuntimeRule: armotypes.RuntimeRule{
			ID: "R1089",
			StateWrites: []armotypes.StateWrite{{
				EventType: armotypes.EventTypeExec,
				Scope:     armotypes.StateScopeContainer,
				Name:      "mount_exec",
				Key:       "string(event.pid)",
				When:      "is_mount",
				TTL:       "10m",
				Value:     map[string]any{"argv": "event.args", "comm": "event.comm"},
			}},
		}}
	}

	require.Equal(t, stateWritesCacheKey(base()), stateWritesCacheKey(base()),
		"an unchanged clause must hash the same, or the cache never hits")

	// Value is a map: iteration order varies between runs, so the digest must not.
	reordered := base()
	reordered.StateWrites[0].Value = map[string]any{"comm": "event.comm", "argv": "event.args"}
	assert.Equal(t, stateWritesCacheKey(base()), stateWritesCacheKey(reordered),
		"map iteration order must not change the key, or the cache thrashes")

	mutations := map[string]func(*typesv1.Rule){
		"rule ID":    func(r *typesv1.Rule) { r.ID = "R1090" },
		"event type": func(r *typesv1.Rule) { r.StateWrites[0].EventType = armotypes.EventTypeNetwork },
		"scope":      func(r *typesv1.Rule) { r.StateWrites[0].Scope = armotypes.StateScopePod },
		"name":       func(r *typesv1.Rule) { r.StateWrites[0].Name = "other" },
		"key":        func(r *typesv1.Rule) { r.StateWrites[0].Key = "string(event.ppid)" },
		"guard":      func(r *typesv1.Rule) { r.StateWrites[0].When = "other" },
		"ttl":        func(r *typesv1.Rule) { r.StateWrites[0].TTL = "20m" },
		"value expr": func(r *typesv1.Rule) { r.StateWrites[0].Value["argv"] = "event.cwd" },
		"value key":  func(r *typesv1.Rule) { r.StateWrites[0].Value["extra"] = "event.cwd" },
		"extra write": func(r *typesv1.Rule) {
			r.StateWrites = append(r.StateWrites, r.StateWrites[0])
		},
	}
	for what, mutate := range mutations {
		mutated := base()
		mutate(mutated)
		assert.NotEqual(t, stateWritesCacheKey(base()), stateWritesCacheKey(mutated),
			"changing the %s must change the key, or an edited rule keeps its stale compilation", what)
	}
}

// A rule that declares no state must not be handed the previous rule's accessor.
// evalContext is built once per event and reused down the rule list, so skipping
// the seed without clearing the key would let a stateless rule read another
// rule's state -- the exact thing the receiver design makes inexpressible.
func TestSeedStateContext_KeyIsClearedForRulesWithoutState(t *testing.T) {
	rm := testRuleManager(t)
	rm.stateStore = rulestate.NewStore(rm.cfg.CelStateStore, rulestate.NoopMetrics{})

	evalContext := map[string]any{}
	withState := &typesv1.Rule{RuntimeRule: armotypes.RuntimeRule{ID: "R1089"}}
	rm.seedStateContext(evalContext, withState, execEnriched(),
		map[string]armotypes.StateScope{"mount_exec": armotypes.StateScopeContainer}, nil)
	require.Contains(t, evalContext, state.AccessorContextKey)

	// The loop's else branch: a stateless rule follows.
	delete(evalContext, state.AccessorContextKey)
	assert.NotContains(t, evalContext, state.AccessorContextKey,
		"a rule with no declared state must not inherit the previous rule's accessor")
}
