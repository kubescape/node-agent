package applicationprofile

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/parse"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

// TestR0001_BusyboxAppletCollision reproduces the system-test failure for
// basic_incident_presented on busybox-based images (e.g. malware-redis-v3).
//
// Scenario: during the learning phase the test runs busybox applets
// (`wget --help`, `more /etc/passwd`). The container-profile records execs by
// the kernel-authoritative exepath, which for any busybox applet is the single
// binary /bin/busybox. Later the test runs an *unexpected* `cat /etc/hosts`,
// which the kernel also reports with exepath=/bin/busybox and args[0]=/bin/cat.
//
// R0001 "Unexpected process launched" exists in two variants (see
// ~/Desktop/rules.yaml, both id: R0001):
//
//	#1 (exepath-guarded): !ap.was_executed(args[0]) && (exepath=="" || !ap.was_executed(exepath))
//	#2 (simple):          !ap.was_executed(args[0])
//
// This test asserts that variant #1 is SUPPRESSED for the busybox cat (because
// /bin/busybox was already whitelisted), while variant #2 would still fire —
// confirming that the deployed node-agent uses variant #1 and that is why no
// "Unexpected process launched" incident reached the backend.
func TestR0001_BusyboxAppletCollision(t *testing.T) {
	const containerID = "test-container-id"

	objCache := objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}
	objCache.SetSharedContainerData(containerID, &objectcache.WatchedContainerData{
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {{Name: "redis"}},
		},
	})

	// Profile as recorded during learning: busybox applets collapse to the
	// single /bin/busybox binary (resolveExecPath prefers exepath).
	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name: "redis",
		Execs: []v1beta1.ExecCalls{
			{Path: "/bin/busybox", Args: []string{"/bin/wget", "--help"}},
			{Path: "/bin/busybox", Args: []string{"/bin/more", "/etc/passwd"}},
		},
	})
	objCache.SetApplicationProfile(profile)

	env, err := cel.NewEnv(
		cel.Variable("containerId", cel.StringType),
		cel.Variable("args", cel.ListType(cel.StringType)),
		cel.Variable("comm", cel.StringType),
		cel.Variable("exepath", cel.StringType),
		AP(&objCache, config.Config{}),
		parse.Parse(config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	eval := func(t *testing.T, expr string, vars map[string]any) bool {
		t.Helper()
		ast, issues := env.Compile(expr)
		if issues != nil && issues.Err() != nil {
			t.Fatalf("compile %q: %v", expr, issues.Err())
		}
		prg, err := env.Program(ast)
		if err != nil {
			t.Fatalf("program %q: %v", expr, err)
		}
		out, _, err := prg.Eval(vars)
		if err != nil {
			t.Fatalf("eval %q: %v", expr, err)
		}
		return out.Value().(bool)
	}

	const (
		exprExepathGuarded = `!ap.was_executed(containerId, parse.get_exec_path(args, comm)) && ` +
			`(exepath == "" || !ap.was_executed(containerId, exepath))`
		exprSimple = `!ap.was_executed(containerId, parse.get_exec_path(args, comm))`
		// Variant #3: prefer exepath, else args[0] — symmetric with the
		// recording-side resolveExecPath (exepath -> args[0] -> comm).
		exprExepathPreferred = `!ap.was_executed(containerId, ` +
			`(exepath != "" ? exepath : parse.get_exec_path(args, comm)))`
	)

	// The unexpected `cat /etc/hosts` exec as reported by the kernel for a
	// busybox applet.
	catEvent := map[string]any{
		"containerId": containerID,
		"args":        []string{"/bin/cat", "/etc/hosts"},
		"comm":        "cat",
		"exepath":     "/bin/busybox",
	}

	t.Run("control: was_executed lookups", func(t *testing.T) {
		assert.False(t, eval(t, `ap.was_executed(containerId, "/bin/cat")`, catEvent),
			"/bin/cat must NOT be in the profile (rule-side lookup uses args[0])")
		assert.True(t, eval(t, `ap.was_executed(containerId, "/bin/busybox")`, catEvent),
			"/bin/busybox MUST be in the profile (whitelisted during learning)")
	})

	t.Run("R0001 #1 exepath-guarded -> SUPPRESSED (matches observed prod behavior)", func(t *testing.T) {
		fired := eval(t, exprExepathGuarded, catEvent)
		assert.False(t, fired,
			"variant #1 should NOT fire: exepath /bin/busybox was already executed")
	})

	t.Run("R0001 #2 simple -> FIRES", func(t *testing.T) {
		fired := eval(t, exprSimple, catEvent)
		assert.True(t, fired,
			"variant #2 should fire: args[0] /bin/cat was never executed")
	})

	t.Run("R0001 #3 exepath-preferred (symmetric) -> SUPPRESSED", func(t *testing.T) {
		fired := eval(t, exprExepathPreferred, catEvent)
		assert.False(t, fired,
			"variant #3 should NOT fire: lookup keys on exepath /bin/busybox, which is whitelisted")
	})

	// Sanity: a genuinely-new, non-busybox binary must fire under BOTH variants,
	// proving the suppression above is specific to the busybox collision.
	t.Run("non-busybox new binary -> both fire", func(t *testing.T) {
		pyEvent := map[string]any{
			"containerId": containerID,
			"args":        []string{"/usr/bin/python3", "-c", "print(1)"},
			"comm":        "python3",
			"exepath":     "/usr/bin/python3",
		}
		assert.True(t, eval(t, exprExepathGuarded, pyEvent), "variant #1 should fire for a new binary")
		assert.True(t, eval(t, exprSimple, pyEvent), "variant #2 should fire for a new binary")
		assert.True(t, eval(t, exprExepathPreferred, pyEvent), "variant #3 should fire for a new binary")
	})
}
