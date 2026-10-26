package cache_test

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/objectcache/containerprofilecache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/containerprofile"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/containerprofilenetwork"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type projectedProfileCache struct {
	objectcache.ContainerProfileCacheMock
	profile *objectcache.ProjectedContainerProfile
}

func (c *projectedProfileCache) GetProjectedContainerProfile(string) *objectcache.ProjectedContainerProfile {
	return c.profile
}

type profileObjectCache struct {
	objectcachev1.RuleObjectCacheMock
	profiles *projectedProfileCache
}

func (c *profileObjectCache) ContainerProfileCache() objectcache.ContainerProfileCache {
	return c.profiles
}

func TestCELHelpersInvalidateWithoutSyncChecksum(t *testing.T) {
	for _, expr := range []string{
		`cp.was_path_opened("host", "/etc/passwd")`,
		`cp.was_capability_used("host", "SYS_PTRACE")`,
		`cp.was_address_in_egress("host", "192.0.2.1")`,
	} {
		t.Run(expr, func(t *testing.T) {
			profiles := &projectedProfileCache{}
			oc := &profileObjectCache{profiles: profiles}
			env, err := cel.NewEnv(containerprofile.CP(oc, config.Config{}), containerprofilenetwork.CPNetwork(oc, config.Config{}))
			require.NoError(t, err)
			ast, issues := env.Compile(expr)
			require.NoError(t, issues.Err())
			program, err := env.Program(ast)
			require.NoError(t, err)
			spec := &objectcache.RuleProjectionSpec{Hash: "same-rules"}
			evaluate := func(want bool) {
				t.Helper()
				// Repeated evaluations also exercise the cached path.
				for range 2 {
					result, _, err := program.Eval(map[string]any{})
					require.NoError(t, err)
					require.Equal(t, want, result.Value())
				}
			}
			authored := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "authored-a"}}
			profiles.profile = containerprofilecache.Apply(spec, authored, nil)
			evaluate(false)

			// Same identity and no checksum: a content update must invalidate false.
			authored.Spec.Capabilities = []string{"SYS_PTRACE"}
			authored.Spec.Opens = []v1beta1.OpenCalls{{Path: "/etc/passwd"}}
			authored.Spec.Egress = []v1beta1.NetworkNeighbor{{IPAddress: "192.0.2.1"}}
			profiles.profile = containerprofilecache.Apply(spec, authored, nil)
			evaluate(true)

			// Rebinding to another authored profile must invalidate true.
			rebound := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "authored-b"}}
			profiles.profile = containerprofilecache.Apply(spec, rebound, nil)
			evaluate(false)

			// Removing then restoring the binding must not retain the absent result.
			profiles.profile = nil
			evaluate(false)
			profiles.profile = containerprofilecache.Apply(spec, authored, nil)
			evaluate(true)
		})
	}
}
