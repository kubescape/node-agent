package containerprofile

import (
	"testing"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	functioncache "github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
)

func TestDNSBaselineMatching(t *testing.T) {
	for _, tc := range []struct {
		name, domain, path, version string
		truncated                   bool
		want                        bool
		wantErr                     bool
	}{
		{name: "same process", domain: "API.VENDOR.COM", path: "/app", version: "v1", want: true},
		{name: "different process", domain: "api.vendor.com.", path: "/usr/bin/python3", version: "v1"},
		{name: "new name", domain: "new.vendor.com.", path: "/app", version: "v1"},
		{name: "network baseline does not teach DNS", domain: "network-only.example.", path: "/app", version: "v1"},
		{name: "old profile", domain: "api.vendor.com.", path: "/app", wantErr: true},
		{name: "truncated", domain: "api.vendor.com.", path: "/app", version: "v1", truncated: true, wantErr: true},
		{name: "unknown executable", domain: "api.vendor.com.", version: "v1", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := &objectcachev1.RuleObjectCacheMock{}
			cache.SetContainerProfileState(&objectcache.ProfileState{Status: "completed", Completion: "complete"})
			cache.SetContainerProfile(&v1beta1.ContainerProfile{Spec: v1beta1.ContainerProfileSpec{DNSBaselineVersion: tc.version, DNSBaselineTruncated: tc.truncated, DNSLookups: []v1beta1.DNSLookup{{Name: "api.vendor.com.", ExePaths: []string{"/app"}}}, Egress: []v1beta1.NetworkNeighbor{{DNS: "network-only.example."}}}})
			env, err := cel.NewEnv(CP(cache, config.Config{}))
			require.NoError(t, err)
			ast, issues := env.Compile("cp.was_dns_resolved_by_process('container', '" + tc.domain + "', '" + tc.path + "')")
			require.NoError(t, issues.Err())
			program, err := env.Program(ast)
			require.NoError(t, err)
			result, _, err := program.Eval(map[string]any{})
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, result.Value())
			ast, issues = env.Compile("cp.was_dns_resolved('container', 'api.vendor.com.')")
			require.NoError(t, issues.Err())
			program, err = env.Program(ast)
			require.NoError(t, err)
			result, _, err = program.Eval(map[string]any{})
			require.NoError(t, err)
			require.Equal(t, true, result.Value())
		})
	}
}

func TestDNSBaselineRequiresCompletedFullProfile(t *testing.T) {
	for _, state := range []*objectcache.ProfileState{nil, {}, {Status: "ready", Completion: "complete"}, {Status: "too-large", Completion: "complete"}, {Status: "completed", Completion: "partial"}} {
		cache := &objectcachev1.RuleObjectCacheMock{}
		cache.SetContainerProfile(&v1beta1.ContainerProfile{Spec: v1beta1.ContainerProfileSpec{DNSBaselineVersion: "v1"}})
		cache.SetContainerProfileState(state)
		env, err := cel.NewEnv(CP(cache, config.Config{}))
		require.NoError(t, err)
		ast, issues := env.Compile("!cp.was_dns_resolved('container','new.example.')")
		require.NoError(t, issues.Err())
		program, err := env.Program(ast)
		require.NoError(t, err)
		_, _, err = program.Eval(map[string]any{})
		require.Error(t, err)
	}
}

func TestDNSBaselineReadinessRefreshBypassesResultCache(t *testing.T) {
	for _, expression := range []string{"!cp.was_dns_resolved('container','new.example.')", "!cp.was_dns_resolved_by_process('container','new.example.','/app')"} {
		for _, invalid := range []string{"truncated", "unversioned", "partial"} {
			t.Run(expression+"/"+invalid, func(t *testing.T) {
				cache := &objectcachev1.RuleObjectCacheMock{}
				cache.SetContainerProfileState(&objectcache.ProfileState{Status: "completed", Completion: "complete"})
				profile := &v1beta1.ContainerProfile{Spec: v1beta1.ContainerProfileSpec{DNSBaselineVersion: "v1"}}
				cache.SetContainerProfile(profile)
				env, err := cel.NewEnv(CP(cache, config.Config{CelConfigCache: functioncache.FunctionCacheConfig{MaxSize: 100, TTL: time.Hour}}))
				require.NoError(t, err)
				ast, issues := env.Compile(expression)
				require.NoError(t, issues.Err())
				program, err := env.Program(ast)
				require.NoError(t, err)
				result, _, err := program.Eval(map[string]any{})
				require.NoError(t, err)
				require.Equal(t, true, result.Value())
				switch invalid {
				case "truncated":
					profile.Spec.DNSBaselineTruncated = true
				case "unversioned":
					profile.Spec.DNSBaselineVersion = ""
				case "partial":
					cache.SetContainerProfileState(&objectcache.ProfileState{Status: "completed", Completion: "partial"})
				}
				cache.SetContainerProfile(profile)
				_, _, err = program.Eval(map[string]any{})
				require.Error(t, err, "refreshed unavailable baseline must not reuse cached false")
			})
		}
	}
}
