package containerprofile

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
)

// cpLibForEndpoints wires a containerProfileLibrary to a mock objectCache
// that returns the supplied ProjectedContainerProfile for any containerID.
// Reuses mockObjectCacheForPattern (defined in open_test.go) so the HTTP
// evaluators can be exercised as pure functions over a projected CP without
// a cluster.
func cpLibForEndpoints(pcp *objectcache.ProjectedContainerProfile) *containerProfileLibrary {
	return &containerProfileLibrary{objectCache: &mockObjectCacheForPattern{pcp: pcp}}
}

// endpointsPCP builds a pass-through (All=true) ProjectedContainerProfile
// whose Endpoints surface carries the given concrete values and patterns.
func endpointsPCP(values []string, patterns []string) *objectcache.ProjectedContainerProfile {
	vals := make(map[string]struct{}, len(values))
	for _, v := range values {
		vals[v] = struct{}{}
	}
	return &objectcache.ProjectedContainerProfile{
		Endpoints: objectcache.ProjectedField{
			All:      true,
			Values:   vals,
			Patterns: patterns,
		},
	}
}

func asBool(t *testing.T, v ref.Val) bool {
	t.Helper()
	b, ok := v.Value().(bool)
	if !ok {
		t.Fatalf("expected bool result, got %T (%v)", v.Value(), v)
	}
	return b
}

// TestWasEndpointAccessed pins path membership: a concrete value or a
// dynamic pattern in the projected Endpoints surface answers true; anything
// else (including an empty-endpoints CP) answers false.
func TestWasEndpointAccessed(t *testing.T) {
	pcp := endpointsPCP(
		[]string{"/v1/api/users", "http://api.example.com/health"},
		[]string{"/v1/api/orders/" + dynamicpathdetector.DynamicIdentifier},
	)
	empty := endpointsPCP(nil, nil)

	testCases := []struct {
		name     string
		pcp      *objectcache.ProjectedContainerProfile
		endpoint string
		want     bool
	}{
		{"concrete value matches", pcp, "/v1/api/users", true},
		{"url value matches", pcp, "http://api.example.com/health", true},
		{"dynamic pattern matches", pcp, "/v1/api/orders/42", true},
		{"no match", pcp, "/v1/api/secrets", false},
		{"empty-endpoints CP", empty, "/v1/api/users", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			lib := cpLibForEndpoints(tc.pcp)
			got := asBool(t, lib.wasEndpointAccessed(types.String("cid"), types.String(tc.endpoint)))
			if got != tc.want {
				t.Errorf("wasEndpointAccessed(%q) = %v, want %v", tc.endpoint, got, tc.want)
			}
		})
	}
}

// TestWasEndpointAccessedWithMethod pins the v1 degradation: method is
// type-checked but NOT matched (EndpointMethodsByPath is out of scope for
// projection-v1), so a method mismatch on a matching path still answers
// true. Path membership alone decides the result.
func TestWasEndpointAccessedWithMethod(t *testing.T) {
	pcp := endpointsPCP([]string{"/v1/api/users"}, nil)
	empty := endpointsPCP(nil, nil)

	testCases := []struct {
		name     string
		pcp      *objectcache.ProjectedContainerProfile
		endpoint string
		method   string
		want     bool
	}{
		{"path+method match", pcp, "/v1/api/users", "GET", true},
		{"method mismatch still true (v1 path-only)", pcp, "/v1/api/users", "DELETE", true},
		{"path no match", pcp, "/v1/api/secrets", "GET", false},
		{"empty-endpoints CP", empty, "/v1/api/users", "GET", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			lib := cpLibForEndpoints(tc.pcp)
			got := asBool(t, lib.wasEndpointAccessedWithMethod(
				types.String("cid"), types.String(tc.endpoint), types.String(tc.method)))
			if got != tc.want {
				t.Errorf("wasEndpointAccessedWithMethod(%q,%q) = %v, want %v", tc.endpoint, tc.method, got, tc.want)
			}
		})
	}
}

// TestWasEndpointAccessedWithMethods mirrors the single-method variant for
// the plural (list-of-methods) overload. Methods are parsed but not matched
// in v1; path membership decides.
func TestWasEndpointAccessedWithMethods(t *testing.T) {
	pcp := endpointsPCP([]string{"/v1/api/users"}, nil)
	empty := endpointsPCP(nil, nil)

	testCases := []struct {
		name     string
		pcp      *objectcache.ProjectedContainerProfile
		endpoint string
		methods  []string
		want     bool
	}{
		{"path match, methods parsed", pcp, "/v1/api/users", []string{"GET", "POST"}, true},
		{"methods mismatch still true (v1 path-only)", pcp, "/v1/api/users", []string{"DELETE"}, true},
		{"path no match", pcp, "/v1/api/secrets", []string{"GET"}, false},
		{"empty methods list, path match", pcp, "/v1/api/users", []string{}, true},
		{"empty-endpoints CP", empty, "/v1/api/users", []string{"GET"}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			lib := cpLibForEndpoints(tc.pcp)
			methods := types.DefaultTypeAdapter.NativeToValue(tc.methods)
			got := asBool(t, lib.wasEndpointAccessedWithMethods(
				types.String("cid"), types.String(tc.endpoint), methods))
			if got != tc.want {
				t.Errorf("wasEndpointAccessedWithMethods(%q,%v) = %v, want %v", tc.endpoint, tc.methods, got, tc.want)
			}
		})
	}
}

// TestWasEndpointAccessedWithPrefix exercises BOTH branches:
//   - pass-through (Endpoints.All=true): concrete Values are scanned with
//     strings.HasPrefix; patterns are also scanned in this branch.
//   - projection-active (Endpoints.All=false): PrefixHits is authoritative;
//     an absent key is treated as undeclared → false.
func TestWasEndpointAccessedWithPrefix(t *testing.T) {
	passthrough := endpointsPCP([]string{"/v1/api/users", "/v1/api/orders"}, []string{"/metrics/scrape"})

	projected := &objectcache.ProjectedContainerProfile{
		Endpoints: objectcache.ProjectedField{
			All:        false,
			PrefixHits: map[string]bool{"/v1/api": true, "/admin": false},
		},
	}
	empty := endpointsPCP(nil, nil)

	testCases := []struct {
		name   string
		pcp    *objectcache.ProjectedContainerProfile
		prefix string
		want   bool
	}{
		{"passthrough value prefix match", passthrough, "/v1/api", true},
		{"passthrough pattern prefix match", passthrough, "/metrics", true},
		{"passthrough boundary: full string as prefix", passthrough, "/v1/api/users", true},
		{"passthrough empty prefix matches all", passthrough, "", true},
		{"passthrough no match", passthrough, "/nope", false},
		{"projected prefix hit true", projected, "/v1/api", true},
		{"projected prefix hit false", projected, "/admin", false},
		{"projected undeclared prefix", projected, "/unknown", false},
		{"empty-endpoints CP", empty, "/v1/api", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			lib := cpLibForEndpoints(tc.pcp)
			got := asBool(t, lib.wasEndpointAccessedWithPrefix(types.String("cid"), types.String(tc.prefix)))
			if got != tc.want {
				t.Errorf("wasEndpointAccessedWithPrefix(%q) = %v, want %v", tc.prefix, got, tc.want)
			}
		})
	}
}

// TestWasEndpointAccessedWithSuffix mirrors the prefix test across both the
// pass-through scan branch and the projection-active SuffixHits branch.
func TestWasEndpointAccessedWithSuffix(t *testing.T) {
	passthrough := endpointsPCP([]string{"/v1/api/users.json", "/v1/api/report.csv"}, []string{"/health.check"})

	projected := &objectcache.ProjectedContainerProfile{
		Endpoints: objectcache.ProjectedField{
			All:        false,
			SuffixHits: map[string]bool{".json": true, ".xml": false},
		},
	}
	empty := endpointsPCP(nil, nil)

	testCases := []struct {
		name   string
		pcp    *objectcache.ProjectedContainerProfile
		suffix string
		want   bool
	}{
		{"passthrough value suffix match", passthrough, ".json", true},
		{"passthrough pattern suffix match", passthrough, ".check", true},
		{"passthrough boundary: full string as suffix", passthrough, "/v1/api/users.json", true},
		{"passthrough empty suffix matches all", passthrough, "", true},
		{"passthrough no match", passthrough, ".xml", false},
		{"projected suffix hit true", projected, ".json", true},
		{"projected suffix hit false", projected, ".xml", false},
		{"projected undeclared suffix", projected, ".yaml", false},
		{"empty-endpoints CP", empty, ".json", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			lib := cpLibForEndpoints(tc.pcp)
			got := asBool(t, lib.wasEndpointAccessedWithSuffix(types.String("cid"), types.String(tc.suffix)))
			if got != tc.want {
				t.Errorf("wasEndpointAccessedWithSuffix(%q) = %v, want %v", tc.suffix, got, tc.want)
			}
		})
	}
}

// TestWasHostAccessed pins host extraction from endpoints:
//   - URL-shaped endpoints match on parsed Host / Hostname.
//   - non-URL endpoints match on whole-token equality or a host+"/" /
//     host+":" boundary — a short host must NOT match a mid-path segment.
func TestWasHostAccessed(t *testing.T) {
	pcp := endpointsPCP(
		[]string{
			"http://api.example.com/v1/health",
			"db.internal:5432",
			"metrics.svc/scrape",
			"/v1/api/users",
		},
		nil,
	)
	empty := endpointsPCP(nil, nil)

	testCases := []struct {
		name string
		pcp  *objectcache.ProjectedContainerProfile
		host string
		want bool
	}{
		{"url host match", pcp, "api.example.com", true},
		{"host:port boundary match", pcp, "db.internal", true},
		{"host/path boundary match", pcp, "metrics.svc", true},
		{"short host must not match path segment", pcp, "api", false},
		{"no match", pcp, "unknown.host", false},
		{"empty-endpoints CP", empty, "api.example.com", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			lib := cpLibForEndpoints(tc.pcp)
			got := asBool(t, lib.wasHostAccessed(types.String("cid"), types.String(tc.host)))
			if got != tc.want {
				t.Errorf("wasHostAccessed(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

// TestHTTPEvaluatorsNilObjectCache confirms every HTTP evaluator returns a
// CEL error (not a panic) when the library has no objectCache wired.
func TestHTTPEvaluatorsNilObjectCache(t *testing.T) {
	lib := &containerProfileLibrary{objectCache: nil}
	cid := types.String("cid")
	s := types.String("x")
	list := types.DefaultTypeAdapter.NativeToValue([]string{"GET"})

	checks := []ref.Val{
		lib.wasEndpointAccessed(cid, s),
		lib.wasEndpointAccessedWithMethod(cid, s, s),
		lib.wasEndpointAccessedWithMethods(cid, s, list),
		lib.wasEndpointAccessedWithPrefix(cid, s),
		lib.wasEndpointAccessedWithSuffix(cid, s),
		lib.wasHostAccessed(cid, s),
	}
	for i, r := range checks {
		if !types.IsError(r) {
			t.Errorf("evaluator #%d with nil objectCache: expected error, got %v", i, r)
		}
	}
}
