package containerprofilenetwork

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

// TestIsDomainInEgress_NoMatchWildcardAndEmpty exercises the non-happy
// paths of isDomainInEgress that the existing happy-only tests miss:
// a domain absent from the neighborhood, a leading-wildcard match, a
// "*" catch-all, an empty-neighborhood profile, and a container whose
// profile is unavailable (ProfileNotAvailableErr -> false).
func TestIsDomainInEgress_NoMatchWildcardAndEmpty(t *testing.T) {
	lib := buildLibWithContainer(t, []v1beta1.NetworkNeighbor{
		{DNSNames: []string{"*.example.com.", "static.internal."}},
	}, nil)

	cases := []struct {
		name   string
		cid    string
		domain string
		want   bool
	}{
		{"leading wildcard matches one label", "cid", "api.example.com.", true},
		{"literal domain matches", "cid", "static.internal.", true},
		{"wildcard rejects two labels", "cid", "v1.api.example.com.", false},
		{"no match", "cid", "evil.other.com.", false},
		{"profile unavailable -> false", "missing-cid", "api.example.com.", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := lib.isDomainInEgress(types.String(tc.cid), types.String(tc.domain))
			res = cache.ConvertProfileNotAvailableErrToBool(res, false)
			assert.Equal(t, types.Bool(tc.want), res, "domain %q", tc.domain)
		})
	}
}

// TestIsDomainInIngress_NoMatchWildcardAndEmpty mirrors the egress domain
// coverage for the ingress direction: leading-wildcard match, no-match,
// empty-neighborhood and profile-unavailable.
func TestIsDomainInIngress_NoMatchWildcardAndEmpty(t *testing.T) {
	lib := buildLibWithContainer(t, nil, []v1beta1.NetworkNeighbor{
		{DNSNames: []string{"*.svc.cluster.local."}},
	})

	// Leading wildcard: exactly one label matches.
	res := lib.isDomainInIngress(types.String("cid"), types.String("redis.svc.cluster.local."))
	res = cache.ConvertProfileNotAvailableErrToBool(res, false)
	assert.Equal(t, types.Bool(true), res, "leading wildcard should match one label")

	// No match against the wildcard.
	res = lib.isDomainInIngress(types.String("cid"), types.String("redis.other.local."))
	res = cache.ConvertProfileNotAvailableErrToBool(res, false)
	assert.Equal(t, types.Bool(false), res, "domain outside wildcard should not match")

	// Empty neighborhood: no ingress declared at all -> false.
	emptyLib := buildLibWithContainer(t, nil, nil)
	res = emptyLib.isDomainInIngress(types.String("cid"), types.String("anything.example.com."))
	res = cache.ConvertProfileNotAvailableErrToBool(res, false)
	assert.Equal(t, types.Bool(false), res, "empty ingress neighborhood should not match")

	// Profile unavailable -> false.
	res = lib.isDomainInIngress(types.String("missing-cid"), types.String("x.example.com."))
	res = cache.ConvertProfileNotAvailableErrToBool(res, false)
	assert.Equal(t, types.Bool(false), res, "profile unavailable should be false")
}

// TestWasAddressInEgress_NoMatchAndEmpty covers no-match, empty-neighborhood
// and profile-unavailable branches for the egress address matcher.
func TestWasAddressInEgress_NoMatchAndEmpty(t *testing.T) {
	lib := buildLibWithContainer(t, []v1beta1.NetworkNeighbor{
		{IPAddresses: []string{"10.0.0.5"}},
	}, nil)

	cases := []struct {
		name    string
		cid     string
		address string
		want    bool
	}{
		{"exact match", "cid", "10.0.0.5", true},
		{"no match", "cid", "10.0.0.6", false},
		{"empty observed address", "cid", "", false},
		{"profile unavailable -> false", "missing-cid", "10.0.0.5", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := lib.wasAddressInEgress(types.String(tc.cid), types.String(tc.address))
			res = cache.ConvertProfileNotAvailableErrToBool(res, false)
			assert.Equal(t, types.Bool(tc.want), res, "address %q", tc.address)
		})
	}

	// Empty egress neighborhood -> false.
	emptyLib := buildLibWithContainer(t, nil, nil)
	res := emptyLib.wasAddressInEgress(types.String("cid"), types.String("10.0.0.5"))
	res = cache.ConvertProfileNotAvailableErrToBool(res, false)
	assert.Equal(t, types.Bool(false), res, "empty egress neighborhood should not match")
}

// TestWasAddressInIngress_NoMatchAndEmpty covers no-match, empty-neighborhood
// and profile-unavailable branches for the ingress address matcher.
func TestWasAddressInIngress_NoMatchAndEmpty(t *testing.T) {
	lib := buildLibWithContainer(t, nil, []v1beta1.NetworkNeighbor{
		{IPAddresses: []string{"172.16.0.9"}},
	})

	cases := []struct {
		name    string
		cid     string
		address string
		want    bool
	}{
		{"exact match", "cid", "172.16.0.9", true},
		{"no match", "cid", "172.16.0.10", false},
		{"profile unavailable -> false", "missing-cid", "172.16.0.9", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := lib.wasAddressInIngress(types.String(tc.cid), types.String(tc.address))
			res = cache.ConvertProfileNotAvailableErrToBool(res, false)
			assert.Equal(t, types.Bool(tc.want), res, "address %q", tc.address)
		})
	}

	emptyLib := buildLibWithContainer(t, nil, nil)
	res := emptyLib.wasAddressInIngress(types.String("cid"), types.String("172.16.0.9"))
	res = cache.ConvertProfileNotAvailableErrToBool(res, false)
	assert.Equal(t, types.Bool(false), res, "empty ingress neighborhood should not match")
}

// TestNetworkMatchersNilObjectCache confirms the address/domain matchers
// return a CEL error (not a panic) when no objectCache is wired.
func TestNetworkMatchersNilObjectCache(t *testing.T) {
	lib := &containerProfileNetworkLibrary{objectCache: nil}
	assert.True(t, types.IsError(lib.wasAddressInEgress(types.String("cid"), types.String("1.2.3.4"))))
	assert.True(t, types.IsError(lib.wasAddressInIngress(types.String("cid"), types.String("1.2.3.4"))))
	assert.True(t, types.IsError(lib.isDomainInEgress(types.String("cid"), types.String("x.com."))))
	assert.True(t, types.IsError(lib.isDomainInIngress(types.String("cid"), types.String("x.com."))))
}
