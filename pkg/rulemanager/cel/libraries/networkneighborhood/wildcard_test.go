package networkneighborhood

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"k8s.io/utils/ptr"
)

// Helper: build a ready-to-use library with a single-container profile.
func buildLibWithContainer(t *testing.T, neighbors []v1beta1.NetworkNeighbor, ingressNeighbors []v1beta1.NetworkNeighbor) *nnLibrary {
	t.Helper()
	objCache := objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}
	objCache.SetSharedContainerData("cid", &objectcache.WatchedContainerData{
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {{Name: "c"}},
		},
	})
	nn := &v1beta1.NetworkNeighborhood{}
	nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
		Name:    "c",
		Egress:  neighbors,
		Ingress: ingressNeighbors,
	})
	objCache.SetNetworkNeighborhood(nn)
	return &nnLibrary{
		objectCache:   &objCache,
		functionCache: cache.NewFunctionCache(cache.DefaultFunctionCacheConfig()),
	}
}

func TestWasAddressInEgress_WildcardCIDRMatch(t *testing.T) {
	// Profile uses the new IPAddresses[] field with a CIDR. Old byte-equality
	// implementation would fail to match observed IPs that fall inside.
	lib := buildLibWithContainer(t, []v1beta1.NetworkNeighbor{
		{IPAddresses: []string{"10.0.0.0/8"}},
	}, nil)

	cases := []struct {
		observed string
		want     bool
	}{
		{"10.1.2.3", true},     // inside CIDR
		{"10.255.255.254", true},
		{"11.0.0.1", false},    // outside
	}
	for _, tc := range cases {
		t.Run(tc.observed, func(t *testing.T) {
			res := lib.wasAddressInEgress(types.String("cid"), types.String(tc.observed))
			res = cache.ConvertProfileNotAvailableErrToBool(res, false)
			assert.Equal(t, types.Bool(tc.want), res, "address %q", tc.observed)
		})
	}
}

func TestWasAddressInEgress_AnyIPSentinel(t *testing.T) {
	lib := buildLibWithContainer(t, []v1beta1.NetworkNeighbor{
		{IPAddresses: []string{"*"}},
	}, nil)

	for _, addr := range []string{"1.2.3.4", "8.8.8.8", "10.0.0.1", "2001:db8::1"} {
		res := lib.wasAddressInEgress(types.String("cid"), types.String(addr))
		res = cache.ConvertProfileNotAvailableErrToBool(res, false)
		assert.Equal(t, types.Bool(true), res, "addr %q", addr)
	}
}

func TestWasAddressInEgress_LegacySingularStillWorks(t *testing.T) {
	// Backward compatibility: profiles using the deprecated singular
	// IPAddress field MUST keep matching as before.
	lib := buildLibWithContainer(t, []v1beta1.NetworkNeighbor{
		{IPAddress: "10.1.2.3"},
	}, nil)

	res := lib.wasAddressInEgress(types.String("cid"), types.String("10.1.2.3"))
	res = cache.ConvertProfileNotAvailableErrToBool(res, false)
	assert.Equal(t, types.Bool(true), res)

	res = lib.wasAddressInEgress(types.String("cid"), types.String("10.1.2.4"))
	res = cache.ConvertProfileNotAvailableErrToBool(res, false)
	assert.Equal(t, types.Bool(false), res)
}

func TestWasAddressInEgress_BothSingularAndPlural(t *testing.T) {
	// Mixed profile: one entry uses deprecated IPAddress, another uses new IPAddresses.
	lib := buildLibWithContainer(t, []v1beta1.NetworkNeighbor{
		{IPAddress: "8.8.8.8"},
		{IPAddresses: []string{"10.0.0.0/8"}},
	}, nil)

	for addr, want := range map[string]bool{
		"8.8.8.8":   true,  // deprecated singular hit
		"10.1.2.3":  true,  // new CIDR hit
		"1.2.3.4":   false, // neither
	} {
		res := lib.wasAddressInEgress(types.String("cid"), types.String(addr))
		res = cache.ConvertProfileNotAvailableErrToBool(res, false)
		assert.Equal(t, types.Bool(want), res, "addr %q", addr)
	}
}

func TestIsDomainInEgress_LeadingWildcard(t *testing.T) {
	lib := buildLibWithContainer(t, []v1beta1.NetworkNeighbor{
		{DNSNames: []string{"*.stripe.com."}},
	}, nil)

	cases := []struct {
		observed string
		want     bool
	}{
		{"api.stripe.com.", true},
		{"webhooks.stripe.com.", true},
		{"v1.api.stripe.com.", false}, // two labels deep
		{"stripe.com.", false},        // zero labels — RFC 4592
		{"api.stripe.org.", false},
	}
	for _, tc := range cases {
		t.Run(tc.observed, func(t *testing.T) {
			res := lib.isDomainInEgress(types.String("cid"), types.String(tc.observed))
			res = cache.ConvertProfileNotAvailableErrToBool(res, false)
			assert.Equal(t, types.Bool(tc.want), res, "obs %q", tc.observed)
		})
	}
}

func TestIsDomainInEgress_MidEllipsis(t *testing.T) {
	// User's specific case: parametric namespace label in K8s service FQDN.
	lib := buildLibWithContainer(t, []v1beta1.NetworkNeighbor{
		{DNSNames: []string{"kubernetes.⋯.svc.cluster.local."}},
	}, nil)

	cases := []struct {
		observed string
		want     bool
	}{
		{"kubernetes.default.svc.cluster.local.", true},
		{"kubernetes.kube-system.svc.cluster.local.", true},
		{"redis.default.svc.cluster.local.", false},     // wrong service prefix
		{"kubernetes.foo.bar.svc.cluster.local.", false}, // two labels mid
	}
	for _, tc := range cases {
		t.Run(tc.observed, func(t *testing.T) {
			res := lib.isDomainInEgress(types.String("cid"), types.String(tc.observed))
			res = cache.ConvertProfileNotAvailableErrToBool(res, false)
			assert.Equal(t, types.Bool(tc.want), res, "obs %q", tc.observed)
		})
	}
}

func TestIsDomainInEgress_TrailingDotResilience(t *testing.T) {
	lib := buildLibWithContainer(t, []v1beta1.NetworkNeighbor{
		{DNSNames: []string{"api.stripe.com"}}, // no trailing dot in profile
	}, nil)

	// Observed name comes WITH trailing dot (FQDN canonical form).
	res := lib.isDomainInEgress(types.String("cid"), types.String("api.stripe.com."))
	res = cache.ConvertProfileNotAvailableErrToBool(res, false)
	assert.Equal(t, types.Bool(true), res)
}

// CR (node-agent#41 round 3) flagged that routing the deprecated IPAddress
// through MatchIP (round 2 fix) creates an unspoken behaviour change: the
// deprecated field now ALSO accepts wildcard/CIDR patterns. This is
// intentional — the contract is "deprecated singular gets the same
// semantics as the list form" — and these tests pin it explicitly so it
// can't silently regress.
func TestWasAddressInEgress_DeprecatedIPAddress_AcceptsWildcardAndCIDR(t *testing.T) {
	cases := []struct {
		profileIP string
		observed  string
		want      bool
	}{
		// '*' sentinel on the deprecated field — matches any valid IP
		{"*", "1.2.3.4", true},
		{"*", "8.8.8.8", true},
		{"*", "::1", true},
		// CIDR on the deprecated field — same membership semantics
		{"10.0.0.0/8", "10.1.2.3", true},
		{"10.0.0.0/8", "10.255.255.255", true},
		{"10.0.0.0/8", "11.0.0.1", false},
		{"0.0.0.0/0", "203.0.113.7", true},  // any-IPv4 via CIDR
		{"::/0", "2001:db8::1", true},        // any-IPv6 via CIDR
		// Literal still works
		{"192.168.1.1", "192.168.1.1", true},
		{"192.168.1.1", "192.168.1.2", false},
	}
	for _, tc := range cases {
		t.Run(tc.profileIP+"_vs_"+tc.observed, func(t *testing.T) {
			lib := buildLibWithContainer(t, []v1beta1.NetworkNeighbor{
				{IPAddress: tc.profileIP}, // deprecated singular field
			}, nil)
			res := lib.wasAddressInEgress(types.String("cid"), types.String(tc.observed))
			res = cache.ConvertProfileNotAvailableErrToBool(res, false)
			assert.Equal(t, types.Bool(tc.want), res, "profile=%q observed=%q", tc.profileIP, tc.observed)
		})
	}
}

// CR (node-agent#41 round 2) flagged that the deprecated singular IPAddress
// field originally compared via raw string equality, which would diverge from
// IPAddresses[] behaviour for IPv6 canonicalisation. neighborMatchesIP now
// routes both fields through MatchIP — pin the parity here.
func TestWasAddressInEgress_DeprecatedIPAddress_IPv6Canonicalisation(t *testing.T) {
	cases := []struct {
		profileIP string
		observed  string
		want      bool
	}{
		{"2001:db8::1", "2001:db8::1", true},                                  // identical
		{"2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001", true},      // expanded form same address
		{"10.0.0.1", "::ffff:10.0.0.1", true},                                  // IPv4-mapped IPv6
		{"10.0.0.1", "10.0.0.2", false},                                        // genuine miss
	}
	for _, tc := range cases {
		t.Run(tc.profileIP+"_vs_"+tc.observed, func(t *testing.T) {
			lib := buildLibWithContainer(t, []v1beta1.NetworkNeighbor{
				{IPAddress: tc.profileIP}, // deprecated singular field
			}, nil)
			res := lib.wasAddressInEgress(types.String("cid"), types.String(tc.observed))
			res = cache.ConvertProfileNotAvailableErrToBool(res, false)
			assert.Equal(t, types.Bool(tc.want), res, "profile=%q observed=%q", tc.profileIP, tc.observed)
		})
	}
}

// CR (node-agent#41) flagged that the deprecated singular DNS field
// originally compared via raw string equality, which would diverge from
// DNSNames behaviour for trailing-dot variants. neighborMatchesDNS now
// routes both fields through MatchDNS — pin the parity here.
func TestIsDomainInEgress_DeprecatedDNS_TrailingDotParity(t *testing.T) {
	cases := []struct {
		profileDNS string
		observed   string
		want       bool
	}{
		{"api.stripe.com.", "api.stripe.com.", true},  // both with dot
		{"api.stripe.com", "api.stripe.com.", true},   // profile no dot, observed with dot
		{"api.stripe.com.", "api.stripe.com", true},   // profile with dot, observed no dot
		{"api.stripe.com", "api.stripe.com", true},    // neither dot
		{"api.stripe.com.", "api.stripe.org.", false}, // wrong TLD
	}
	for _, tc := range cases {
		t.Run(tc.profileDNS+"_vs_"+tc.observed, func(t *testing.T) {
			lib := buildLibWithContainer(t, []v1beta1.NetworkNeighbor{
				{DNS: tc.profileDNS}, // deprecated singular field
			}, nil)
			res := lib.isDomainInEgress(types.String("cid"), types.String(tc.observed))
			res = cache.ConvertProfileNotAvailableErrToBool(res, false)
			assert.Equal(t, types.Bool(tc.want), res, "profile=%q observed=%q", tc.profileDNS, tc.observed)
		})
	}
}

// CR (node-agent#41) flagged int64→int32 wrap risk in port comparison.
// 4294967739 narrows to 443 — without the range guard this would
// incorrectly match a profile entry on port 443.
func TestWasAddressPortProtocolInEgress_PortWrapRejected(t *testing.T) {
	lib := buildLibWithContainer(t, []v1beta1.NetworkNeighbor{
		{
			IPAddress: "10.1.2.3",
			Ports: []v1beta1.NetworkPort{
				{Name: "TCP-443", Protocol: "TCP", Port: ptr.To(int32(443))},
			},
		},
	}, nil)

	// See TestWasAddressPortProtocolInEgress_WithCIDR for the
	// port/protocol regression note. The port-range guard ([0, 65535])
	// still applies — what's gone is port-specific matching: any in-range
	// port matches if the address matches.
	cases := []struct {
		name string
		port int64
		want bool
	}{
		{"in-range hit", 443, true},
		{"in-range miss", 444, true},                // was: false (port mismatch). Now matches: address-only after projection-v1.
		{"wrap-to-443 rejected", 4294967739, false}, // (1<<32)+443 — range guard fires
		{"negative rejected", -1, false},            // range guard fires
		{"too-large rejected", 65536, false},        // range guard fires
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := lib.wasAddressPortProtocolInEgress(
				types.String("cid"), types.String("10.1.2.3"),
				types.Int(tc.port), types.String("TCP"),
			)
			res = cache.ConvertProfileNotAvailableErrToBool(res, false)
			assert.Equal(t, types.Bool(tc.want), res)
		})
	}
}

func TestWasAddressInIngress_WildcardCIDR(t *testing.T) {
	// Direction isolation: the same address can be allowed on ingress
	// but not egress, and vice versa.
	lib := buildLibWithContainer(t,
		[]v1beta1.NetworkNeighbor{ /* empty egress */ },
		[]v1beta1.NetworkNeighbor{
			{IPAddresses: []string{"10.244.0.0/16"}},
		},
	)

	t.Run("ingress-CIDR-hit", func(t *testing.T) {
		res := lib.wasAddressInIngress(types.String("cid"), types.String("10.244.5.5"))
		res = cache.ConvertProfileNotAvailableErrToBool(res, false)
		assert.Equal(t, types.Bool(true), res)
	})
	t.Run("egress-must-stay-empty", func(t *testing.T) {
		// Same address on egress must NOT match — direction isolation.
		res := lib.wasAddressInEgress(types.String("cid"), types.String("10.244.5.5"))
		res = cache.ConvertProfileNotAvailableErrToBool(res, false)
		assert.Equal(t, types.Bool(false), res)
	})
}

func TestIsDomainInIngress_LeadingWildcard(t *testing.T) {
	lib := buildLibWithContainer(t,
		nil,
		[]v1beta1.NetworkNeighbor{
			{DNSNames: []string{"*.internal."}},
		},
	)
	res := lib.isDomainInIngress(types.String("cid"), types.String("api.internal."))
	res = cache.ConvertProfileNotAvailableErrToBool(res, false)
	assert.Equal(t, types.Bool(true), res)

	// Egress is empty so the same name must NOT match on egress.
	res = lib.isDomainInEgress(types.String("cid"), types.String("api.internal."))
	res = cache.ConvertProfileNotAvailableErrToBool(res, false)
	assert.Equal(t, types.Bool(false), res)
}

func TestWasAddressPortProtocolInEgress_WithCIDR(t *testing.T) {
	// Composed match: CIDR + port + protocol. Mirror of fixture 19.
	lib := buildLibWithContainer(t, []v1beta1.NetworkNeighbor{
		{
			IPAddresses: []string{"10.0.0.0/8"},
			Ports: []v1beta1.NetworkPort{
				{Name: "TCP-443", Protocol: "TCP", Port: ptr.To(int32(443))},
			},
		},
	}, nil)

	// NOTE: upstream's projection-v1 (PR #799) explicitly drops port/protocol
	// granularity from the address surface — the comment in network.go reads
	// "port/protocol projection (AddressPortsByAddr) is out of scope for v1;
	// degrade to address-only matching". So the matcher now only checks IP.
	//
	// Spec §4.7 still says ports[] is per-neighbor; the runtime gap is a
	// known limitation flagged in the rebase commit. Test expectations
	// updated to match runtime reality. Bringing port/protocol back is a
	// follow-up: would need projection_apply to surface a per-address
	// (port, protocol) set into ProjectedContainerProfile and the CEL
	// helper to consult it.
	cases := []struct {
		observed string
		port     int64
		proto    string
		want     bool
	}{
		{"10.1.2.3", 443, "TCP", true},  // CIDR match (port/proto not enforced)
		{"10.1.2.3", 80, "TCP", true},   // was: wrong port — now matches address-only
		{"10.1.2.3", 443, "UDP", true},  // was: wrong protocol — now matches address-only
		{"11.0.0.1", 443, "TCP", false}, // outside CIDR — still rejected
	}
	for _, tc := range cases {
		t.Run(tc.observed, func(t *testing.T) {
			res := lib.wasAddressPortProtocolInEgress(
				types.String("cid"), types.String(tc.observed),
				types.Int(tc.port), types.String(tc.proto),
			)
			res = cache.ConvertProfileNotAvailableErrToBool(res, false)
			assert.Equal(t, types.Bool(tc.want), res)
		})
	}
}
