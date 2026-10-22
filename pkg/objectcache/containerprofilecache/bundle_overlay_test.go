//go:build experimental_signing

package containerprofilecache

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func bkey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func bfrag(t *testing.T, name, class string, spec v1beta1.ContainerProfileSpec, key *ecdsa.PrivateKey) *v1beta1.ContainerProfile {
	t.Helper()
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "redis",
			Labels: map[string]string{
				bundle.LabelBundle:        "redis",
				bundle.LabelFragmentClass: class,
			},
		},
		Spec: spec,
	}
	if err := signature.SignObject(profiles.NewContainerProfileAdapter(cp), signature.WithPrivateKey(key)); err != nil {
		t.Fatalf("sign %s: %v", name, err)
	}
	return cp
}

func newBundleCacheClient(mock storage.ProfileClient, policy *bundle.TrustPolicy, strict bool) *ContainerProfileCacheImpl {
	c := &ContainerProfileCacheImpl{
		storageClient: mock,
		rpcBudget:     time.Second,
		cfg:           config.Config{EnableSignatureVerification: strict},
	}
	c.SetBundleConfig(policy)
	return c
}

// end-to-end runtime path: list fragments from the (mock) store, verify each
// fragment, assemble the composite in-memory, and hand back a usable composite.
// node-agent does NOT sign the composite — it only verifies fragments.
func TestAssembleUserBundle_Runtime_HappyPath(t *testing.T) {
	vendor, operator := bkey(t), bkey(t)

	port := int32(6379)
	base := bfrag(t, "redis", "base", v1beta1.ContainerProfileSpec{
		Execs: []v1beta1.ExecCalls{{Path: "/opt/bitnami/redis/bin/redis-server", Args: []string{"redis-server"}}},
	}, vendor)
	adm := bfrag(t, "redis-ingress-client", "admission", v1beta1.ContainerProfileSpec{
		Ingress: []v1beta1.NetworkNeighbor{{
			Identifier:  "allowed-client",
			Type:        "internal",
			PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "redis-client"}},
			Ports:       []v1beta1.NetworkPort{{Name: "TCP-6379", Port: &port, Protocol: "TCP"}},
		}},
	}, operator)

	vendorID, err := bundle.SignerID(base)
	if err != nil {
		t.Fatal(err)
	}
	operatorID, err := bundle.SignerID(adm)
	if err != nil {
		t.Fatal(err)
	}
	policy := &bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{
		bundle.ClassBase:      {Signers: []string{vendorID}, AllowedSpecPaths: []string{"execs"}},
		bundle.ClassAdmission: {Signers: []string{operatorID}, AllowedSpecPaths: []string{"ingress"}},
	}}

	mock := &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{base, adm}}
	c := newBundleCacheClient(mock, policy, true)

	composite, err := c.assembleUserBundle(context.Background(), "redis", "redis", "wlid://c/cluster/redis/Pod/redis")
	if err != nil {
		t.Fatalf("assembleUserBundle: %v", err)
	}
	if composite == nil {
		t.Fatal("expected a composite, got nil")
	}
	if len(composite.Spec.Execs) != 1 || len(composite.Spec.Ingress) != 1 {
		t.Errorf("composite not assembled: execs=%d ingress=%d", len(composite.Spec.Execs), len(composite.Spec.Ingress))
	}
	// The composite is NOT signed on-cluster (node-agent only verifies fragments):
	// it is verified by construction and carries the assembled spec directly.
	// The composite's ResourceVersion is the bundle's Merkle root (stable content
	// hash) so the reconciler RV fast-skip works; re-assembly of unchanged
	// fragments must yield the same RV.
	if composite.ResourceVersion == "" {
		t.Error("composite.ResourceVersion must carry the bundle Merkle root")
	}
	again, err := c.assembleUserBundle(context.Background(), "redis", "redis", "wlid://c/cluster/redis/Pod/redis")
	if err != nil || again == nil {
		t.Fatalf("re-assembly failed: %v", err)
	}
	if again.ResourceVersion != composite.ResourceVersion {
		t.Errorf("re-assembly of unchanged fragments changed the root RV: %s vs %s", again.ResourceVersion, composite.ResourceVersion)
	}
}

// A single (non-fragment) user CP → assembleUserBundle returns (nil,nil) so the
// caller falls back to the single-CP path.
func TestAssembleUserBundle_Runtime_NotABundle(t *testing.T) {
	single := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "redis", Namespace: "redis"}, // no bundle/class labels
	}
	mock := &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{single}}
	c := newBundleCacheClient(mock, &bundle.TrustPolicy{}, false)

	composite, err := c.assembleUserBundle(context.Background(), "redis", "redis", "wlid")
	if err != nil || composite != nil {
		t.Errorf("want (nil,nil) for a non-bundle; got (%v,%v)", composite, err)
	}
}

// A tampered fragment → error + R1016 emitted.
func TestAssembleUserBundle_Runtime_TamperedEmitsR1016(t *testing.T) {
	vendor, operator := bkey(t), bkey(t)
	base := bfrag(t, "redis", "base", v1beta1.ContainerProfileSpec{
		Execs: []v1beta1.ExecCalls{{Path: "/bin/redis-server", Args: []string{"redis-server"}}},
	}, vendor)
	adm := bfrag(t, "redis-ingress-client", "admission", v1beta1.ContainerProfileSpec{
		Ingress: []v1beta1.NetworkNeighbor{{Identifier: "allowed-client", Type: "internal"}},
	}, operator)
	vendorID, _ := bundle.SignerID(base)
	operatorID, _ := bundle.SignerID(adm)
	policy := &bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{
		bundle.ClassBase:      {Signers: []string{vendorID}, AllowedSpecPaths: []string{"execs"}},
		bundle.ClassAdmission: {Signers: []string{operatorID}, AllowedSpecPaths: []string{"ingress"}},
	}}

	mock := &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{base, adm}}
	exporter := &captureExporter{}
	c := newBundleCacheClient(mock, policy, true)
	c.SetTamperAlertExporter(exporter)

	// 1. A clean assembly first establishes base as a KNOWN verified member.
	// R1016 fires only for a member that verified before and later fails — a
	// tampered-from-first-sight object is an unattributable non-member (skipped),
	// not a tamper, so tamper must be observed as a clean→bad transition.
	if _, err := c.assembleUserBundle(context.Background(), "redis", "redis", "wlid://c/cluster/redis/Pod/redis"); err != nil {
		t.Fatalf("clean assembly must succeed first: %v", err)
	}

	// 2. Tamper the stored base after it was verified.
	base.Spec.Execs[0].Path = "/bin/evil"

	// 3. Re-assemble: base is a known member that no longer verifies → refuse +
	// R1016.
	composite, err := c.assembleUserBundle(context.Background(), "redis", "redis", "wlid://c/cluster/redis/Pod/redis")
	if err == nil || composite != nil {
		t.Fatalf("want error + nil composite on tamper of a known member; got (%v,%v)", composite, err)
	}
	if got := len(exporter.ruleAlerts()); got != 1 {
		t.Errorf("want 1 R1016 alert on tampered bundle; got %d", got)
	}
}

// strippedListClient simulates the real storage server: List serves items from
// the metadata table WITHOUT the payload (spec-stripped); only Get returns the
// full object. Regression for the bug where assembly hashed the stripped items
// and flagged every signed fragment as tampered.
type strippedListClient struct {
	*storage.StorageHttpClientMock
}

func (s *strippedListClient) ListContainerProfiles(ctx context.Context, namespace string, opts metav1.ListOptions) (*v1beta1.ContainerProfileList, error) {
	full, err := s.StorageHttpClientMock.ListContainerProfiles(ctx, namespace, opts)
	if err != nil {
		return nil, err
	}
	out := &v1beta1.ContainerProfileList{}
	for _, item := range full.Items {
		stripped := v1beta1.ContainerProfile{ObjectMeta: *item.ObjectMeta.DeepCopy()}
		out.Items = append(out.Items, stripped)
	}
	return out, nil
}

func TestAssembleUserBundle_Runtime_SpecStrippedList(t *testing.T) {
	vendor, operator := bkey(t), bkey(t)
	base := bfrag(t, "redis", "base", v1beta1.ContainerProfileSpec{
		Execs: []v1beta1.ExecCalls{{Path: "/bin/redis-server", Args: []string{"redis-server"}}},
	}, vendor)
	adm := bfrag(t, "redis-ingress-client", "admission", v1beta1.ContainerProfileSpec{
		Ingress: []v1beta1.NetworkNeighbor{{Identifier: "allowed-client", Type: "internal"}},
	}, operator)
	vendorID, _ := bundle.SignerID(base)
	operatorID, _ := bundle.SignerID(adm)
	policy := &bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{
		bundle.ClassBase:      {Signers: []string{vendorID}, AllowedSpecPaths: []string{"execs"}},
		bundle.ClassAdmission: {Signers: []string{operatorID}, AllowedSpecPaths: []string{"ingress"}},
	}}

	mock := &strippedListClient{&storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{base, adm}}}
	c := newBundleCacheClient(mock, policy, true)

	composite, err := c.assembleUserBundle(context.Background(), "redis", "redis", "wlid://c/cluster/redis/Pod/redis")
	if err != nil {
		t.Fatalf("assembly must survive a spec-stripped List (fetch full fragments via Get): %v", err)
	}
	if composite == nil || len(composite.Spec.Execs) != 1 || len(composite.Spec.Ingress) != 1 {
		t.Fatalf("composite not assembled from full fragments: %+v", composite)
	}
}

// selectorIgnoringClient simulates the real storage server's List, which
// IGNORES the label selector and returns every CP in the namespace. Regression
// for the cross-bundle pickup bug: without client-side membership filtering,
// any bundle name assembled ALL class-labeled fragments in the namespace.
type selectorIgnoringClient struct {
	*storage.StorageHttpClientMock
}

func (s *selectorIgnoringClient) ListContainerProfiles(ctx context.Context, namespace string, _ metav1.ListOptions) (*v1beta1.ContainerProfileList, error) {
	return s.StorageHttpClientMock.ListContainerProfiles(ctx, namespace, metav1.ListOptions{})
}

func TestAssembleUserBundle_Runtime_SelectorIgnoredByStorage(t *testing.T) {
	vendor, operator := bkey(t), bkey(t)
	base := bfrag(t, "redis", "base", v1beta1.ContainerProfileSpec{
		Execs: []v1beta1.ExecCalls{{Path: "/bin/redis-server", Args: []string{"redis-server"}}},
	}, vendor)
	adm := bfrag(t, "redis-ingress-client", "admission", v1beta1.ContainerProfileSpec{
		Ingress: []v1beta1.NetworkNeighbor{{Identifier: "allowed-client", Type: "internal"}},
	}, operator)
	vendorID, _ := bundle.SignerID(base)
	operatorID, _ := bundle.SignerID(adm)
	policy := &bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{
		bundle.ClassBase:      {Signers: []string{vendorID}, AllowedSpecPaths: []string{"execs"}},
		bundle.ClassAdmission: {Signers: []string{operatorID}, AllowedSpecPaths: []string{"ingress"}},
	}}

	mock := &selectorIgnoringClient{&storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{base, adm}}}
	c := newBundleCacheClient(mock, policy, true)

	// Looking up a DIFFERENT bundle name in the same namespace must find NO
	// fragments (fall back to the single-CP path), not assemble redis's.
	composite, err := c.assembleUserBundle(context.Background(), "redis", "redis-client", "wlid://c/cluster/redis/Pod/client")
	if err != nil || composite != nil {
		t.Fatalf("foreign bundle name must resolve to no fragments; got (%v, %v)", composite, err)
	}

	// The real bundle still assembles from exactly its own fragments.
	composite, err = c.assembleUserBundle(context.Background(), "redis", "redis", "wlid://c/cluster/redis/Pod/redis")
	if err != nil || composite == nil {
		t.Fatalf("redis bundle must assemble: %v", err)
	}
	m, err := bundle.ManifestFromComposite(composite)
	if err != nil || len(m.Leaves) != 2 {
		t.Fatalf("composite must contain exactly redis's 2 fragments, got %v (%v)", m, err)
	}
}

// TestAssembleUserBundle_R1016_ReAlertsAfterRecovery pins that R1016 re-fires
// on a NEW tamper after a clean recovery — even when the tampered fragment set
// fingerprint recurs (delete/recreate resets resourceVersions). Regression for
// the dedup bug where a fingerprint key was stored but never cleared.
func TestAssembleUserBundle_R1016_ReAlertsAfterRecovery(t *testing.T) {
	vendor := bkey(t)
	mkOverlay := func(rv, path string) *v1beta1.ContainerProfile {
		cp := bfrag(t, "redis", "base", v1beta1.ContainerProfileSpec{Execs: []v1beta1.ExecCalls{{Path: path}}}, vendor)
		cp.ResourceVersion = rv
		return cp
	}
	base := mkOverlay("1", "/bin/ok")
	vendorID, _ := bundle.SignerID(base)
	policy := &bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{
		bundle.ClassBase: {Signers: []string{vendorID}, AllowedSpecPaths: []string{"execs"}},
	}}
	exporter := &captureExporter{}

	tamper := func(cp *v1beta1.ContainerProfile) {
		cp.Spec.Execs = append(cp.Spec.Execs, v1beta1.ExecCalls{Path: "/bin/evil"}) // break the signature
	}

	assembleWith := func(cp *v1beta1.ContainerProfile, c *ContainerProfileCacheImpl) {
		mock := &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{cp}}
		c.storageClient = mock
		c.assembleUserBundle(context.Background(), "redis", "redis", "wlid://c/cluster/redis/Pod/redis")
	}

	c := &ContainerProfileCacheImpl{rpcBudget: time.Second, cfg: config.Config{EnableSignatureVerification: true}}
	c.SetBundleConfig(policy)
	c.SetTamperAlertExporter(exporter)

	// 0. A clean assembly first makes the base slot a KNOWN verified member, so a
	// later verification failure is an attributable member-tamper (R1016) rather
	// than an unattributable non-member drop.
	assembleWith(mkOverlay("1", "/bin/ok"), c)
	if got := len(exporter.ruleAlerts()); got != 0 {
		t.Fatalf("clean establish: want 0 R1016, got %d", got)
	}
	// 1. tamper the known member → 1 alert
	t1 := mkOverlay("2", "/bin/ok")
	tamper(t1)
	assembleWith(t1, c)
	if got := len(exporter.ruleAlerts()); got != 1 {
		t.Fatalf("first tamper: want 1 R1016, got %d", got)
	}
	// 2. clean recovery → edge-trigger cleared, no new alert
	assembleWith(mkOverlay("3", "/bin/ok"), c)
	if got := len(exporter.ruleAlerts()); got != 1 {
		t.Fatalf("recovery must not add an alert: want 1, got %d", got)
	}
	// 3. NEW tamper after recovery → must re-alert
	t2 := mkOverlay("4", "/bin/ok")
	tamper(t2)
	assembleWith(t2, c)
	if got := len(exporter.ruleAlerts()); got != 2 {
		t.Fatalf("re-tamper after recovery: want 2 R1016, got %d", got)
	}
}

// bfragIn is bfrag with an explicit namespace and bundle name.
func bfragIn(t *testing.T, name, class, ns, bundleName string, spec v1beta1.ContainerProfileSpec, key *ecdsa.PrivateKey) *v1beta1.ContainerProfile {
	t.Helper()
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels: map[string]string{
				bundle.LabelBundle:        bundleName,
				bundle.LabelFragmentClass: class,
			},
		},
		Spec: spec,
	}
	if err := signature.SignObject(profiles.NewContainerProfileAdapter(cp), signature.WithPrivateKey(key)); err != nil {
		t.Fatalf("sign %s: %v", name, err)
	}
	return cp
}

// TestBundleComposite_IsEnforceableByTheRuleEngine pins the contract a bundle
// composite must satisfy to be enforced, end to end through the cache: from a
// pod carrying kubescape.io/user-defined-profile=<bundle> all the way to what
// the rule engine reads.
//
// The three things the rule engine actually consumes:
//
//  1. GetProjectedContainerProfile(containerID) != nil — rule_manager gates
//     every rule with profileDependency=Required on this ("profile_incomplete"
//     suppression otherwise). R0001 is such a rule, so a nil projection makes
//     it silent for EVERY comm, not just unlisted ones.
//  2. GetContainerProfileState == Completed/Full — a composite carries no
//     learning-lifecycle annotations, so the terminal state has to be forced
//     by the cache, not read off the object.
//  3. The projected Execs set is the union of the admissible fragments, and
//     nothing else — the union is what makes an overlay-only exec quiet and an
//     unlisted exec alert.
//
// It also pins the inverse: the composite must NOT carry kubescape.io/status.
// tryPopulateEntry treats any label-referenced CP that has that annotation as a
// LEARNED profile and drops it, so "stamping completion annotations on the
// composite" would disable the bundle path outright rather than enable it.
func TestBundleComposite_IsEnforceableByTheRuleEngine(t *testing.T) {
	vendor, operator := bkey(t), bkey(t)

	base := bfragIn(t, "b37-base", "base", "default", "b37", v1beta1.ContainerProfileSpec{
		Architectures: []string{"amd64"},
		Execs:         []v1beta1.ExecCalls{{Path: "/bin/sleep"}, {Path: "/usr/bin/curl"}},
		Syscalls:      []string{"close", "read"},
	}, vendor)
	overlay := bfragIn(t, "b37-overlay", "overlay", "default", "b37", v1beta1.ContainerProfileSpec{
		Execs: []v1beta1.ExecCalls{{Path: "/usr/bin/id"}},
	}, operator)

	vendorID, err := bundle.SignerID(base)
	require.NoError(t, err)
	operatorID, err := bundle.SignerID(overlay)
	require.NoError(t, err)
	policy := &bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{
		bundle.ClassBase:    {Signers: []string{vendorID}, AllowedSpecPaths: []string{"architectures", "execs", "syscalls"}},
		bundle.ClassOverlay: {Signers: []string{operatorID}, AllowedSpecPaths: []string{"execs"}},
	}}

	mock := &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{base, overlay}}
	c, k8s := newTestCache(t, mock)
	c.SetBundleConfig(policy)

	id := "container-b37"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-b37")
	ev := eventContainer(id)
	ev.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "b37"}
	require.NoError(t, c.addContainer(ev, context.Background()))

	assertComposite := func(stage string) {
		t.Helper()
		pcp := c.GetProjectedContainerProfile(id)
		require.NotNil(t, pcp, "%s: profile-dependent rules are gated on a non-nil projection", stage)

		state := c.GetContainerProfileState(id)
		require.NotNil(t, state, "%s: state must be published", stage)
		require.Equal(t, helpersv1.Completed, state.Status, "%s: composite must read as Completed", stage)
		require.Equal(t, helpersv1.Full, state.Completion, "%s: composite must read as Full", stage)

		for _, p := range []string{"/bin/sleep", "/usr/bin/curl", "/usr/bin/id"} {
			_, ok := pcp.Execs.Values[p]
			require.True(t, ok, "%s: %s must be in the projected union", stage, p)
		}
		_, unlisted := pcp.Execs.Values["/bin/ls"]
		require.False(t, unlisted, "%s: an exec in no fragment must not be in the projection", stage)
	}

	assertComposite("after add")

	// The composite must stay enforceable across reconciler refresh ticks: the
	// refresh path rebuilds from its own sources and must not degrade the entry
	// to a learning/partial state.
	c.refreshAllEntries(context.Background())
	assertComposite("after refresh")

	entry, ok := c.entries.Load(id)
	require.True(t, ok)
	require.NotNil(t, entry.UserCPRef, "the bundle name must be recorded so the reconciler re-assembles it")
	require.Equal(t, "b37", entry.UserCPRef.Name)

	// The composite is an AUTHORED profile: it must carry no learning-lifecycle
	// annotation, or tryPopulateEntry would discard it as a learned CP.
	composite, err := c.assembleUserBundle(context.Background(), "default", "b37", "wlid://c/cluster/default/Pod/b37")
	require.NoError(t, err)
	require.NotNil(t, composite)
	require.NotContains(t, composite.Annotations, helpersv1.StatusMetadataKey,
		"a composite carrying kubescape.io/status would be dropped as a learned profile")
	require.NotContains(t, composite.Annotations, helpersv1.CompletionMetadataKey,
		"completion annotations belong to learned profiles only")
}

func TestAssembleUserBundle_SyncChecksumTracksFragmentSet(t *testing.T) {
	vendor, operator := bkey(t), bkey(t)
	base := bfrag(t, "redis", "base", v1beta1.ContainerProfileSpec{
		Execs: []v1beta1.ExecCalls{{Path: "/bin/redis-server", Args: []string{"redis-server"}}},
	}, vendor)
	overlay := bfrag(t, "redis-ops", "overlay", v1beta1.ContainerProfileSpec{
		Execs: []v1beta1.ExecCalls{{Path: "/usr/bin/id", Args: []string{"id"}}},
	}, operator)

	vendorID, err := bundle.SignerID(base)
	if err != nil {
		t.Fatal(err)
	}
	operatorID, err := bundle.SignerID(overlay)
	if err != nil {
		t.Fatal(err)
	}
	policy := &bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{
		bundle.ClassBase:    {Signers: []string{vendorID}, AllowedSpecPaths: []string{"execs"}},
		bundle.ClassOverlay: {Signers: []string{operatorID}, AllowedSpecPaths: []string{"execs"}},
	}}

	assemble := func(frags ...*v1beta1.ContainerProfile) *v1beta1.ContainerProfile {
		mock := &storage.StorageHttpClientMock{ContainerProfiles: frags}
		c := newBundleCacheClient(mock, policy, true)
		composite, err := c.assembleUserBundle(context.Background(), "redis", "redis", "wlid://c/cluster/redis/Pod/redis")
		if err != nil {
			t.Fatalf("assembleUserBundle: %v", err)
		}
		if composite == nil {
			t.Fatal("expected a composite")
		}
		return composite
	}

	baseOnly := assemble(base)
	if got := baseOnly.Annotations[helpersv1.SyncChecksumMetadataKey]; got != baseOnly.ResourceVersion || got == "" {
		t.Fatalf("base-only SyncChecksum %q must equal the Merkle-root RV %q", got, baseOnly.ResourceVersion)
	}

	withOverlay := assemble(base, overlay)
	if got := withOverlay.Annotations[helpersv1.SyncChecksumMetadataKey]; got != withOverlay.ResourceVersion || got == "" {
		t.Fatalf("with-overlay SyncChecksum %q must equal the Merkle-root RV %q", got, withOverlay.ResourceVersion)
	}

	if baseOnly.Annotations[helpersv1.SyncChecksumMetadataKey] == withOverlay.Annotations[helpersv1.SyncChecksumMetadataKey] {
		t.Fatal("SyncChecksum must change when the fragment set changes, else the CEL was_executed cache never invalidates")
	}
}

func TestBundleTamperAfterLoad_KeepsLastVerifiedProfile(t *testing.T) {
	vendor, operator := bkey(t), bkey(t)

	base := bfragIn(t, "keep-base", "base", "default", "keepb", v1beta1.ContainerProfileSpec{
		Architectures: []string{"amd64"},
		Execs:         []v1beta1.ExecCalls{{Path: "/bin/sleep"}, {Path: "/usr/bin/curl"}},
	}, vendor)
	overlay := bfragIn(t, "keep-overlay", "overlay", "default", "keepb", v1beta1.ContainerProfileSpec{
		Execs: []v1beta1.ExecCalls{{Path: "/usr/bin/id"}},
	}, operator)

	vendorID, err := bundle.SignerID(base)
	require.NoError(t, err)
	operatorID, err := bundle.SignerID(overlay)
	require.NoError(t, err)
	policy := &bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{
		bundle.ClassBase:    {Signers: []string{vendorID}, AllowedSpecPaths: []string{"architectures", "execs"}},
		bundle.ClassOverlay: {Signers: []string{operatorID}, AllowedSpecPaths: []string{"execs"}},
	}}

	mock := &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{base, overlay}}
	c, k8s := newTestCache(t, mock)
	c.SetBundleConfig(policy)

	id := "container-keepb"
	primeSharedData(t, k8s, id, "wlid://cluster-a/namespace-default/deployment-keepb")
	ev := eventContainer(id)
	ev.K8s.PodLabels = map[string]string{helpersv1.UserDefinedProfileMetadataKey: "keepb"}
	require.NoError(t, c.addContainer(ev, context.Background()))

	before := c.GetProjectedContainerProfile(id)
	require.NotNil(t, before)
	for _, p := range []string{"/bin/sleep", "/usr/bin/curl", "/usr/bin/id"} {
		_, ok := before.Execs.Values[p]
		require.True(t, ok, "%s must be enforced before the tamper", p)
	}

	overlay.Spec.Execs = append(overlay.Spec.Execs, v1beta1.ExecCalls{Path: "/bin/backdoor"})

	c.refreshAllEntries(context.Background())

	after := c.GetProjectedContainerProfile(id)
	require.NotNil(t, after, "a tampered fragment must not leave the container without a profile")
	for _, p := range []string{"/bin/sleep", "/usr/bin/curl", "/usr/bin/id"} {
		_, ok := after.Execs.Values[p]
		require.True(t, ok, "%s must still be enforced from the last verified composite", p)
	}
	_, injected := after.Execs.Values["/bin/backdoor"]
	require.False(t, injected, "the tampered content must be refused")

	state := c.GetContainerProfileState(id)
	require.NotNil(t, state)
	require.Equal(t, helpersv1.Completed, state.Status, "the retained profile must stay enforceable")
}

// TestAssembleUserBundle_NonMemberInjection_Skipped pins the F1 fix: an object a
// namespace writer labels into the bundle but does not (and cannot) sign with a
// class-trusted key is a NON-MEMBER. It is skipped, the bundle still assembles
// from the genuine members, and it raises no R1016 (it was never a verified
// member, so a tamper alert would be unattributable). Previously such an object
// failed the whole bundle closed — a denial-of-service any namespace writer
// could trigger.
func TestAssembleUserBundle_NonMemberInjection_Skipped(t *testing.T) {
	vendor := bkey(t)
	base := bfrag(t, "redis", "base", v1beta1.ContainerProfileSpec{
		Execs: []v1beta1.ExecCalls{{Path: "/bin/redis-server", Args: []string{"redis-server"}}},
	}, vendor)
	vendorID, _ := bundle.SignerID(base)
	policy := &bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{
		bundle.ClassBase: {Signers: []string{vendorID}, AllowedSpecPaths: []string{"execs"}},
	}}

	// An UNSIGNED object an attacker labelled into the bundle.
	rogue := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rogue",
			Namespace: "redis",
			Labels: map[string]string{
				bundle.LabelBundle:        "redis",
				bundle.LabelFragmentClass: "base",
			},
		},
		Spec: v1beta1.ContainerProfileSpec{Execs: []v1beta1.ExecCalls{{Path: "/bin/evil"}}},
	}

	mock := &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{base, rogue}}
	exporter := &captureExporter{}
	c := newBundleCacheClient(mock, policy, true)
	c.SetTamperAlertExporter(exporter)

	composite, err := c.assembleUserBundle(context.Background(), "redis", "redis", "wlid://c/cluster/redis/Pod/redis")
	if err != nil || composite == nil {
		t.Fatalf("bundle must assemble from genuine members despite an injected non-member; got (%v,%v)", composite, err)
	}
	// The rogue exec must NOT be in the composite.
	for _, e := range composite.Spec.Execs {
		if e.Path == "/bin/evil" {
			t.Fatal("the injected non-member's content leaked into the composite")
		}
	}
	if got := len(exporter.ruleAlerts()); got != 0 {
		t.Errorf("an injected non-member is not a tamper of a verified member; want 0 R1016, got %d", got)
	}
}
