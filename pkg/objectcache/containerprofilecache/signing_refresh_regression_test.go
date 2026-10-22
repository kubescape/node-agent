//go:build experimental_signing

package containerprofilecache

import (
	"context"
	"fmt"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
)

type signingFailureClient struct {
	*storage.StorageHttpClientMock
	failName string
}

func (s *signingFailureClient) GetContainerProfile(ctx context.Context, ns, name string) (*v1beta1.ContainerProfile, error) {
	if name == s.failName {
		return nil, fmt.Errorf("temporary fetch failure")
	}
	return s.StorageHttpClientMock.GetContainerProfile(ctx, ns, name)
}

func TestSigningReloadFetchFailure(t *testing.T) {
	for _, signed := range []bool{false, true} {
		for _, source := range []string{"learned", "authored"} {
			t.Run(fmt.Sprintf("signed=%t/%s", signed, source), func(t *testing.T) {
				cp := classicalCP("authored-nginx", "default", "/bin/authored")
				if signed {
					require.NoError(t, signature.SignObjectDisableKeyless(profiles.NewContainerProfileAdapter(cp)))
				}
				client := &signingFailureClient{StorageHttpClientMock: &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{cp}}}
				c, k8s := newTestCache(t, client)
				c.SetBundleConfig(&bundle.TrustPolicy{Mode: bundle.ModeAlert})
				primeSharedData(t, k8s, "id", "wlid://cluster-a/namespace-default/deployment-test")
				bindToProfile(t, c, "id", "authored")
				entry, ok := c.entries.Load("id")
				require.True(t, ok)
				require.True(t, execEnforced(c, "id", "/bin/authored"))
				client.failName = entry.CPName
				if source == "authored" {
					client.failName = entry.UserCPRef.Name
				}
				c.SetBundleConfig(&bundle.TrustPolicy{Mode: bundle.ModeEnforce})
				c.refreshAllEntries(context.Background())
				require.Equal(t, signed, execEnforced(c, "id", "/bin/authored"))
				current, ok := c.entries.Load("id")
				require.True(t, ok)
				require.Equal(t, entry.UserCPRef, current.UserCPRef)
			})
		}
	}
}

func TestSigningBundleInstalledAfterPerContainerProfile(t *testing.T) {
	for _, refuseFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("refusedFirst=%t", refuseFirst), func(t *testing.T) {
			cp := classicalCP("bundle37-nginx", "default", "/bin/flat")
			client := &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{cp}}
			c, k8s := newTestCache(t, client)
			primeSharedData(t, k8s, "id", "wlid://cluster-a/namespace-default/deployment-test")
			bindToProfile(t, c, "id", "bundle37")
			entry, ok := c.entries.Load("id")
			require.True(t, ok)
			require.Equal(t, "bundle37-nginx", entry.UserCPRef.Name)
			if refuseFirst {
				c.SetBundleConfig(&bundle.TrustPolicy{Mode: bundle.ModeEnforce})
				c.refreshAllEntries(context.Background())
				require.False(t, execEnforced(c, "id", "/bin/flat"))
			}
			key := bkey(t)
			base := bfragIn(t, "new-base", "base", "default", "bundle37", v1beta1.ContainerProfileSpec{Execs: []v1beta1.ExecCalls{{Path: "/bin/bundle"}}}, key)
			signer, err := bundle.SignerID(base)
			require.NoError(t, err)
			client.ContainerProfiles = append(client.ContainerProfiles, base)
			c.SetBundleConfig(&bundle.TrustPolicy{Mode: bundle.ModeEnforce, Classes: map[bundle.FragmentClass]bundle.ClassPolicy{bundle.ClassBase: {Signers: []string{signer}, AllowedSpecPaths: []string{"execs"}}}})
			c.refreshAllEntries(context.Background())
			require.True(t, execEnforced(c, "id", "/bin/bundle"))
			require.False(t, execEnforced(c, "id", "/bin/flat"))
			adopted, ok := c.entries.Load("id")
			require.True(t, ok)
			require.Equal(t, "bundle37-nginx", adopted.UserCPRef.Name)
		})
	}
}

func TestUnsignedAlertOnlyAfterAdoption(t *testing.T) {
	for _, shape := range []string{"missing-section", "learned", "adopted"} {
		t.Run(shape, func(t *testing.T) {
			cp := classicalCP("authored-nginx", "default", "/bin/authored")
			if shape == "missing-section" {
				cp.Spec.Containers = []v1beta1.ContainerProfileContainer{{Name: "other"}}
			}
			if shape == "learned" {
				cp.Annotations = map[string]string{helpersv1.StatusMetadataKey: helpersv1.Completed}
			}
			c, k8s := newTestCache(t, &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{cp}})
			exp := &captureExporter{}
			c.SetTamperAlertExporter(exp)
			primeSharedData(t, k8s, "id", "wlid://cluster-a/namespace-default/deployment-test")
			bindToProfile(t, c, "id", "authored")
			if shape == "adopted" {
				require.Len(t, exp.ruleAlerts(), 1)
				require.Equal(t, "R1018", exp.ruleAlerts()[0].GetRuleId())
			} else {
				require.Empty(t, exp.ruleAlerts())
			}
		})
	}
}

func TestSigningBundleFetchFailurePreservesOnlyCurrentPolicy(t *testing.T) {
	key := bkey(t)
	base := bfragIn(t, "base", "base", "default", "bundle37", v1beta1.ContainerProfileSpec{Execs: []v1beta1.ExecCalls{{Path: "/bin/bundle"}}}, key)
	signer, err := bundle.SignerID(base)
	require.NoError(t, err)
	policy := &bundle.TrustPolicy{Mode: bundle.ModeEnforce, Classes: map[bundle.FragmentClass]bundle.ClassPolicy{bundle.ClassBase: {Signers: []string{signer}, AllowedSpecPaths: []string{"execs"}}}}
	client := &signingFailureClient{StorageHttpClientMock: &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{base}}}
	c, k8s := newTestCache(t, client)
	c.SetBundleConfig(policy)
	primeSharedData(t, k8s, "id", "wlid://cluster-a/namespace-default/deployment-test")
	bindToProfile(t, c, "id", "bundle37")
	entry, ok := c.entries.Load("id")
	require.True(t, ok)
	client.failName = entry.CPName
	c.refreshAllEntries(context.Background())
	require.True(t, execEnforced(c, "id", "/bin/bundle"))
	replacement := *policy
	c.SetBundleConfig(&replacement)
	c.refreshAllEntries(context.Background())
	require.False(t, execEnforced(c, "id", "/bin/bundle"))
	client.failName = ""
	c.refreshAllEntries(context.Background())
	require.True(t, execEnforced(c, "id", "/bin/bundle"))
}

func TestUnsignedAlertOnlyAfterRefreshAdoption(t *testing.T) {
	for _, shape := range []string{"missing-section", "learned", "adopted"} {
		t.Run(shape, func(t *testing.T) {
			cp := classicalCP("authored-nginx", "default", "/bin/authored")
			client := &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{cp}}
			c, k8s := newTestCache(t, client)
			primeSharedData(t, k8s, "id", "wlid://cluster-a/namespace-default/deployment-test")
			bindToProfile(t, c, "id", "authored")
			exp := &captureExporter{}
			c.SetTamperAlertExporter(exp)
			if shape == "missing-section" {
				cp.Spec.Containers = []v1beta1.ContainerProfileContainer{{Name: "other"}}
			}
			if shape == "learned" {
				cp.Annotations = map[string]string{helpersv1.StatusMetadataKey: helpersv1.Completed}
			}
			c.refreshAllEntries(context.Background())
			if shape == "adopted" {
				require.Len(t, exp.ruleAlerts(), 1)
				require.Equal(t, "R1018", exp.ruleAlerts()[0].GetRuleId())
			} else {
				require.Empty(t, exp.ruleAlerts())
			}
		})
	}
}

func TestSigningRefusalRecoversWithEmptyResourceVersion(t *testing.T) {
	cp := classicalCP("authored-nginx", "default", "/bin/recovered")
	client := &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{cp}}
	c, k8s := newTestCache(t, client)
	primeSharedData(t, k8s, "id", "wlid://cluster-a/namespace-default/deployment-test")
	bindToProfile(t, c, "id", "authored")
	require.True(t, execEnforced(c, "id", "/bin/recovered"))
	c.SetBundleConfig(&bundle.TrustPolicy{Mode: bundle.ModeEnforce})
	c.refreshAllEntries(context.Background())
	require.False(t, execEnforced(c, "id", "/bin/recovered"))
	refused, ok := c.entries.Load("id")
	require.True(t, ok)
	require.Empty(t, refused.RV)
	require.Empty(t, refused.UserCPRV)
	require.Empty(t, refused.Checksum)
	require.NoError(t, signature.SignObjectDisableKeyless(profiles.NewContainerProfileAdapter(cp)))
	require.Empty(t, cp.ResourceVersion)
	c.refreshAllEntries(context.Background())
	require.True(t, execEnforced(c, "id", "/bin/recovered"), "successful re-signing must install the recovered grants despite unchanged empty RVs")
	recovered, ok := c.entries.Load("id")
	require.True(t, ok)
	require.Equal(t, helpersv1.Completed, recovered.State.Status)
	require.Equal(t, refused.UserCPRef, recovered.UserCPRef)
	// The restored projection stays usable on subsequent unchanged-source ticks.
	c.refreshAllEntries(context.Background())
	require.True(t, execEnforced(c, "id", "/bin/recovered"))
}

func TestSignedRefreshRebuildsChangedContentWithUnchangedResourceVersion(t *testing.T) {
	for _, rv := range []string{"", "unchanged"} {
		for _, initiallySigned := range []bool{false, true} {
			for _, failedSource := range []string{"learned", "authored"} {
				t.Run(fmt.Sprintf("rv=%s/signed=%t/failure=%s", rv, initiallySigned, failedSource), func(t *testing.T) {
					cp := classicalCP("authored-nginx", "default", "/bin/old")
					cp.ResourceVersion = rv
					if initiallySigned {
						require.NoError(t, signature.SignObjectDisableKeyless(profiles.NewContainerProfileAdapter(cp)))
					}
					client := &signingFailureClient{StorageHttpClientMock: &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{cp}}}
					c, k8s := newTestCache(t, client)
					c.SetBundleConfig(&bundle.TrustPolicy{Mode: bundle.ModeAlert})
					primeSharedData(t, k8s, "id", "wlid://cluster-a/namespace-default/deployment-test")
					bindToProfile(t, c, "id", "authored")
					require.True(t, execEnforced(c, "id", "/bin/old"))

					replacement := classicalCP("authored-nginx", "default", "/bin/signed")
					replacement.ResourceVersion = rv
					require.NoError(t, signature.SignObjectDisableKeyless(profiles.NewContainerProfileAdapter(replacement)))
					client.ContainerProfiles = []*v1beta1.ContainerProfile{replacement}
					c.refreshAllEntries(context.Background())
					require.False(t, execEnforced(c, "id", "/bin/old"), "newly verified content must replace the previous projection despite matching RVs")
					require.True(t, execEnforced(c, "id", "/bin/signed"))

					entry, ok := c.entries.Load("id")
					require.True(t, ok)
					client.failName = entry.CPName
					if failedSource == "authored" {
						client.failName = entry.UserCPRef.Name
					}
					c.SetBundleConfig(&bundle.TrustPolicy{Mode: bundle.ModeEnforce})
					c.refreshAllEntries(context.Background())
					require.False(t, execEnforced(c, "id", "/bin/old"))
					require.True(t, execEnforced(c, "id", "/bin/signed"), "fetch failure may retain only the projection built from authenticated content")
				})
			}
		}
	}
}
