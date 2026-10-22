//go:build experimental_signing

package profiles

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	storagefile "github.com/kubescape/storage/pkg/registry/file"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// deflateSpec runs storage's write-path rewrite over a spec, exactly as
// ContainerProfileProcessor.PreSave does, and returns it as the versioned type
// the signature is computed over.
func deflateSpec(t *testing.T, in v1beta1.ContainerProfileSpec) v1beta1.ContainerProfileSpec {
	t.Helper()
	var internal softwarecomposition.ContainerProfileSpec
	require.NoError(t, v1beta1.Convert_v1beta1_ContainerProfileSpec_To_softwarecomposition_ContainerProfileSpec(&in, &internal, nil))
	deflated := storagefile.DeflateContainerProfileSpec(internal, mapset.NewSet[string](), dynamicpathdetector.DefaultCollapseSettings())
	var out v1beta1.ContainerProfileSpec
	require.NoError(t, v1beta1.Convert_softwarecomposition_ContainerProfileSpec_To_v1beta1_ContainerProfileSpec(&deflated, &out, nil))
	return out
}

func specJSON(t *testing.T, s v1beta1.ContainerProfileSpec) string {
	t.Helper()
	b, err := json.Marshal(s)
	require.NoError(t, err)
	return string(b)
}

func TestConversionAloneDoesNotDisturbASignedSpec(t *testing.T) {
	in := v1beta1.ContainerProfileSpec{
		Egress: []v1beta1.NetworkNeighbor{{Identifier: "peers", Type: v1beta1.CommunicationTypeEgress, IPAddresses: []string{"10.10.0.1"}}},
	}
	var internal softwarecomposition.ContainerProfileSpec
	require.NoError(t, v1beta1.Convert_v1beta1_ContainerProfileSpec_To_softwarecomposition_ContainerProfileSpec(&in, &internal, nil))
	var back v1beta1.ContainerProfileSpec
	require.NoError(t, v1beta1.Convert_softwarecomposition_ContainerProfileSpec_To_v1beta1_ContainerProfileSpec(&internal, &back, nil))
	require.Equal(t, specJSON(t, in), specJSON(t, back),
		"the internal/versioned round-trip must be lossless, or every result below measures the conversion instead of the deflate")
}

func TestDeflateIsAFixpointAfterOnePass(t *testing.T) {
	in := v1beta1.ContainerProfileSpec{
		Egress: []v1beta1.NetworkNeighbor{{Identifier: "peers", Type: v1beta1.CommunicationTypeEgress, IPAddresses: []string{"10.10.0.2", "10.10.0.1"}}},
	}
	once := deflateSpec(t, in)
	twice := deflateSpec(t, once)
	require.Equal(t, specJSON(t, once), specJSON(t, twice),
		"deflate must be idempotent, otherwise no authored document could ever be signed stably")
}

// entlein/node-agent#51. Storage deflates every ContainerProfile spec on write
// (ContainerProfileProcessor.PreSave, no provenance check) and the signature
// covers the spec, so the signed bytes survive the write only if what was
// signed is ALREADY a deflate fixpoint. Exceeding the address-collapse
// threshold is one way to not be a fixpoint; this is another, reached with two
// addresses and no collapse at all.
func TestSigningAPreDeflateSpecLosesTheSignatureOnWrite(t *testing.T) {
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "authored", Namespace: "flux"},
		Spec: v1beta1.ContainerProfileSpec{
			Egress: []v1beta1.NetworkNeighbor{{Identifier: "peers", Type: v1beta1.CommunicationTypeEgress, IPAddresses: []string{"10.10.0.1", "10.10.0.2"}}},
		},
	}
	require.NoError(t, signature.SignObjectDisableKeyless(NewContainerProfileAdapter(cp)))
	require.NoError(t, signature.VerifyObjectAllowUntrusted(NewContainerProfileAdapter(cp)))

	stored := cp.DeepCopy()
	stored.Spec = deflateSpec(t, cp.Spec)
	require.NotEqual(t, specJSON(t, cp.Spec), specJSON(t, stored.Spec),
		"the premise: an authored spec is not automatically in deflated form")
	require.Error(t, signature.VerifyObjectAllowUntrusted(NewContainerProfileAdapter(stored)),
		"#51: the stored spec differs from the signed one, so verification fails")
}

// Signing the deflated form is what makes it survive, which is the shape of the
// mitigation a generator has to adopt while #51 is open.
func TestSigningTheDeflatedFormSurvivesTheWrite(t *testing.T) {
	spec := v1beta1.ContainerProfileSpec{
		Egress: []v1beta1.NetworkNeighbor{{Identifier: "peers", Type: v1beta1.CommunicationTypeEgress, IPAddresses: []string{"10.10.0.1", "10.10.0.2"}}},
	}
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "authored", Namespace: "flux"},
		Spec:       deflateSpec(t, spec),
	}
	require.NoError(t, signature.SignObjectDisableKeyless(NewContainerProfileAdapter(cp)))

	stored := cp.DeepCopy()
	stored.Spec = deflateSpec(t, cp.Spec)
	require.NoError(t, signature.VerifyObjectAllowUntrusted(NewContainerProfileAdapter(stored)),
		"a signed deflate fixpoint must survive the write unchanged")
}

// The identifier merge reaches the same outage without any address collapse:
// two distinct entries sharing an Identifier become one whose ports are the
// union, which is both a signature break and a silent widening.
func TestDuplicateIdentifiersMergeAndUnionPorts(t *testing.T) {
	port80, port443 := int32(80), int32(443)
	spec := v1beta1.ContainerProfileSpec{
		Egress: []v1beta1.NetworkNeighbor{
			{Identifier: "peer", Type: v1beta1.CommunicationTypeEgress, IPAddresses: []string{"10.0.0.1"},
				Ports: []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: v1beta1.ProtocolTCP, Port: &port80}}},
			{Identifier: "peer", Type: v1beta1.CommunicationTypeEgress, IPAddresses: []string{"10.0.0.2"},
				Ports: []v1beta1.NetworkPort{{Name: "TCP-443", Protocol: v1beta1.ProtocolTCP, Port: &port443}}},
		},
	}
	stored := deflateSpec(t, spec)
	require.Len(t, stored.Egress, 1, "entries sharing an identifier are merged into one")
	require.Len(t, stored.Egress[0].Ports, 2,
		"and their ports are unioned — the merged entry admits both, which neither original did")
}

func TestAddressCollapseRewritesAboveTheThreshold(t *testing.T) {
	n := dynamicpathdetector.NetworkIPGroupThreshold + 1
	addrs := make([]string, 0, n)
	for i := 0; i < n; i++ {
		addrs = append(addrs, fmt.Sprintf("10.10.%d.%d", i/250, i%250))
	}
	spec := v1beta1.ContainerProfileSpec{
		Egress: []v1beta1.NetworkNeighbor{{Identifier: "peers", Type: v1beta1.CommunicationTypeEgress, IPAddresses: addrs}},
	}
	stored := deflateSpec(t, spec)
	require.NotEqual(t, addrs, stored.Egress[0].IPAddresses,
		"above the collapse threshold the literals are replaced by a CIDR cover")
	require.Less(t, len(stored.Egress[0].IPAddresses), n,
		"the cover must be smaller than the set it replaces")
}

// Every signed ContainerProfile fixture in this repo must be a deflate
// fixpoint. They are today, which is why #51 has never bitten a component test
// — not because they are small. A fixture that stops being one would fail its
// signature check only on a live cluster, long after the commit that broke it.
func TestCommittedSignedFixturesAreDeflateFixpoints(t *testing.T) {
	files, err := filepath.Glob("../../../tests/resources/signed/fragments/*-signed.yaml")
	require.NoError(t, err)
	require.NotEmpty(t, files, "the fixtures must be found, or this guard passes vacuously")

	checked := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		require.NoError(t, err)
		cp := &v1beta1.ContainerProfile{}
		if err := yaml.Unmarshal(b, cp); err != nil || cp.Kind != "ContainerProfile" {
			continue
		}
		checked++
		name := filepath.Base(f)
		require.NoErrorf(t, signature.VerifyObjectAllowUntrusted(NewContainerProfileAdapter(cp)),
			"%s must verify as committed", name)

		stored := cp.DeepCopy()
		stored.Spec = deflateSpec(t, cp.Spec)
		require.NoErrorf(t, signature.VerifyObjectAllowUntrusted(NewContainerProfileAdapter(stored)),
			"%s must still verify after storage's write-path deflate (#51)", name)
	}
	require.NotZero(t, checked, "no ContainerProfile fixtures were actually checked")
}
