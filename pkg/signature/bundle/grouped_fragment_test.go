//go:build experimental_signing

package bundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func TestGroupedFragmentsRejected(t *testing.T) {
	for _, field := range []string{"containers", "initContainers", "ephemeralContainers"} {
		for _, embedded := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/embedded=%t", field, embedded), func(t *testing.T) {
				var spec v1beta1.ContainerProfileSpec
				// Include a flat grant too: mixed fragments must not silently lose
				// the grouped grant while admitting the flat portion.
				if err := json.Unmarshal([]byte(fmt.Sprintf(`{"execs":[{"path":"/bin/flat"}],%q:[{"name":"app","execs":[{"path":"/bin/grouped"}]}]}`, field)), &spec); err != nil {
					t.Fatal(err)
				}
				key := genKey(t)
				cp := buildFragment(t, "grouped", "bundle", "base", spec, key, false)
				if err := signature.SignObject(profiles.NewContainerProfileAdapter(cp), signature.WithPrivateKey(key), signature.WithEmbedContent(embedded)); err != nil {
					t.Fatal(err)
				}
				policy := TrustPolicy{Classes: map[FragmentClass]ClassPolicy{
					ClassBase: {Signers: []string{signerIDOf(t, cp)}, AllowedSpecPaths: []string{"*"}},
				}}
				if embedded {
					// Admission must inspect signed content, even if storage has
					// removed all grouped fields from the carrier.
					cp.Spec = baseSpec()
				}
				composite, manifest, err := AssembleAndVerify("bundle", "any", []*v1beta1.ContainerProfile{cp}, policy)
				if !errors.Is(err, ErrGroupedFragment) || composite != nil || manifest != nil {
					t.Fatalf("grouped fragment admitted: composite=%v manifest=%v err=%v", composite, manifest, err)
				}
				composite, manifest, dropped, err := AssembleAndVerifyPartial("bundle", "any", []*v1beta1.ContainerProfile{cp}, policy)
				if !errors.Is(err, ErrEmptyBundle) || composite != nil || manifest != nil || len(dropped) != 1 {
					t.Fatalf("partial assembly should reject grouped fragment: composite=%v manifest=%v dropped=%v err=%v", composite, manifest, dropped, err)
				}
				if !errors.Is(dropped[0].Reason, ErrGroupedFragment) {
					t.Fatalf("unexpected drop reason: %v", dropped[0].Reason)
				}
			})
		}
	}
}
