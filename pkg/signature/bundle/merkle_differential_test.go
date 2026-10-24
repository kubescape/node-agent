//go:build experimental_signing

package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	mathrand "math/rand"
	"reflect"
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func refLeafHash(l LeafRef) [32]byte {
	h := sha256.New()
	h.Write([]byte("kubescape-bundle-leaf\x00"))
	h.Write([]byte(l.Class))
	h.Write([]byte{0})
	h.Write([]byte(l.Signer))
	h.Write([]byte{0})
	h.Write([]byte(l.ContentDigest))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func refMerkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return sha256.Sum256([]byte("kubescape-bundle-empty"))
	}
	level := leaves
	for len(level) > 1 {
		var next [][32]byte
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			h := sha256.New()
			h.Write([]byte{0x01})
			h.Write(level[i][:])
			h.Write(level[i+1][:])
			var n [32]byte
			copy(n[:], h.Sum(nil))
			next = append(next, n)
		}
		level = next
	}
	return level[0]
}

func refRoot(leaves []LeafRef) string {
	hashes := make([][32]byte, len(leaves))
	for i, l := range leaves {
		hashes[i] = refLeafHash(l)
	}
	root := refMerkleRoot(hashes)
	return hex.EncodeToString(root[:])
}

func randomLeaf(rng *mathrand.Rand) LeafRef {
	classes := []FragmentClass{ClassBase, ClassAdmission, ClassOverlay}
	digest := make([]byte, 32)
	rng.Read(digest)
	return LeafRef{
		Class:         classes[rng.Intn(len(classes))],
		Signer:        "key:" + hex.EncodeToString([]byte{byte(rng.Intn(256)), byte(rng.Intn(256))}),
		Name:          "frag-" + hex.EncodeToString([]byte{byte(rng.Intn(256))}),
		ContentDigest: hex.EncodeToString(digest),
	}
}

func randomLeaves(rng *mathrand.Rand, n int) []LeafRef {
	out := make([]LeafRef, n)
	for i := range out {
		out[i] = randomLeaf(rng)
	}
	return out
}

func TestMerkleDifferential_RefRootEqualsProduction(t *testing.T) {
	rng := mathrand.New(mathrand.NewSource(0x0FFEE))
	const iterations = 400
	for i := 0; i < iterations; i++ {
		n := rng.Intn(9)
		leaves := randomLeaves(rng, n)
		got := rootFromLeaves(leaves)
		want := refRoot(leaves)
		if got != want {
			t.Fatalf("iteration %d (n=%d): production rootFromLeaves=%s, independent refRoot=%s", i, n, got, want)
		}
	}
	if refRoot(nil) != rootFromLeaves(nil) {
		t.Fatalf("empty-leaf-set root diverged: ref=%s prod=%s", refRoot(nil), rootFromLeaves(nil))
	}
	t.Logf("independent sha256 domain-separated reference matched production rootFromLeaves over %d random leaf sets (0..8 leaves) plus the empty set", iterations)
}

func TestMerkleDifferential_LeafDigestChangeChangesRoot(t *testing.T) {
	rng := mathrand.New(mathrand.NewSource(0x1234))
	const iterations = 200
	for i := 0; i < iterations; i++ {
		leaves := randomLeaves(rng, rng.Intn(6)+1)
		before := rootFromLeaves(leaves)
		idx := rng.Intn(len(leaves))
		mutated := make([]LeafRef, len(leaves))
		copy(mutated, leaves)
		orig := mutated[idx].ContentDigest
		mutated[idx].ContentDigest = orig + "0"
		after := rootFromLeaves(mutated)
		if before == after {
			t.Fatalf("iteration %d: changing leaf %d content digest did not change the root (%s)", i, idx, before)
		}
		if after != refRoot(mutated) {
			t.Fatalf("iteration %d: production and reference disagree after mutation", i)
		}
	}
	t.Logf("changing any single leaf content digest changed the Merkle root across %d random sets", iterations)
}

func TestMerkleDifferential_AddOrRemoveLeafChangesRoot(t *testing.T) {
	rng := mathrand.New(mathrand.NewSource(0x9E3779B9))
	const iterations = 200
	for i := 0; i < iterations; i++ {
		leaves := randomLeaves(rng, rng.Intn(5)+1)
		before := rootFromLeaves(leaves)

		added := append(append([]LeafRef{}, leaves...), randomLeaf(rng))
		if rootFromLeaves(added) == before {
			t.Fatalf("iteration %d: adding a leaf did not change the root", i)
		}

		idx := rng.Intn(len(leaves))
		removed := append(append([]LeafRef{}, leaves[:idx]...), leaves[idx+1:]...)
		if rootFromLeaves(removed) == before {
			t.Fatalf("iteration %d: removing leaf %d did not change the root", i, idx)
		}
	}
	t.Logf("adding or removing a leaf changed the Merkle root across %d random sets", iterations)
}

func randomFragmentSpec(rng *mathrand.Rand, class FragmentClass) v1beta1.ContainerProfileSpec {
	switch class {
	case ClassAdmission:
		port := int32(6379)
		return v1beta1.ContainerProfileSpec{Ingress: []v1beta1.NetworkNeighbor{{
			Identifier: "n-" + hex.EncodeToString([]byte{byte(rng.Intn(256))}),
			Type:       "internal",
			Ports:      []v1beta1.NetworkPort{{Name: "TCP-6379", Port: &port, Protocol: "TCP"}},
		}}}
	default:
		return v1beta1.ContainerProfileSpec{
			Execs: []v1beta1.ExecCalls{{Path: "/bin/tool-" + hex.EncodeToString([]byte{byte(rng.Intn(256))})}},
		}
	}
}

func TestMerkleDifferential_AssemblyOrderIndependent(t *testing.T) {
	rng := mathrand.New(mathrand.NewSource(0xABCDEF))
	vendor, operator := genKey(t), genKey(t)

	const iterations = 20
	for it := 0; it < iterations; it++ {
		base := fragment(t, "redis", "base", randomFragmentSpec(rng, ClassBase), vendor)
		adm := fragment(t, "redis-ingress", "admission", randomFragmentSpec(rng, ClassAdmission), operator)
		ovl := fragment(t, "redis-overlay", "base", randomFragmentSpec(rng, ClassBase), vendor)

		policy := TrustPolicy{Classes: map[FragmentClass]ClassPolicy{
			ClassBase:      {Signers: []string{signerIDOf(t, base)}, AllowedSpecPaths: []string{"execs", "opens", "architectures"}},
			ClassAdmission: {Signers: []string{signerIDOf(t, adm)}, AllowedSpecPaths: []string{"ingress", "egress"}},
		}}

		frags := []*v1beta1.ContainerProfile{base, adm, ovl}
		refComposite, refManifest, err := AssembleAndVerify("redis", "redis", frags, policy)
		if err != nil {
			t.Fatalf("iteration %d: baseline assembly: %v", it, err)
		}

		perms := [][]int{{0, 1, 2}, {2, 1, 0}, {1, 2, 0}, {2, 0, 1}, {0, 2, 1}, {1, 0, 2}}
		for _, p := range perms {
			shuffled := []*v1beta1.ContainerProfile{frags[p[0]], frags[p[1]], frags[p[2]]}
			composite, manifest, err := AssembleAndVerify("redis", "redis", shuffled, policy)
			if err != nil {
				t.Fatalf("iteration %d perm %v: %v", it, p, err)
			}
			if manifest.Root != refManifest.Root {
				t.Fatalf("iteration %d perm %v: Merkle root depends on input order: %s vs %s", it, p, manifest.Root, refManifest.Root)
			}
			if !reflect.DeepEqual(composite.Spec, refComposite.Spec) {
				t.Fatalf("iteration %d perm %v: composite spec depends on input order", it, p)
			}
		}
	}
	t.Logf("across %d random fragment sets, every input permutation produced an identical composite spec AND Merkle root", iterations)
}
