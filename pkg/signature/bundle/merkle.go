//go:build experimental_signing

package bundle

import (
	"crypto/sha256"
	"encoding/hex"
)

// leafHash binds class‖signer‖contentDigest into a domain-separated leaf
// pre-image so a leaf commits to WHO signed WHAT for WHICH class — swapping any
// of the three changes the leaf and therefore the root.
func leafHash(l LeafRef) [32]byte {
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

// merkleRoot computes a binary Merkle root over the leaf hashes. Internal nodes
// are domain-separated (0x01 prefix) to prevent second-preimage attacks; an odd
// node at any level is promoted unchanged. Order matters: the caller passes
// leaves in canonical (sorted) fragment order.
func merkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return sha256.Sum256([]byte("kubescape-bundle-empty"))
	}
	level := leaves
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i]) // promote odd node
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

// rootFromLeaves computes the hex Merkle root over LeafRefs in the given order.
func rootFromLeaves(leaves []LeafRef) string {
	hashes := make([][32]byte, len(leaves))
	for i, l := range leaves {
		hashes[i] = leafHash(l)
	}
	root := merkleRoot(hashes)
	return hex.EncodeToString(root[:])
}
