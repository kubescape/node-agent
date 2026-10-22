//go:build experimental_signing

package bundle

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func writePubKeyPEM(t *testing.T, dir string, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "root.pub")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestResolveRootFingerprint_EmbeddedByDefault(t *testing.T) {
	fp, mounted, err := ResolveRootFingerprint("")
	if err != nil {
		t.Fatalf("resolve embedded: %v", err)
	}
	if mounted {
		t.Fatal("empty path must resolve to the embedded key, not mounted")
	}
	embedded, _ := rootFingerprint()
	if fp != embedded {
		t.Fatalf("embedded fingerprint mismatch: %q vs %q", fp, embedded)
	}
}

func TestResolveRootFingerprint_MountedOverridesEmbedded(t *testing.T) {
	key := genKey(t)
	path := writePubKeyPEM(t, t.TempDir(), key)
	fp, mounted, err := ResolveRootFingerprint(path)
	if err != nil {
		t.Fatalf("resolve mounted: %v", err)
	}
	if !mounted {
		t.Fatal("a supplied path must resolve as mounted")
	}
	embedded, _ := rootFingerprint()
	if fp == embedded {
		t.Fatal("a distinct mounted key must yield a distinct fingerprint")
	}
}

func TestLoadSignedTrustPolicy_AcceptsPolicySignedByMountedRoot(t *testing.T) {
	root := genKey(t)
	path := writePubKeyPEM(t, t.TempDir(), root)
	signed, err := SignTrustPolicy(demoPolicy(), root)
	if err != nil {
		t.Fatalf("sign policy with mounted root: %v", err)
	}
	artifact := filepath.Join(t.TempDir(), "trust-policy.signed.json")
	if err := os.WriteFile(artifact, signed, 0644); err != nil {
		t.Fatal(err)
	}
	pol, err := LoadSignedTrustPolicy(artifact, path)
	if err != nil {
		t.Fatalf("mounted-root policy must load: %v", err)
	}
	if len(pol.Classes) != 2 {
		t.Fatalf("expected 2 classes, got %d", len(pol.Classes))
	}
}

func TestLoadSignedTrustPolicy_RejectsPolicyNotSignedByMountedRoot(t *testing.T) {
	root, rogue := genKey(t), genKey(t)
	path := writePubKeyPEM(t, t.TempDir(), root)
	signed, err := SignTrustPolicy(demoPolicy(), rogue)
	if err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(t.TempDir(), "trust-policy.signed.json")
	if err := os.WriteFile(artifact, signed, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSignedTrustPolicy(artifact, path); err == nil {
		t.Fatal("a policy signed by a key other than the mounted root must be rejected")
	}
}

func TestResolveRootFingerprint_UnreadableMountFails(t *testing.T) {
	if _, _, err := ResolveRootFingerprint(filepath.Join(t.TempDir(), "nope.pub")); err == nil {
		t.Fatal("an unreadable mounted key path must fail closed")
	}
}

func TestTrustedRootDoesNotFallbackOnStatFailure(t *testing.T) {
	// Descending through a regular file fails with ENOTDIR even as root.
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if fp, _, err := resolveTrustedRootFingerprintAt(filepath.Join(blocker, "root.pub")); err == nil || fp != "" {
		t.Fatalf("stat errors must not select compiled root: fp=%q err=%v", fp, err)
	}
}

func TestTrustedRootFallbackOnlyWhenMissing(t *testing.T) {
	fp, mounted, err := resolveTrustedRootFingerprintAt(filepath.Join(t.TempDir(), "absent.pub"))
	if err != nil || mounted || fp != DemoRootFingerprint {
		t.Fatalf("missing mount must use compiled root: fp=%q mounted=%v err=%v", fp, mounted, err)
	}
	keyPath := writePubKeyPEM(t, t.TempDir(), genKey(t))
	fp, mounted, err = resolveTrustedRootFingerprintAt(keyPath)
	if err != nil || !mounted || fp == DemoRootFingerprint {
		t.Fatalf("existing mount must override compiled root: fp=%q mounted=%v err=%v", fp, mounted, err)
	}
}
