//go:build experimental_signing

package bundle

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
)

const DefaultRootPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwIIkPTD5rGPP/bYmjRHxefAoCI1m
wIiQMRA78xdS5rTT3zl06ygpY9D4A1zRrQjq2CkF5ciwO2kSJGe3h64jEw==
-----END PUBLIC KEY-----
`

func fingerprintFromPublicKeyPEM(pemBytes []byte) (string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", fmt.Errorf("failed to PEM-decode root public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse root public key: %w", err)
	}
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("failed to marshal root public key: %w", err)
	}
	sum := sha256.Sum256(pkix)
	return "key:" + hex.EncodeToString(sum[:]), nil
}

// DemoRootFingerprint is the fingerprint of the published demo root key that
// DefaultRootPublicKeyPEM embeds. A published key authenticates nothing, so
// enforce mode refuses it unless a real root is mounted at FixedRootKeyPath.
// TestDemoRootFingerprintMatchesDefault pins this to the embedded key.
const DemoRootFingerprint = "key:d0cc7f2e82d99699d7a5f7078a9f30ec4847d13b6e41e91e224e0a47b32b9f9e"

// IsDemoRoot reports whether a resolved root fingerprint is the published demo
// key that authenticates nothing.
func IsDemoRoot(fingerprint string) bool { return fingerprint == DemoRootFingerprint }

func rootFingerprint() (string, error) {
	return fingerprintFromPublicKeyPEM([]byte(DefaultRootPublicKeyPEM))
}

func rootFingerprintFromKeyFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read root public key %q: %w", path, err)
	}
	return fingerprintFromPublicKeyPEM(b)
}

func ResolveRootFingerprint(mountedKeyPath string) (fingerprint string, mounted bool, err error) {
	if mountedKeyPath != "" {
		fp, ferr := rootFingerprintFromKeyFile(mountedKeyPath)
		if ferr != nil {
			return "", true, ferr
		}
		return fp, true, nil
	}
	fp, ferr := rootFingerprint()
	return fp, false, ferr
}
