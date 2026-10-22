//go:build experimental_signing

package bundle

import (
	"encoding/json"
	"fmt"
	"os"
)

func LoadTrustPolicy(path string) (*TrustPolicy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trust policy %q: %w", path, err)
	}
	var p TrustPolicy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parse trust policy %q: %w", path, err)
	}
	if len(p.Classes) == 0 {
		return nil, fmt.Errorf("trust policy %q has no classes", path)
	}
	return &p, nil
}

func LoadSignedTrustPolicy(policyPath, rootKeyPath string) (*TrustPolicy, error) {
	rootFp, _, err := ResolveRootFingerprint(rootKeyPath)
	if err != nil {
		return nil, fmt.Errorf("resolve root fingerprint: %w", err)
	}
	return loadSignedTrustPolicyWithRoot(policyPath, rootFp)
}

// ResolveTrustedRootFingerprint resolves the root anchor from the fixed mount
// (FixedRootKeyPath) or the compiled-in default ONLY. Unlike a config-supplied
// path, this anchor cannot be redirected by editing a mutable ConfigMap.
func ResolveTrustedRootFingerprint() (fingerprint string, mounted bool, err error) {
	mountedKeyPath := ""
	if _, statErr := os.Stat(FixedRootKeyPath); statErr == nil {
		mountedKeyPath = FixedRootKeyPath
	}
	return ResolveRootFingerprint(mountedKeyPath)
}

// GuardRootAnchor rejects an unsafe trust anchor. In enforce mode a policy
// anchored to the published demo root with no mounted override authenticates
// nothing (anyone holds the private half), so it is refused. nil == acceptable.
func GuardRootAnchor(p *TrustPolicy, rootFp string, mounted bool) error {
	if p.Enforcing() && !mounted && IsDemoRoot(rootFp) {
		return fmt.Errorf("enforce mode refuses the published demo root key: mount a real root at %s", FixedRootKeyPath)
	}
	return nil
}

// RuleAdmissionUnauthenticated reports whether the policy turns rule signing on
// while the trust anchor is the published demo root: every rule-admission
// decision then rests on a key whose private half is public.
func RuleAdmissionUnauthenticated(p *TrustPolicy, rootFp string) bool {
	return p != nil && p.RuleSigningEnabled() && IsDemoRoot(rootFp)
}

// LoadSignedTrustPolicyTrusted loads and verifies the policy against the trusted
// root anchor (fixed mount or compiled default), never a config-supplied path,
// then guards the anchor for the policy's mode. This is the boot entry point.
func LoadSignedTrustPolicyTrusted(policyPath string) (p *TrustPolicy, rootFp string, mounted bool, err error) {
	rootFp, mounted, err = ResolveTrustedRootFingerprint()
	if err != nil {
		return nil, "", false, fmt.Errorf("resolve trusted root: %w", err)
	}
	p, err = loadSignedTrustPolicyWithRoot(policyPath, rootFp)
	if err != nil {
		return nil, rootFp, mounted, err
	}
	if gerr := GuardRootAnchor(p, rootFp, mounted); gerr != nil {
		return nil, rootFp, mounted, gerr
	}
	return p, rootFp, mounted, nil
}

func loadSignedTrustPolicyWithRoot(path, expectedRootFp string) (*TrustPolicy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signed trust policy %q: %w", path, err)
	}
	p, err := verifyAndPinPolicy(b, expectedRootFp)
	if err != nil {
		return nil, fmt.Errorf("signed trust policy %q: %w", path, err)
	}
	return p, nil
}
