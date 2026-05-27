// Package signature is a build-time stub of the full signature package
// landing in kubescape/node-agent#809. Exposes the minimum surface the
// tamper-detection path in this PR (#808) imports — IsSigned,
// VerifyObjectAllowUntrusted, SignObjectDisableKeyless, and the
// ErrSignatureMismatch sentinel — so the PR compiles standalone.
//
// All operations no-op: IsSigned returns false (tamper path treats
// every profile as unsigned and skips verification), Verify and Sign
// return nil. Replace with the real implementation from #809 when that
// PR lands; this file is intended to be deleted, not maintained.
package signature

import "errors"

// ErrSignatureMismatch is the sentinel the tamper-detection path
// errors.Is-checks. Must remain non-nil with this exact message —
// tamper_alert_test.go pins both invariants.
var ErrSignatureMismatch = errors.New("signature verification failed")

// Signable is the marker interface adapters in pkg/signature/profiles
// satisfy. Empty in the stub; the real package decorates it with
// signature-payload accessors.
type Signable interface{}

func IsSigned(_ Signable) bool                    { return false }
func VerifyObjectAllowUntrusted(_ Signable) error { return nil }
func SignObjectDisableKeyless(_ Signable) error   { return nil }
