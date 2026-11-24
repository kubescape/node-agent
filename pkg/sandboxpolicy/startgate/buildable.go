//go:build !startgate_vmtest

package startgate

// startGateBuildable is the start gate's enablement constant (design §9,
// owner decisions D2 and "Enablement"). While it is false, NewPlugin returns
// ErrNotBuildable and nothing dials NRI; no configuration can override it.
// It flips to true only in S9, after S8 (pre-start exec binding) and the S9
// VM proofs. The S5/S6 VM tests build with the test-only tag
// startgate_vmtest (buildable_vmtest.go), which a release build must never
// carry: scripts/check-startgate-release.sh refuses it.
const startGateBuildable = false
