//go:build startgate_vmtest

package startgate

// startGateBuildable is true only in builds with the test-only tag
// startgate_vmtest (the S5/S6 VM tests). A release build must never carry
// the tag: scripts/check-startgate-release.sh refuses it.
const startGateBuildable = true
