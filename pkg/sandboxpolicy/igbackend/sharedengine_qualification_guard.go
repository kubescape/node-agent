//go:build sandbox_shared_qualification && !enforce_exec_shared_qualification

package igbackend

// The shared engine needs IG's qualification StartNode path, which only
// binaries built with enforce_exec_shared_qualification carry. Without it
// StartNode always refuses, so fail the build instead of shipping an engine
// that can never start:
//
//	go build -tags sandbox_shared_qualification,enforce_exec_shared_qualification
var _ = sandbox_shared_qualification_requires_tag_enforce_exec_shared_qualification
