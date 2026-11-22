// Copyright 2026 The Kubescape authors
// SPDX-License-Identifier: Apache-2.0

package sandboxpolicy

import "context"

// ExecFenceCandidate binds the resolved plan to its current census identity.
// Scope reports any exec policy potentially selecting a present or future
// child of this pod (pod selector, not just current container matches).
// Unknown candidates may retain last-good mode, never authorize Off.
type ExecFenceCandidate struct {
	Binding   Binding
	Plan      Plan
	Known     bool
	Scope     bool
	MayStrict bool
	// NoExec is a valid selected empty exec policy. Preserve its usual
	// native lifecycle without marking it for exec outage enforcement.
	NoExec bool
}

// ExecFence coordinates v2 pod marking with exact native publication. It
// runs under the controller's reconciliation lock. All implementations must
// preserve last-good marks if preparation fails.
type ExecFence interface {
	Prepare(context.Context, []ExecFenceCandidate) error
	// PrepareExplicitRemoval authorizes explicit Off or deletion of retained
	// bindings from an authoritative configuration snapshot during discovery failure.
	PrepareExplicitRemoval(context.Context, Binding, Plan, bool) error
	BeforeReplace(context.Context, Binding, string) error
	VerifyAndMove(context.Context, Binding, string) error
	Refence(context.Context, Binding) error
	// PrepareWithdrawal seals an inherited or locally handed-over managed
	// child before native withdrawal. False means no managed fence receipt
	// needs withdrawal; it does not attest any native cleanup.
	PrepareWithdrawal(context.Context, Binding) (bool, error)
	Withdrawn(context.Context, Binding) error
	Deactivate(context.Context, Binding) error
}
