package igbackend

import (
	"context"
	"errors"
	"testing"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

type noPendingAbortInstance struct{ FullInstance }

func pendingBackendFixture(t *testing.T) (*FullBackend, *controllerIdentityEngine, sandboxpolicy.Binding, sandboxpolicy.Plan) {
	t.Helper()
	e := &controllerIdentityEngine{}
	b, err := NewFull(e, &controllerIdentitySource{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	binding := sandboxpolicy.Binding{Runtime: "containerd", ContainerID: "id", ContainerName: "app", CgroupID: 19, PID: 20, MountNamespace: 21, PodUID: "pod", Namespace: "ns", PodName: "pod", Kind: "regular"}
	plan := verdictPlan()
	if result, err := b.Replace(context.Background(), binding, plan); err != nil || !result.Committed {
		t.Fatal(result, err)
	}
	t.Cleanup(func() {
		if err := b.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return b, e, binding, plan
}

func TestFullBackendAttestIsReadOnlyAndExact(t *testing.T) {
	for _, test := range []string{"healthy", "revision", "identity", "metadata", "missing", "retiring", "protocol-fault", "health", "pending", "closed"} {
		t.Run(test, func(t *testing.T) {
			b, e, binding, plan := pendingBackendFixture(t)
			owner := e.instances[0]
			record := b.records[key(binding)]
			requested := binding
			revision := plan.Revision
			switch test {
			case "revision":
				revision = "wrong"
			case "identity":
				requested.PID++
			case "metadata":
				requested.PodUID = "replacement"
			case "missing":
				requested.ContainerID = "absent"
			case "retiring":
				record.retiring = true
			case "protocol-fault":
				record.protocolFault = true
			case "health":
				owner.health = errors.New("quarantined")
			case "pending":
				owner.pending = owner.generation + 1
				record.pending = owner.pending
			case "closed":
				b.closed = true
			}
			beforeGeneration := owner.generation
			err := b.Attest(context.Background(), requested, revision)
			if (err == nil) != (test == "healthy") {
				t.Fatal("unexpected attestation result", err)
			}
			if owner.generation != beforeGeneration || owner.updates != 0 || owner.resumes != 0 || owner.aborts != 0 || owner.stops != 0 || len(e.instances) != 1 {
				t.Fatal("attestation mutated owned enforcement")
			}
			if test == "healthy" && owner.checks < 2 {
				t.Fatal("attestation skipped native health")
			}
		})
	}
}

func TestFullBackendSupersededUncommittedCandidateNeverResumes(t *testing.T) {
	for _, test := range []string{"rollback", "new-revision", "abort-fails", "abort-unsupported"} {
		t.Run(test, func(t *testing.T) {
			b, e, binding, original := pendingBackendFixture(t)
			ctx := context.Background()
			owner := e.instances[0]
			generation := owner.generation
			candidate := verdictPlan()
			candidate.Revision = "superseded"
			owner.holdUncommitted = true
			result, err := b.Replace(ctx, binding, candidate)
			if err == nil || result.Committed || owner.pending == 0 || owner.generation != generation {
				t.Fatal("test requires uncommitted staged candidate", result, err)
			}
			pending := owner.pending
			desired := original
			if test == "new-revision" {
				desired.Revision = "current-desired"
			}
			owner.holdUncommitted = false
			switch test {
			case "abort-fails":
				owner.abortError = errors.New("drain incomplete")
			case "abort-unsupported":
				b.records[key(binding)].instance = noPendingAbortInstance{owner}
			}
			result, err = b.Replace(ctx, binding, desired)
			if test == "abort-fails" || test == "abort-unsupported" {
				if err == nil || result.Committed || !result.ProtectionUnconfirmed || owner.pending != pending || owner.generation != generation || owner.updates != 1 || owner.resumes != 0 {
					t.Fatal("unsupported/failed abort resumed superseded revision", result, err)
				}
				owner.abortError = nil
				b.records[key(binding)].instance = owner
				result, err = b.Replace(ctx, binding, desired)
			}
			if err != nil || !result.Committed || result.ActiveRevision != desired.Revision || owner.pending != 0 || b.records[key(binding)].pending != 0 || owner.resumes != 0 || owner.aborts < 1 || len(e.instances) != 1 {
				t.Fatal("superseded candidate not aborted safely", result, err)
			}
			if test == "new-revision" {
				if owner.generation <= pending || owner.updates != 2 {
					t.Fatal("new desired revision not published after abort")
				}
			} else if owner.generation != generation || owner.updates != 1 {
				t.Fatal("rollback unnecessarily published or restarted last-good")
			}
			if err := b.Attest(ctx, binding, desired.Revision); err != nil {
				t.Fatal("post-abort active revision cannot be attested", err)
			}
		})
	}
}

func TestFullBackendSupersededCommittedPublicationMayFinalize(t *testing.T) {
	b, e, binding, original := pendingBackendFixture(t)
	ctx := context.Background()
	owner := e.instances[0]
	committed := verdictPlan()
	committed.Revision = "committed-awaiting-finalization"
	owner.commitFailure = true
	result, err := b.Replace(ctx, binding, committed)
	if err == nil || !result.Committed || owner.pending == 0 || owner.pending != owner.generation {
		t.Fatal("test requires committed pending finalization", result, err)
	}
	committedGeneration := owner.generation
	// The previous commit is irreversible, but the new authoritative request may
	// finalize it before publishing the requested rollback on the same owner.
	result, err = b.Replace(ctx, binding, original)
	if err != nil || !result.Committed || result.ActiveRevision != original.Revision || owner.aborts != 0 || owner.resumes != 1 || owner.updates != 2 || owner.generation <= committedGeneration || len(e.instances) != 1 {
		t.Fatal("committed publication was aborted or failed to finalize", result, err)
	}
}
