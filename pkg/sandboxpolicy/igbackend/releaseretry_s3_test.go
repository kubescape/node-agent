package igbackend

import (
	"context"
	"errors"
	"testing"
)

// TestReleasePodRetriedAfterUnbindFailure answers the S3 review v2 open
// question: who retries a ReleasePod whose Unbind failed on a ready
// instance? The record keeps pendingUnbind, and the next ready bindPods
// unbinds it, with or without a sequence, when the pod is not listed (the
// start gate leaves a released pod out of its list).
func TestReleasePodRetriedAfterUnbindFailure(t *testing.T) {
	ctx := context.Background()
	for _, sequenced := range []bool{false, true} {
		b, e := newGate(t)
		b.SetStartGate(true)
		mustMark(t, b, strictPlan, seq(1, 1))
		i := e.last()
		i.unbindErr = map[uint64]error{podCgroup: errors.New("map busy")}
		if err := b.ReleasePod(ctx, "u", podCgroup); err == nil {
			t.Fatal("the failed unbind must be reported")
		}
		if p := b.pods["u"]; p == nil || !p.pendingUnbind {
			t.Fatalf("the record must wait for its unbind: %+v", p)
		}
		if _, ok := i.entries[podCgroup]; !ok {
			t.Fatal("setup: the mark must still be in the kernel")
		}
		i.unbindErr = nil
		var err error
		if sequenced {
			err = b.BindPodsAt(ctx, nil, seq(1, 1))
		} else {
			err = b.BindPods(ctx, nil)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := i.entries[podCgroup]; ok || b.pods["u"] != nil {
			t.Fatalf("sequenced=%v: the next ready bindPods did not retry the release", sequenced)
		}
		// Residual (S3-S5-NOTES.md): the retry records the removal's
		// order at the record's last sequence, so a new sandbox's mark at
		// an older or incomparable sequence is refused until a fresh one.
		err = b.MarkPod(ctx, gatePod(strictPlan), seq(2, 2))
		if err != nil {
			t.Fatalf("a newer mark after the retried release: %v", err)
		}
	}
}
