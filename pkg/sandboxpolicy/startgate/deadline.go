// Package startgate holds the NRI start gate's timing primitive. It makes no
// admission verdict and starts no work.
//
// WorkDeadline is ported unchanged from na-wt's primitives.go (approved in
// the primitives v2 review); the event mask and the observation counters
// stay there until S5 needs them.
package startgate

import (
	"errors"
	"time"
)

// WorkDeadline calculates a work cutoff with time reserved for the response.
// runtimeTimeout must be the runtime-advertised value, not a stub default read
// before configuration. A zero parentDeadline means no parent deadline; otherwise
// its return margin is reserved too. The result never extends the runtime or
// parent budget. No context is canceled and no work is started by this function.
//
// An error describes unusable timing inputs, NOT a workload admission decision.
// In particular, callers must not turn this into a denial of attested Audit.
func WorkDeadline(start time.Time, runtimeTimeout, returnMargin time.Duration, parentDeadline time.Time) (time.Time, error) {
	if start.IsZero() || returnMargin <= 0 || runtimeTimeout <= returnMargin {
		return time.Time{}, errors.New("start gate requires a start time and runtime timeout exceeding a positive return margin")
	}
	cutoff := start.Add(runtimeTimeout - returnMargin)
	if !parentDeadline.IsZero() {
		parentCutoff := parentDeadline.Add(-returnMargin)
		if parentCutoff.Before(cutoff) {
			cutoff = parentCutoff
		}
	}
	if !cutoff.After(start) {
		return time.Time{}, errors.New("start gate timing inputs leave no work budget")
	}
	return cutoff, nil
}
