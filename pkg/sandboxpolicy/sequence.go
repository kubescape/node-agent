package sandboxpolicy

// Seq orders the pod-gate writes of one cgroup. Config is the configSeq of
// the classification snapshot the decision read (Controller.ClassifyPod);
// Input is the input epoch of the informer data it read (CaptureInputs).
// Both counters only grow.
//
// Seq will be unified with S2's PodSeq when S3 merges the two: Config maps
// to PodSeq.ConfigSeq and Input to PodSeq.InputEpoch (Compare is the same).
type Seq struct {
	Config uint64
	Input  uint64
}

// SeqOrder is how a sequence compares with another one. The zero value is
// SeqIncomparable, which counts as "not newer" in both directions.
type SeqOrder int

const (
	// SeqIncomparable: one component is greater and the other smaller.
	SeqIncomparable SeqOrder = iota
	// SeqOlder: both components are less or equal, at least one is less.
	SeqOlder
	// SeqEqual: both components are equal.
	SeqEqual
	// SeqNewer: both components are greater or equal, at least one is greater.
	SeqNewer
)

// Compare compares s with last (for example, the last sequence written for
// a cgroup).
func (s Seq) Compare(last Seq) SeqOrder {
	switch {
	case s == last:
		return SeqEqual
	case s.Config >= last.Config && s.Input >= last.Input:
		return SeqNewer
	case s.Config <= last.Config && s.Input <= last.Input:
		return SeqOlder
	}
	return SeqIncomparable
}

// CaptureInputs reads informer inputs seqlock-style: the input epoch (e1),
// the inputs, then the epoch again (e2). When e1 and e2 differ it reads once
// more, and returns the inputs of that second read with its e1, whether or
// not its epochs match. e1 is a lower bound: the informer cache never moves
// backwards, so data read after e1 is at least as new as e1, and a sequence
// that is too low can only make a write refused, never let a stale one
// through.
func CaptureInputs[T any](epoch func() uint64, read func() T) (T, uint64) {
	e1 := epoch()
	inputs := read()
	if epoch() == e1 {
		return inputs, e1
	}
	e1 = epoch()
	return read(), e1
}
