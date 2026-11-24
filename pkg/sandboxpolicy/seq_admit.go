package sandboxpolicy

// Admits reports whether a pod-gate write at s applies over the last write
// at last (see Seq): a tightening (a new mark, Audit to Strict, a plan
// change) with a newer or equal sequence, a loosening (Strict to Audit, a
// removal) only with a newer one. An equal sequence can hide newer informer
// data (the cache updates before the hint bumps the epoch), so it never
// loosens. An incomparable sequence is not newer in either direction.
func (s Seq) Admits(last Seq, loosen bool) bool {
	switch s.Compare(last) {
	case SeqNewer:
		return true
	case SeqEqual:
		return !loosen
	}
	return false
}
